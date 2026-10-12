# -*- coding: utf-8 -*-
"""Collector and parser for Auditd EXECVE / command-like log entries."""

import json
import re


def _flatten_text(value):
    """Convert nested GCP payloads into searchable text without losing fields."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            parts.append(str(key))
            parts.append(_flatten_text(item))
        return " ".join(p for p in parts if p)
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten_text(item) for item in value)
    return str(value)


def _entry_parts(entry):
    """Return timestamp, log name, payload object and flattened payload text."""
    if isinstance(entry, dict):
        ts = entry.get("timestamp")
        log_name = entry.get("log_name") or entry.get("logName") or ""
        payload = (
            entry.get("text_payload")
            or entry.get("textPayload")
            or entry.get("json_payload")
            or entry.get("jsonPayload")
            or entry.get("proto_payload")
            or entry.get("protoPayload")
            or entry.get("payload")
            or entry.get("message")
            or ""
        )
    else:
        ts = getattr(entry, "timestamp", None)
        log_name = getattr(entry, "log_name", "") or getattr(entry, "logName", "") or ""
        payload = (
            getattr(entry, "text_payload", None)
            or getattr(entry, "json_payload", None)
            or getattr(entry, "proto_payload", None)
            or getattr(entry, "payload", None)
            or ""
        )
    if isinstance(payload, str):
        text = payload
    else:
        lower_log = str(log_name).lower()
        if "auditd" in lower_log or "audit.log" in lower_log:
            text = _flatten_text(payload)
        elif isinstance(payload, dict) and any(k in payload for k in ("command", "command_line", "cmd", "argv")):
            text = _flatten_text(payload)
        else:
            text = ""
    return ts, str(log_name), payload, text


def _unquote_audit_value(raw):
    value = raw.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        try:
            return json.loads(value)
        except (ValueError, json.JSONDecodeError):
            return value[1:-1].replace('\\"', '"').replace('\\\\', '\\')
    return value


def _extract_command(payload, text):
    lower = text.lower()

    # Linux auditd EXECVE records normally expose argc + a0..aN.
    argv = []
    for match in re.finditer(r"\ba(\d+)=(\"(?:\\.|[^\"])*\"|[^\s]+)", text):
        argv.append((int(match.group(1)), _unquote_audit_value(match.group(2))))
    if argv:
        argv.sort(key=lambda item: item[0])
        command = " ".join(item[1] for item in argv if item[1])
        if command:
            return command

    for pattern in (
        r"(?:command_line|commandline|cmdline)\s*[:=]\s*['\"]([^'\"]+)['\"]",
        r"(?:command_line|commandline|cmdline)\s*[:=]\s*([^,\n]+)",
        r"(?:command|cmd)\s*[:=]\s*['\"]([^'\"]+)['\"]",
        r"(?:command|cmd)\s*[:=]\s*([^\s,]+)",
    ):
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            if value:
                return value

    exe_match = re.search(r'\bexe="([^"]+)"', text, re.IGNORECASE)
    if exe_match:
        return exe_match.group(1)
    exe_match = re.search(r"\bexe=([^\s]+)", text, re.IGNORECASE)
    if exe_match:
        return exe_match.group(1)

    # A few shippers expose the command as a structured JSON field.
    if isinstance(payload, dict):
        for key in ("command_line", "commandLine", "cmdline", "command", "cmd"):
            value = payload.get(key)
            if value:
                return str(value)
        # OS Config, Ops Agent and custom GCP log shippers often nest command
        # data below request/metadata rather than at the payload root.
        for container in (payload.get("request"), payload.get("metadata"), payload.get("jsonPayload")):
            if isinstance(container, dict):
                for key in ("command_line", "commandLine", "cmdline", "command", "cmd", "argv"):
                    value = container.get(key)
                    if isinstance(value, (list, tuple)):
                        value = " ".join(str(part) for part in value)
                    if value:
                        return str(value)

    return ""


def _is_command_event(log_name, text, payload):
    lower_log = log_name.lower()
    lower_text = text.lower()

    if "auditd" in lower_log or "audit.log" in lower_log:
        return True
    if re.search(r"\btype=EXECVE\b", text, re.IGNORECASE):
        return True
    if re.search(r"\bEXECVE\b", text, re.IGNORECASE):
        return True

    if isinstance(payload, dict):
        keys = {str(k).casefold() for k in payload.keys()}
        if keys.intersection({"command", "command_line", "commandline", "cmd", "cmdline", "argv"}):
            return True
        nested = [payload.get("request"), payload.get("metadata"), payload.get("jsonPayload")]
        if any(isinstance(item, dict) and {str(k).casefold() for k in item}.intersection({"command", "command_line", "commandline", "cmd", "cmdline", "argv"}) for item in nested):
            return True

    return bool(
        re.search(r"\b(?:command_line|commandline|cmdline|command|cmd)=", lower_text)
    )


def _extract_user_ip_host(entry, text, payload):
    auid_match = re.search(r"\bauid=(\d+)", text, re.IGNORECASE)
    auid = auid_match.group(1) if auid_match else "unset"

    uid_match = re.search(r"\buid=(\d+)", text, re.IGNORECASE)
    uid = uid_match.group(1) if uid_match else "0"
    uid_disp = "0 (root)" if uid == "0" else uid

    ip = "Local / TTY Session"
    ip_match = re.search(
        r"\b(?:addr|ip|callerIp|caller_ip|remoteAddress|remote_address)=([0-9a-fA-F:.]+)",
        text,
        re.IGNORECASE,
    )
    if ip_match:
        ip = ip_match.group(1)

    hostname = "gcp-vm"
    host_match = re.search(r"^([a-zA-Z0-9_.-]+)\s+auditd", text)
    if host_match:
        hostname = host_match.group(1)
    elif isinstance(payload, dict):
        for key in ("hostname", "host", "instance_name", "instanceName"):
            if payload.get(key):
                hostname = str(payload[key])
                break

    # Prefer GCP resource labels when present.
    resource = None
    if isinstance(entry, dict):
        resource = entry.get("resource")
    else:
        resource = getattr(entry, "resource", None)
    if resource is not None:
        labels = resource.get("labels") if isinstance(resource, dict) else getattr(resource, "labels", None)
        if labels:
            for key in ("instance_name", "instance_id", "instanceName"):
                if isinstance(labels, dict) and labels.get(key):
                    hostname = str(labels[key])
                    break

    return auid, uid_disp, ip, hostname


def parse_execve(logs):
    """Parse command activity from Auditd and structured command-like GCP logs.

    The parser intentionally returns no row for unrelated log entries. This allows
    the caller to stream every project log through the parser without fabricating
    commands from arbitrary application text.
    """
    results = []

    for entry in logs:
        ts, log_name, payload, text = _entry_parts(entry)
        if not _is_command_event(log_name, text, payload):
            continue

        command = _extract_command(payload, text)
        if not command:
            continue

        auid, uid_disp, ip, hostname = _extract_user_ip_host(entry, text, payload)

        results.append(
            {
                "timestamp": ts,
                "auid": auid,
                "uid": uid_disp,
                "command": command,
                "hostname": hostname,
                "ip": ip,
                "source_log": log_name or "Cloud Logging",
                "raw": text,
            }
        )

    return results

# -*- coding: utf-8 -*-
"""Parsers for authentication, GCP IAM behavior, and generic project logs."""

import re
import pandas as pd

from collectors.cloud_scope import extract_project_id


def _flatten_text(value):
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
    if isinstance(entry, dict):
        ts = entry.get("timestamp")
        log_name = entry.get("log_name") or entry.get("logName") or ""
        text_payload = entry.get("text_payload") or entry.get("textPayload")
        json_payload = entry.get("json_payload") or entry.get("jsonPayload")
        proto_payload = entry.get("proto_payload") or entry.get("protoPayload")
        payload = (
            text_payload
            if text_payload is not None
            else json_payload
            if json_payload is not None
            else proto_payload
            if proto_payload is not None
            else entry.get("payload")
            or entry.get("message")
            or ""
        )
        return ts, str(log_name), payload, _flatten_text(payload)

    ts = getattr(entry, "timestamp", None)
    log_name = getattr(entry, "log_name", "") or getattr(entry, "logName", "") or ""
    text_payload = getattr(entry, "text_payload", None)
    json_payload = getattr(entry, "json_payload", None)
    proto_payload = getattr(entry, "proto_payload", None)
    payload = (
        text_payload
        if text_payload is not None
        else json_payload
        if json_payload is not None
        else proto_payload
        if proto_payload is not None
        else getattr(entry, "payload", None)
        or getattr(entry, "message", None)
        or ""
    )
    return ts, str(log_name), payload, _flatten_text(payload)


def _deep_get(obj, *paths):
    for path in paths:
        current = obj
        ok = True
        for key in path:
            if isinstance(current, dict):
                if key not in current:
                    ok = False
                    break
                current = current[key]
            elif hasattr(current, key):
                current = getattr(current, key)
            else:
                ok = False
                break
        if ok and current not in (None, ""):
            return current
    return ""


def _field_payload(entry, field_name):
    """Read one LogEntry payload field without being overridden by another field."""
    if isinstance(entry, dict):
        return entry.get(field_name) or entry.get(
            field_name[0].lower() + field_name[1:]
        )
    snake = re.sub(r"(?<!^)([A-Z])", r"_\1", field_name).lower()
    value = getattr(entry, snake, None) or getattr(entry, field_name, None)
    if value is None and field_name in {"protoPayload", "proto_payload"}:
        value = getattr(entry, "payload", None)
    return value


def _resource_info(entry):
    if isinstance(entry, dict):
        return entry.get("resource") or {}
    return getattr(entry, "resource", None) or {}


def _payload_value(payload, *paths):
    return _deep_get(payload, *paths)


def parse_auth(logs):
    """Parse GCP LoginService identity-security events into a uniform audit model."""
    parsed = []
    login_methods = {
        "google.login.LoginService.loginSuccess": "SUCCESS",
        "google.login.LoginService.loginFailure": "FAILED",
        "google.login.LoginService.loginChallenge": "CHALLENGE",
        "google.login.LoginService.loginVerification": "VERIFIED",
        "google.login.LoginService.logout": "LOGOUT",
        "google.login.LoginService.suspiciousLogin": "SUSPICIOUS",
        "google.login.LoginService.suspiciousProgrammaticLogin": "SUSPICIOUS",
        "google.login.LoginService.twoStepVerification": "VERIFIED",
        "google.login.LoginService.accountDisabled": "DISABLED",
    }

    for entry in logs:
        ts, log_name, payload, _text = _entry_parts(entry)
        method = str(_payload_value(
            payload,
            ("methodName",), ("method_name",),
        ) or "").strip()
        service = str(_payload_value(payload, ("serviceName",), ("service_name",)) or "")
        if method not in login_methods and service != "login.googleapis.com":
            continue

        user_val = str(_payload_value(
            payload,
            ("authenticationInfo", "principalEmail"),
            ("authentication_info", "principal_email"),
            ("authenticationInfo", "principalSubject"),
            ("authentication_info", "principal_subject"),
            ("serviceAccountDelegationInfo", "firstPartyPrincipal", "principalEmail"),
            ("service_account_delegation_info", "first_party_principal", "principal_email"),
        ) or "unknown")
        ip_val = str(_payload_value(
            payload,
            ("requestMetadata", "callerIp"),
            ("request_metadata", "caller_ip"),
        ) or "unknown")
        user_agent = str(_payload_value(
            payload,
            ("requestMetadata", "callerSuppliedUserAgent"),
            ("request_metadata", "caller_supplied_user_agent"),
        ) or "-")
        resource_name = str(_payload_value(
            payload, ("resourceName",), ("resource_name",)
        ) or "unknown")
        resource = _resource_info(entry)
        if isinstance(resource, dict):
            labels = resource.get("labels") or {}
            resource_type = str(resource.get("type") or "audited_resource")
        else:
            labels = getattr(resource, "labels", {}) or {}
            resource_type = str(getattr(resource, "type", None) or "audited_resource")
        host = str(labels.get("instance_name") or labels.get("instance_id") or resource_name)

        parsed.append({
            "timestamp": ts,
            "project_id": extract_project_id(entry),
            "status": login_methods.get(method, "SECURITY_EVENT"),
            "method": method or "login.googleapis.com",
            "user": user_val,
            "ip": ip_val,
            "hostname": host,
            "resource_type": resource_type,
            "resource_name": resource_name,
            "login_method": method,
            "user_agent": user_agent,
            "severity": "NOTICE" if login_methods.get(method) in {"SUCCESS", "LOGOUT", "VERIFIED"} else "WARNING",
            "source_log": log_name or "Cloud Audit Logs",
            "raw": _flatten_text(payload),
        })

    return pd.DataFrame(parsed)

def parse_gcp_iam_logs(logs):
    """Extract GCP AuditLog activity, including human and service accounts."""
    rows = []

    for entry in logs:
        ts, log_name, payload, text = _entry_parts(entry)
        log_lower = log_name.casefold()

        email = _deep_get(
            payload,
            ("authentication_info", "principal_email"),
            ("authenticationInfo", "principalEmail"),
            ("authentication_info", "principalEmail"),
            ("principal_email",),
            ("principalEmail",),
            ("serviceAccountEmail",),
        )
        method_raw = _deep_get(
            payload,
            ("method_name",),
            ("methodName",),
        )
        resource_name = _deep_get(
            payload,
            ("resource_name",),
            ("resourceName",),
        )

        is_audit = (
            "cloudaudit" in log_lower
            or bool(email)
            or bool(method_raw)
            or "authentication_info" in text
            or "method_name" in text
            or "methodname" in text.casefold()
        )
        if not is_audit:
            continue

        if not email:
            email_match = re.search(r"[\w.\-+]+@[\w.\-]+", text)
            email = email_match.group(0) if email_match else "unknown"
        email = str(email)

        resource = None
        if isinstance(entry, dict):
            resource = entry.get("resource")
        else:
            resource = getattr(entry, "resource", None)
        res_type = _deep_get(resource, ("type",)) or "unknown"
        labels = _deep_get(resource, ("labels",)) or {}
        project_id = _deep_get(labels, ("project_id",), ("projectId",))
        if not resource_name:
            resource_name = f"projects/{project_id}" if project_id else str(res_type)

        req_meta = _deep_get(
            payload,
            ("request_metadata",),
            ("requestMetadata",),
        ) or {}
        ip = _deep_get(req_meta, ("caller_ip",), ("callerIp",)) or "private"
        user_agent = _deep_get(
            req_meta,
            ("caller_supplied_user_agent",),
            ("callerSuppliedUserAgent",),
        ) or ""

        if hasattr(entry, "severity"):
            severity = getattr(entry, "severity", None) or "NOTICE"
        elif isinstance(entry, dict):
            severity = entry.get("severity") or "NOTICE"
        else:
            severity = "NOTICE"

        if not method_raw:
            method_match = re.search(r"(?:methodName|method_name)\s*[:=]\s*['\"]?([^,\s'\"]+)", text, re.IGNORECASE)
            method_raw = method_match.group(1) if method_match else ""
        method = str(method_raw).split(".")[-1] if method_raw else "unknown"

        actor_type = "SERVICE ACCOUNT" if email.casefold().endswith("gserviceaccount.com") else "HUMAN / USER"

        authz = _deep_get(payload, ("authorizationInfo",), ("authorization_info",)) or []
        if isinstance(authz, dict):
            authz = [authz]
        granted_values = []
        permissions = []
        for item in authz if isinstance(authz, (list, tuple)) else []:
            permissions.append(str(_deep_get(item, ("permission",), ("Permission",)) or ""))
            granted_values.append(_deep_get(item, ("granted",), ("Granted",)))
        method_lower = str(method_raw or method).casefold()
        if any("read" in p.casefold() or ".get" in p.casefold() or ".list" in p.casefold() for p in permissions):
            permission_type = "DATA_READ"
        elif any(any(k in p.casefold() for k in ("write", "create", "delete", "setiampolicy", "update")) for p in permissions):
            permission_type = "ADMIN_WRITE"
        elif any(k in method_lower for k in ("get", "list", "read", "search")):
            permission_type = "DATA_READ"
        elif any(k in method_lower for k in ("set", "update", "create", "delete", "patch", "write", "iam")):
            permission_type = "ADMIN_WRITE"
        else:
            permission_type = "OTHER"
        granted = None
        if granted_values:
            meaningful = [v for v in granted_values if v not in (None, "")]
            if meaningful:
                granted = all(bool(v) for v in meaningful)
        if granted is None:
            lower_text = text.casefold()
            if "permission_denied" in lower_text or "permission denied" in lower_text or "denied" in lower_text:
                granted = False
            elif "success" in lower_text or "request completed" in lower_text:
                granted = True

        rows.append(
            {
                "timestamp": ts,
                "Date": ts.strftime("%Y-%m-%d") if ts is not None and hasattr(ts, "strftime") else "",
                "Time": ts.strftime("%H:%M:%S") if ts is not None and hasattr(ts, "strftime") else "",
                "Email": email,
                "Actor Type": actor_type,
                "Resource": str(res_type),
                "Resource Name": str(resource_name),
                "Permission Type": permission_type,
                "Granted": "[true]" if granted is True else "[false]" if granted is False else "[unknown]",
                "permission_type": permission_type,
                "permission": permissions[0] if permissions and permissions[0] else str(method_raw or method),
                "permission_granted": granted,
                "Method": method,
                "IP": str(ip),
                "User Agent": str(user_agent),
                "Severity": str(severity),
                "source_log": log_name or "Cloud Logging",
                "raw": text,
            }
        )

    return pd.DataFrame(rows)


def failed_ip_anomaly(auth_df, threshold=5):
    """Detect IPs with failed logins at/above the configured threshold."""
    if auth_df.empty or "status" not in auth_df.columns or "ip" not in auth_df.columns:
        return pd.DataFrame(columns=["ip", "failed_attempts", "anomaly"])

    failed = auth_df[auth_df["status"] == "FAILED"]
    if failed.empty:
        return pd.DataFrame(columns=["ip", "failed_attempts", "anomaly"])

    counts = failed["ip"].value_counts().reset_index()
    counts.columns = ["ip", "failed_attempts"]
    counts["anomaly"] = counts["failed_attempts"] >= threshold
    return counts


def user_profile(auth_df):
    """Create per-user authentication activity profile."""
    if auth_df.empty or "user" not in auth_df.columns or "status" not in auth_df.columns:
        return pd.DataFrame(columns=["success", "failed"])

    profile = auth_df.groupby(["user", "status"]).size().unstack(fill_value=0)
    for col in ["SUCCESS", "FAILED"]:
        if col not in profile.columns:
            profile[col] = 0

    profile.rename(columns={"SUCCESS": "success", "FAILED": "failed"}, inplace=True)
    return profile

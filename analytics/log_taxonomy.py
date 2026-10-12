# -*- coding: utf-8 -*-
"""Automatic taxonomy for project-wide Google Cloud logs.

The classifier is intentionally evidence-based: it prefers structured LogEntry
metadata (logName, resource.type, protoPayload) and only falls back to textual
markers when the structured fields are not available.
"""

from urllib.parse import unquote
import re


CLOUD_AUDIT_MAP = {
    "activity": "Admin Activity Logs",
    "data_access": "Data Access Logs",
    "system_event": "System Event Logs",
    "policy": "Policy Denied Logs",
}

TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _get(entry, *keys, default=""):
    if isinstance(entry, dict):
        for key in keys:
            if key in entry and entry[key] not in (None, ""):
                return entry[key]
        return default
    for key in keys:
        value = getattr(entry, key, None)
        if value not in (None, ""):
            return value
    return default


def _nested(obj, *path):
    current = obj
    for key in path:
        if isinstance(current, dict):
            if key not in current:
                return ""
            current = current[key]
        elif hasattr(current, key):
            current = getattr(current, key)
        else:
            return ""
        if current in (None, ""):
            return ""
    return current


def payloads(entry):
    """Return common structured payload variants, including ProtobufEntry.payload."""
    if isinstance(entry, dict):
        generic = _get(entry, "payload", default={})
        return {
            "json": _get(entry, "json_payload", "jsonPayload", default={}),
            "proto": _get(entry, "proto_payload", "protoPayload", default={}) or generic,
            "text": _get(entry, "text_payload", "textPayload", default=""),
        }

    generic = _get(entry, "payload", default={})
    proto = _get(entry, "proto_payload", "protoPayload", default={})
    # Cloud Logging ProtobufEntry stores google.logging.v2.LogEntry.payload
    # as the actual AuditLog protobuf. Treat it as the proto payload when the
    # dedicated proto_payload property is absent.
    if not proto and entry.__class__.__name__.lower().startswith("protobuf"):
        proto = generic
    return {
        "json": _get(entry, "json_payload", "jsonPayload", default={}),
        "proto": proto,
        "text": _get(entry, "text_payload", "textPayload", default=""),
    }


def text_payload(entry):
    parts = payloads(entry)
    values = [parts["text"], parts["json"], parts["proto"]]
    out = []
    for value in values:
        if isinstance(value, dict):
            out.extend(str(k) for k in value.keys())
            out.append(str(value))
        elif value not in (None, ""):
            out.append(str(value))
    return " ".join(out)


def method_name(entry):
    proto = payloads(entry)["proto"]
    return str(
        _nested(proto, "methodName")
        or _nested(proto, "method_name")
        or ""
    )


def log_name(entry):
    return str(_get(entry, "log_name", "logName", default=""))


def resource_type(entry):
    resource = _get(entry, "resource", default={})
    return str(_nested(resource, "type") or "")


def resource_name(entry):
    resource = _get(entry, "resource", default={})
    labels = _nested(resource, "labels") or {}
    if isinstance(labels, dict):
        for key in ("instance_name", "instance_id", "instanceName", "project_id", "projectId"):
            if labels.get(key):
                return str(labels[key])
    return ""


def _decoded_log_name(entry):
    return unquote(log_name(entry)).casefold()


def extract_technique_ids(entry):
    raw = text_payload(entry)
    return sorted({m.upper() for m in TECHNIQUE_ID_RE.findall(raw)})


def classify_gcp_log(entry):
    """Return a stable group/subcategory for a raw Cloud Logging entry."""
    lname = _decoded_log_name(entry)
    rtype = resource_type(entry).casefold()
    raw = text_payload(entry).casefold()
    proto_method = method_name(entry).casefold()
    service_name = str(_nested(payloads(entry)["proto"], "serviceName") or _nested(payloads(entry)["proto"], "service_name") or "").casefold()

    # Google Workspace/GCP Login Audit events are identity-security telemetry.
    # They may live at organization scope and therefore need an explicit class.
    if proto_method.startswith("google.login.loginservice.") or service_name == "login.googleapis.com":
        return {
            "group": "C. Network Log & Specific Security",
            "subcategory": "GCP Login Audit Logs",
            "source_system": "Google Login Audit",
        }

    # Sources that belong to the security-specific stream take precedence.
    if (
        "chronicle" in lname
        or "securityoperations" in lname
        or "security_operations" in lname
        or "security operations" in raw
        or "udm" in lname
    ):
        return {
            "group": "C. Network Log & Specific Security",
            "subcategory": "Google Security Operations (Chronicle)",
            "source_system": "Google Security Operations / Chronicle",
        }

    if (
        "securitycenter" in lname
        or "security-command-center" in lname
        or rtype in {"threat_detector", "securitycenter.googleapis.com"}
        or "security command center" in raw
        or "event threat detection" in raw
    ):
        # ETD is a specific SCC detection pipeline; otherwise classify as SCC.
        sub = (
            "Cloud Security Command Center (SCC) - Event Threat Detection"
            if "event threat detection" in raw or rtype == "threat_detector"
            else "Security Command Center (SCC)"
        )
        return {
            "group": "C. Network Log & Specific Security",
            "subcategory": sub,
            "source_system": "Security Command Center",
        }

    if (
        "abuse" in lname
        or "gcp_abuse" in lname
        or "abuseevent" in raw
        or "abuse_event" in raw
        or "cloud abuse" in raw
    ):
        return {
            "group": "C. Network Log & Specific Security",
            "subcategory": "GCP Abuse Events",
            "source_system": "Google Cloud Abuse",
        }

    # Cloud Audit Logs.
    audit_match = re.search(r"cloudaudit\.googleapis\.com/(activity|data_access|system_event|policy)\b", lname)
    if audit_match:
        return {
            "group": "A. Cloud Audit Logs",
            "subcategory": CLOUD_AUDIT_MAP[audit_match.group(1)],
            "source_system": "Cloud Audit Logs",
        }

    # Structured audit markers are useful for fixtures/shippers that omit logName.
    if proto_method or "authenticationinfo" in raw:
        if "denied" in raw or "permissiondenied" in raw:
            return {
                "group": "A. Cloud Audit Logs",
                "subcategory": "Policy Denied Logs",
                "source_system": "Cloud Audit Logs",
            }
        # Google Cloud AuditLog entries without a recognizable suffix are treated
        # as Admin Activity because that is the safest non-data-access default.
        return {
            "group": "A. Cloud Audit Logs",
            "subcategory": "Admin Activity Logs",
            "source_system": "Cloud Audit Logs",
        }

    # Network logging.
    if (
        "vpc_flows" in lname
        or "vpc-flow" in lname
        or "vpc flow" in raw
        or "flowlog" in raw
        or rtype in {"vpc_flow", "vpcflow", "networkmanagement.googleapis.com/vpc_flow"}
    ):
        return {
            "group": "C. Network Log & Specific Security",
            "subcategory": "VPC Flow Logs",
            "source_system": "VPC Flow Logs",
        }

    if (
        "firewall" in lname
        or "firewall" in raw
        or "compute.googleapis.com/firewall" in rtype
        or "gce_subnetwork" in rtype and "disposition" in raw
    ):
        return {
            "group": "C. Network Log & Specific Security",
            "subcategory": "Firewall Rules Logs",
            "source_system": "Firewall Rules Logging",
        }

    # Platform / application logs.
    platform_markers = (
        "platform" in lname,
        "cloudrun" in lname,
        "cloud_run" in lname,
        "appengine" in lname,
        "app_engine" in lname,
        "cloudfunctions" in lname,
        "cloud_functions" in lname,
        "kubernetes" in lname,
        rtype.startswith("k8s_"),
        rtype in {"cloud_run_revision", "gae_app", "cloud_function"},
    )
    if any(platform_markers):
        return {
            "group": "B. Platform Logs & Application Logs",
            "subcategory": "Platform Logs",
            "source_system": "Google Cloud Platform",
        }

    # Remaining non-audit project/application entries are user-defined/app logs.
    return {
        "group": "B. Platform Logs & Application Logs",
        "subcategory": "User-defined/Application Logs",
        "source_system": "User-defined / Application",
    }

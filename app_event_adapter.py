"""Adapter from provider log entries to the canonical event model."""
from __future__ import annotations
import json
import hashlib
import re
from analytics.log_taxonomy import classify_gcp_log
from collectors.cloud_scope import extract_project_id
from core.event_schema import SecurityEvent, stable_event_id


def _payload(entry):
    if isinstance(entry, dict):
        return entry.get("protoPayload") or entry.get("proto_payload") or entry.get("jsonPayload") or entry.get("json_payload") or entry.get("textPayload") or entry.get("text_payload") or entry.get("payload") or ""
    return getattr(entry, "payload", None) or getattr(entry, "proto_payload", None) or getattr(entry, "json_payload", None) or getattr(entry, "text_payload", None) or ""


def _get(obj, *paths):
    for path in paths:
        cur = obj
        for key in path:
            if isinstance(cur, dict): cur = cur.get(key)
            else: cur = getattr(cur, key, None)
            if cur is None: break
        if cur not in (None, ""): return cur
    return ""


GCE_INSTANCE_RESOURCE_RE = re.compile(
    r"^projects/(?P<project>[^/]+)/zones/(?P<zone>[^/]+)/instances/(?P<instance>[^/]+)$",
    re.IGNORECASE,
)


def _device_id(resource_type: str, labels: dict, resource_name: str, project_id: str) -> str:
    """Resolve GCP resource identity without collapsing distinct devices.

    Preference order: explicit device label → normalized GCE instance resource →
    normalized GCE label identity → deterministic hash for non-compute resources.
    """
    labels = labels if isinstance(labels, dict) else {}
    explicit = labels.get("device_id") or labels.get("deviceId")
    if explicit:
        return str(explicit).strip()

    kind = str(resource_type or "").strip().casefold()
    resource = str(resource_name or "").strip()
    project = str(project_id or labels.get("project_id") or labels.get("projectId") or "").strip()
    instance_id = str(labels.get("instance_id") or labels.get("instanceId") or "").strip()
    instance_name = str(labels.get("instance_name") or labels.get("instanceName") or "").strip()
    zone = str(labels.get("zone") or labels.get("location") or "").strip()

    match = GCE_INSTANCE_RESOURCE_RE.match(resource) if resource else None
    if match and kind in {"", "gce_instance", "gce_instance_group", "gce_instance_group_manager", "gce_instance_template"}:
        project = project or match.group("project")
        zone = zone or match.group("zone")
        instance_name = instance_name or match.group("instance")

    if kind in {"gce_instance", "gce_instance_group", "gce_instance_group_manager", "gce_instance_template"}:
        identity = instance_id or instance_name
        if identity:
            return f"gce:{project}:{zone}:{identity}" if zone else f"gce:{project}:{identity}"

    if resource:
        compact = hashlib.sha256(f"{project}|{kind}|{resource}".encode("utf-8")).hexdigest()[:20]
        return f"gcp:{kind or 'resource'}:{compact}"
    return ""


def normalize_cloud_entry(entry) -> dict:
    payload = _payload(entry)
    timestamp = entry.get("timestamp") if isinstance(entry, dict) else getattr(entry, "timestamp", None)
    log_name = entry.get("logName") or entry.get("log_name") if isinstance(entry, dict) else getattr(entry, "log_name", "")
    method = str(_get(payload, ("methodName",), ("method_name",)) or "")
    principal = str(_get(
        payload,
        ("authenticationInfo", "principalEmail"),
        ("authentication_info", "principal_email"),
        ("authenticationInfo", "principalSubject"),
        ("authentication_info", "principal_subject"),
        ("serviceAccountDelegationInfo", "firstPartyPrincipal", "principalEmail"),
        ("service_account_delegation_info", "first_party_principal", "principal_email"),
    ) or "")
    caller_ip = str(_get(payload, ("requestMetadata","callerIp"), ("request_metadata","caller_ip")) or "")
    resource_name = str(_get(payload, ("resourceName",), ("resource_name",)) or "")
    category = "ACTIVITY"
    try:
        category = classify_gcp_log(entry).get("subcategory", category)
    except Exception:
        pass
    login_method = "loginservice" in method.casefold() or str(_get(payload, ("serviceName",), ("service_name",)) or "") == "login.googleapis.com"
    action = "LOGIN" if login_method else method or "LOG_EVENT"
    outcome = "SUCCESS" if method.endswith("loginSuccess") else "FAILURE" if method.endswith("loginFailure") else "SUSPICIOUS" if "suspicious" in method.casefold() else "UNKNOWN"
    resource = entry.get("resource") or {} if isinstance(entry, dict) else getattr(entry, "resource", {}) or {}
    if isinstance(resource, dict):
        rtype = str(resource.get("type") or "")
        labels = resource.get("labels") or {}
    else:
        rtype = str(getattr(resource, "type", "") or "")
        labels = getattr(resource, "labels", {}) or {}
    rid = resource_name or str(labels.get("instance_name") or labels.get("instance_id") or "")
    project_id = str(extract_project_id(entry) or "")
    if not project_id:
        project_id = str(labels.get("project_id") or labels.get("projectId") or "")
    device_id = _device_id(rtype, labels, resource_name or rid, project_id)
    status_code = _get(payload, ("status", "code"), ("status", "Code"), ("status", "codeValue"), ("status", "code_value"))
    authz = _get(payload, ("authorizationInfo",), ("authorization_info",)) or []
    if isinstance(authz, dict): authz = [authz]
    grant_values = [_get(item, ("granted",), ("Granted",)) for item in authz if isinstance(item, dict)]
    permission_granted = all(value is True for value in grant_values) if grant_values else None
    permission = str(_get(authz[0], ("permission",), ("Permission",)) or "") if authz and isinstance(authz[0], dict) else ""
    # Preserve explicit LoginService outcomes. Generic AuditLog status codes must
    # not overwrite loginSuccess/loginFailure/suspiciousLogin semantics.
    if not login_method:
        status_text = str(status_code or "").strip()
        if permission_granted is False or status_text == "7":
            outcome = "DENIED"
        elif status_text and status_text != "0":
            # Kode status non-nol = kegagalan (mis. 3 INVALID_ARGUMENT, 5 NOT_FOUND).
            outcome = "FAILURE"
        elif outcome == "UNKNOWN":
            # Audit log tanpa status error dianggap berhasil (bukan UNKNOWN).
            outcome = "SUCCESS"
    severity = str(_get(entry, ("severity",),) or "DEFAULT")
    insert_id = str(_get(entry, ("insertId",), ("insert_id",)) or "")
    # Prefer the provider's immutable identifiers (logName + insertId) for the
    # canonical ID. Falling back to the schema's content hash keeps fixtures and
    # non-standard shippers deterministic when insertId is absent.
    provider_event_id = stable_event_id({
        "provider": "gcp.cloud_logging",
        "log_name": str(log_name),
        "insert_id": insert_id,
        "project_id": project_id,
    }) if insert_id and log_name else ""
    event = SecurityEvent(
        event_id=provider_event_id,
        event_time=timestamp,
        source_system="GCP",
        source_type=category,
        collector="cloud_logging",
        event_category="AUTHENTICATION" if login_method else "CLOUD_ACTIVITY",
        event_action=action,
        event_outcome=outcome,
        principal_id=principal,
        principal_name=principal,
        principal_type="SERVICE ACCOUNT" if "gserviceaccount.com" in principal else "HUMAN" if "@" in principal else "UNKNOWN",
        device_id=device_id,
        source_ip=caller_ip,
        resource_type=rtype,
        resource_id=rid,
        resource_name=rid,
        api_method=method,
        permission=permission,
        permission_granted=permission_granted,
        project_id=project_id,
        # Retain structured evidence even when methodName exists; method alone
        # previously made manual search silently lose request/audit diagnostics.
        detail=json.dumps(payload, default=str, ensure_ascii=False, sort_keys=True)[:12000] if isinstance(payload, (dict, list, tuple)) else str(payload)[:12000],
        raw_reference=str(log_name),
        extensions={
            "log_name": str(log_name),
            "severity": severity,
            "insert_id": insert_id,
            "telemetry_stream": "LOGIN_AUDIT" if login_method else "GENERAL",
            "gcp_resource_name": resource_name,
        },
    )
    normalized = event.finalize().to_dict()
    normalized["log_name"] = str(log_name)
    normalized["gcp_severity"] = severity
    normalized["insert_id"] = insert_id
    # The v7 schema calls this event_time, while downstream pipeline/dashboards
    # use timestamp. Preserve the typed canonical field and supply the alias.
    normalized["timestamp"] = normalized["event_time"]
    return normalized

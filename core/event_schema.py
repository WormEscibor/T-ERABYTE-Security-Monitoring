"""Canonical event schema for T-ERABYTE CSIRT SOC PRO.

The schema is deliberately provider-neutral so Cloud Logging, SCC, auditd,
FHIR/API, threat-intelligence and future collectors can share one model.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Mapping


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _clean(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Mapping):
        return {str(k): _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_clean(v) for v in value]
    return value


def stable_event_id(payload: Mapping[str, Any]) -> str:
    """Create a deterministic event id for idempotent processing."""
    canonical = json.dumps(_clean(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class SecurityEvent:
    event_id: str = ""
    event_time: datetime | None = None
    ingest_time: datetime = field(default_factory=utc_now)
    source_system: str = "unknown"
    source_type: str = "unknown"
    collector: str = "unknown"
    event_category: str = "UNKNOWN"
    event_action: str = "UNKNOWN"
    event_outcome: str = "UNKNOWN"
    principal_id: str = ""
    principal_name: str = ""
    principal_type: str = "UNKNOWN"
    session_id: str = ""
    device_id: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    source_country: str = ""
    source_asn: str = ""
    resource_type: str = ""
    resource_id: str = ""
    resource_name: str = ""
    project_id: str = ""
    folder_id: str = ""
    organization_id: str = ""
    api_method: str = ""
    command: str = ""
    process: str = ""
    permission: str = ""
    permission_type: str = ""
    permission_granted: bool | None = None
    data_classification: str = "UNKNOWN"
    data_volume: float = 0.0
    asset_criticality: str = "MEDIUM"
    mitre_tactic: str = ""
    mitre_technique: str = ""
    threat_intel_match: bool = False
    threat_intel_confidence: float = 0.0
    anomaly_score: float = 0.0
    baseline_deviation: float = 0.0
    rarity_score: float = 0.0
    trust_score: float = 50.0
    risk_score: float = 0.0
    confidence: float = 0.0
    raw_reference: str = ""
    evidence_reference: str = ""
    detail: str = ""
    tags: list[str] = field(default_factory=list)
    extensions: dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> "SecurityEvent":
        if self.event_time is None:
            self.event_time = self.ingest_time
        if not self.event_id:
            self.event_id = stable_event_id({
                "event_time": self.event_time,
                "source_system": self.source_system,
                "source_type": self.source_type,
                "principal_id": self.principal_id,
                "source_ip": self.source_ip,
                "event_category": self.event_category,
                "event_action": self.event_action,
                "resource_id": self.resource_id,
                "detail": self.detail,
            })
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self.finalize())




# Canonical event defaults used at every pipeline boundary.  Live GCP streams can
# legitimately contain a different projection (for example the LoginService
# parser used for the dedicated authentication panel).  Downstream analytics
# must never depend on a particular collector projection being present.
_NUMERIC_EVENT_FIELDS = {
    "data_volume": 0.0,
    "anomaly_score": 0.0,
    "baseline_deviation": 0.0,
    "rarity_score": 0.0,
    "trust_score": 50.0,
    "risk_score": 0.0,
    "confidence": 0.0,
}
_BOOLEAN_EVENT_FIELDS = {
    "threat_intel_match": False,
}
_NONE_EVENT_FIELDS = {
    "permission_granted": None,
}
_TEXT_EVENT_FIELDS = (
    "source_system", "source_type", "collector", "event_category",
    "event_action", "event_outcome", "principal_id", "principal_name",
    "principal_type", "session_id", "device_id", "source_ip",
    "destination_ip", "source_country", "source_asn", "resource_type",
    "resource_id", "resource_name", "project_id", "folder_id",
    "organization_id", "api_method", "command", "process", "permission",
    "permission_type", "data_classification", "asset_criticality",
    "mitre_tactic", "mitre_technique", "raw_reference",
    "evidence_reference", "detail",
)


def ensure_canonical_event_frame(events, project_id: str = ""):
    """Return a dataframe safe for every downstream canonical-event consumer.

    Collector-specific projections are intentionally allowed at the ingestion
    boundary, but analytics operate on one stable schema.  Missing fields are
    populated with semantically neutral values instead of allowing pandas to
    raise errors such as ``Column(s) ['risk_score'] do not exist``.
    Existing non-empty project identifiers are never overwritten.
    """
    import pandas as pd

    if events is None or not isinstance(events, pd.DataFrame):
        return pd.DataFrame(columns=dataframe_columns() + ["timestamp", "log_name", "gcp_severity", "insert_id"])

    out = events.copy()
    if out.empty:
        for field_name, default in _NUMERIC_EVENT_FIELDS.items():
            if field_name not in out.columns:
                out[field_name] = pd.Series(dtype="float64")
        for field_name in _BOOLEAN_EVENT_FIELDS:
            if field_name not in out.columns:
                out[field_name] = pd.Series(dtype="bool")
        for field_name in _NONE_EVENT_FIELDS:
            if field_name not in out.columns:
                out[field_name] = pd.Series(dtype="object")
        for field_name in _TEXT_EVENT_FIELDS:
            if field_name not in out.columns:
                out[field_name] = pd.Series(dtype="object")
        for field_name in ("event_time", "ingest_time"):
            if field_name not in out.columns:
                out[field_name] = pd.Series(dtype="datetime64[ns, UTC]")
        if "event_id" not in out.columns:
            out["event_id"] = pd.Series(dtype="object")
        if "tags" not in out.columns:
            out["tags"] = pd.Series(dtype="object")
        if "extensions" not in out.columns:
            out["extensions"] = pd.Series(dtype="object")
        for field_name in ("timestamp", "log_name", "gcp_severity", "insert_id"):
            if field_name not in out.columns:
                out[field_name] = pd.Series(dtype="object")
        return out.reset_index(drop=True)

    for field_name in _TEXT_EVENT_FIELDS:
        if field_name not in out.columns:
            out[field_name] = ""
    for field_name, default in _NUMERIC_EVENT_FIELDS.items():
        if field_name not in out.columns:
            out[field_name] = default
        out[field_name] = pd.to_numeric(out[field_name], errors="coerce").fillna(default)
    for field_name, default in _BOOLEAN_EVENT_FIELDS.items():
        if field_name not in out.columns:
            out[field_name] = default
        # Preserve actual booleans while accepting common provider encodings.
        out[field_name] = (
            out[field_name]
            .map(lambda value: value if isinstance(value, bool) else str(value).strip().casefold() in {"true", "1", "yes"})
            .fillna(default)
            .astype(bool)
        )
    for field_name, default in _NONE_EVENT_FIELDS.items():
        if field_name not in out.columns:
            out[field_name] = default
    if "tags" not in out.columns:
        out["tags"] = [[] for _ in range(len(out))]
    if "extensions" not in out.columns:
        out["extensions"] = [{} for _ in range(len(out))]

    if "event_time" not in out.columns:
        out["event_time"] = out.get("timestamp")
    if "timestamp" not in out.columns:
        out["timestamp"] = out.get("event_time")
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out["event_time"] = pd.to_datetime(out["event_time"], errors="coerce", utc=True)
    if "ingest_time" not in out.columns:
        out["ingest_time"] = out["timestamp"]
    out["ingest_time"] = pd.to_datetime(out["ingest_time"], errors="coerce", utc=True)

    if "project_id" in out.columns and str(project_id or "").strip():
        project = str(project_id).strip()
        empty_project = out["project_id"].fillna("").astype(str).str.strip().eq("")
        out.loc[empty_project, "project_id"] = project

    if "event_id" not in out.columns:
        out["event_id"] = ""
    out["event_id"] = out["event_id"].fillna("").astype(str).str.strip()
    missing_id = out["event_id"].eq("")
    if missing_id.any():
        stable_fields = (
            "timestamp", "source_system", "source_type", "event_category",
            "event_action", "event_outcome", "principal_id", "source_ip",
            "resource_id", "resource_name", "api_method", "command", "detail",
        )
        out.loc[missing_id, "event_id"] = [
            stable_event_id({key: row.get(key) for key in stable_fields})
            for _, row in out.loc[missing_id].iterrows()
        ]

    # These adapter fields are intentionally retained as optional extras.
    if "log_name" not in out.columns:
        out["log_name"] = out.get("raw_reference", "")
    out["log_name"] = out["log_name"].fillna("").astype(str)
    if "gcp_severity" not in out.columns:
        out["gcp_severity"] = "DEFAULT"
    out["gcp_severity"] = out["gcp_severity"].fillna("DEFAULT").astype(str)
    if "insert_id" not in out.columns:
        out["insert_id"] = ""
    out["insert_id"] = out["insert_id"].fillna("").astype(str)
    return out.reset_index(drop=True)


def dataframe_columns() -> list[str]:
    return list(SecurityEvent.__dataclass_fields__.keys())

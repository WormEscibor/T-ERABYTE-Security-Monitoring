"""Identity resolution and continuity analytics."""
from __future__ import annotations
import re
import pandas as pd

from core.event_schema import ensure_canonical_event_frame

SERVICE_SUFFIX = "gserviceaccount.com"


def identity_type(identifier: object) -> str:
    value = str(identifier or "").strip().casefold()
    if value in {"", "root", "system", "unknown", "anonymous", "-", "system@google.com", "noreply@google.com"}:
        return "SYSTEM"
    if SERVICE_SUFFIX in value or value.startswith("sa-") or value.startswith("svc-"):
        return "SERVICE ACCOUNT"
    if "@" in value:
        return "HUMAN"
    if value.startswith("uid:") and value[4:].isdigit() and value[4:] not in {"0", "4294967295"}:
        return "HUMAN"
    return "UNKNOWN"


def normalize_identity(value: object) -> str:
    return str(value or "").strip().casefold()


def resolve_identity(events: pd.DataFrame) -> pd.DataFrame:
    out = ensure_canonical_event_frame(events)
    if out.empty:
        return out
    for col in ("principal_id", "principal_name"):
        if col not in out.columns:
            out[col] = ""
    out["principal_id"] = out["principal_id"].fillna("").map(normalize_identity)
    out["principal_name"] = out["principal_name"].fillna("").astype(str)
    def _resolved_type(row):
        current = str(row.get("principal_type") or "").strip().upper()
        if current and current != "UNKNOWN":
            # Koreksi defensif untuk identitas sistem yang jelas.
            if identity_type(row.get("principal_id") or row.get("principal_name")) == "SYSTEM":
                return "SYSTEM"
            return current
        return identity_type(row.get("principal_id") or row.get("principal_name"))

    out["principal_type"] = out.apply(_resolved_type, axis=1)
    out["identity_key"] = out["principal_id"].where(out["principal_id"] != "", out["principal_name"].map(normalize_identity))
    out["identity_display"] = out["principal_name"].where(out["principal_name"] != "", out["identity_key"])
    return out


def identity_summary(events: pd.DataFrame) -> pd.DataFrame:
    out = resolve_identity(events)
    if out.empty:
        return pd.DataFrame()
    grouped = out.groupby(["identity_key", "identity_display", "principal_type"], dropna=False)
    summary = grouped.agg(
        events=("event_id", "count"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        unique_ips=("source_ip", "nunique"),
        unique_devices=("device_id", "nunique"),
        unique_sessions=("session_id", "nunique"),
        unique_resources=("resource_id", "nunique"),
        anomaly_score=("anomaly_score", "mean"),
        risk_score=("risk_score", "max"),
    ).reset_index()
    return summary.sort_values("risk_score", ascending=False, kind="stable")

"""Session reconstruction and forensic windowing."""
from __future__ import annotations
import hashlib
import pandas as pd

from core.event_schema import ensure_canonical_event_frame


def sessionize(events: pd.DataFrame, gap_minutes: int = 30) -> pd.DataFrame:
    events = ensure_canonical_event_frame(events)
    if events.empty:
        return events.copy()
    out = events.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out = out.sort_values(["principal_id", "timestamp"], kind="stable")
    out["session_gap_min"] = out.groupby("principal_id")["timestamp"].diff().dt.total_seconds().div(60).fillna(gap_minutes + 1)
    new_session = out["session_gap_min"] > gap_minutes
    out["session_sequence"] = new_session.groupby(out["principal_id"]).cumsum()
    out["session_id_derived"] = out.apply(
        lambda r: hashlib.sha1(f"{r.get('principal_id','')}|{r.get('session_sequence')}|{r.get('timestamp')}".encode()).hexdigest()[:16],
        axis=1,
    )
    out["session_id"] = out["session_id"].replace("", pd.NA).fillna(out["session_id_derived"])
    return out


def session_summary(events: pd.DataFrame) -> pd.DataFrame:
    if events.empty:
        return pd.DataFrame()
    out = sessionize(events)
    return out.groupby("session_id", dropna=False).agg(
        user=("principal_id", "first"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        events=("event_id", "count"),
        source_ip=("source_ip", "first"),
        device=("device_id", "first"),
        max_risk=("risk_score", "max"),
        max_anomaly=("anomaly_score", "max"),
    ).reset_index().sort_values("max_risk", ascending=False, kind="stable")

"""Temporal entity graph utilities using pandas-friendly edge lists."""
from __future__ import annotations
from collections import Counter
import pandas as pd

from core.event_schema import ensure_canonical_event_frame

ENTITY_FIELDS = [
    ("USER", "principal_id"),
    ("DEVICE", "device_id"),
    ("IP", "source_ip"),
    ("SESSION", "session_id"),
    ("PROJECT", "project_id"),
    ("RESOURCE", "resource_id"),
]


def build_edges(events: pd.DataFrame) -> pd.DataFrame:
    events = ensure_canonical_event_frame(events)
    rows = []
    if events.empty:
        return pd.DataFrame(columns=["source_type", "source", "relationship", "target_type", "target", "timestamp", "risk_score", "confidence"])
    for _, row in events.iterrows():
        stamp = row.get("timestamp")
        principal = str(row.get("principal_id") or "").strip()
        for target_type, field in ENTITY_FIELDS[1:]:
            target = str(row.get(field) or "").strip()
            if not principal or not target or target in {"nan", "-"}:
                continue
            rows.append({
                "source_type": "USER",
                "source": principal,
                "relationship": {
                    "device_id": "USES",
                    "source_ip": "FROM",
                    "session_id": "CREATES",
                    "project_id": "ACCESSES",
                    "resource_id": "TOUCHES",
                }.get(field, "RELATED"),
                "target_type": target_type,
                "target": target,
                "timestamp": stamp,
                "risk_score": float(row.get("risk_score") or 0),
                "confidence": float(row.get("confidence") or 0),
            })
    return pd.DataFrame(rows).drop_duplicates(subset=["source_type", "source", "target_type", "target", "relationship", "timestamp"])


def graph_summary(edges: pd.DataFrame) -> pd.DataFrame:
    if edges.empty:
        return pd.DataFrame()
    a = edges.groupby(["source_type", "source"], dropna=False).agg(
        relationships=("target", "count"),
        targets=("target", "nunique"),
        max_risk=("risk_score", "max"),
        avg_confidence=("confidence", "mean"),
    ).reset_index()
    return a.sort_values("max_risk", ascending=False, kind="stable")


def blast_radius(edges: pd.DataFrame, source: str, max_hops: int = 3) -> dict:
    if edges.empty or not source:
        return {"nodes": [], "edges": 0, "max_risk": 0.0}
    frontier = {source}
    seen = {source}
    selected = []
    for _ in range(max_hops):
        if not frontier:
            break
        mask = edges["source"].isin(frontier) | edges["target"].isin(frontier)
        layer = edges.loc[mask]
        if layer.empty:
            break
        selected.append(layer)
        nxt = set(layer["source"].astype(str)) | set(layer["target"].astype(str))
        nxt -= seen
        seen |= nxt
        frontier = nxt
    selected_df = pd.concat(selected, ignore_index=True) if selected else pd.DataFrame()
    return {
        "nodes": sorted(seen),
        "edges": int(len(selected_df)),
        "max_risk": float(selected_df["risk_score"].max()) if not selected_df.empty else 0.0,
    }

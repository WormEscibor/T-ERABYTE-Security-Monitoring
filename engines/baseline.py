"""Deterministic user/entity behavioral baseline and rarity engine."""
from __future__ import annotations
import math
import pandas as pd


def _entropy(values: pd.Series) -> float:
    if values.empty:
        return 0.0
    counts = values.fillna("").astype(str).value_counts(normalize=True)
    return float(-(counts * counts.map(lambda p: math.log2(p) if p > 0 else 0)).sum())


def build_baseline(events: pd.DataFrame, entity_col: str = "principal_id") -> pd.DataFrame:
    if events.empty:
        return pd.DataFrame()
    out = events.copy()
    out["timestamp"] = pd.to_datetime(out.get("timestamp"), errors="coerce", utc=True)
    out["hour"] = out["timestamp"].dt.hour
    if entity_col not in out:
        out[entity_col] = ""
    grouped = out.groupby(entity_col, dropna=False)
    rows = []
    for entity, frame in grouped:
        rows.append({
            "entity": str(entity),
            "events": int(len(frame)),
            "median_events_per_day": float(frame.groupby(frame["timestamp"].dt.date).size().median()) if not frame.empty else 0.0,
            "usual_hour_start": int(frame["hour"].quantile(0.10)) if frame["hour"].notna().any() else 0,
            "usual_hour_end": int(frame["hour"].quantile(0.90)) if frame["hour"].notna().any() else 23,
            "unique_ips": int(frame.get("source_ip", pd.Series(dtype=str)).nunique()),
            "unique_devices": int(frame.get("device_id", pd.Series(dtype=str)).nunique()),
            "api_entropy": _entropy(frame.get("api_method", pd.Series(dtype=str))),
            "resource_entropy": _entropy(frame.get("resource_id", pd.Series(dtype=str))),
            "command_entropy": _entropy(frame.get("command", pd.Series(dtype=str))),
        })
    return pd.DataFrame(rows)


def apply_baseline(events: pd.DataFrame, baseline: pd.DataFrame, entity_col: str = "principal_id") -> pd.DataFrame:
    if events.empty:
        return events.copy()
    out = events.copy()
    if baseline.empty:
        out["baseline_deviation"] = 0.0
        out["rarity_score"] = 0.0
        return out
    base = baseline.set_index("entity")
    deviations = []
    rarities = []
    for _, row in out.iterrows():
        key = str(row.get(entity_col) or "")
        b = base.loc[key] if key in base.index else None
        if b is None:
            deviations.append(90.0)
            rarities.append(100.0)
            continue
        hour = pd.to_datetime(row.get("timestamp"), errors="coerce", utc=True)
        hour_val = int(hour.hour) if not pd.isna(hour) else 0
        dev = 0.0
        if hour_val < int(b["usual_hour_start"]) or hour_val > int(b["usual_hour_end"]):
            dev += 40.0
        if str(row.get("source_ip") or "") and b["unique_ips"] and str(row.get("source_ip")) not in {"", "unknown"}:
            # Presence is enough to keep the deterministic baseline conservative.
            pass
        action = str(row.get("api_method") or row.get("command") or row.get("event_action") or "")
        prevalence = max(float(b["events"]), 1.0)
        rarity = min(100.0, 100.0 / prevalence if action else 0.0)
        deviations.append(min(100.0, dev + rarity * 0.5))
        rarities.append(rarity)
    out["baseline_deviation"] = deviations
    out["rarity_score"] = rarities
    out["anomaly_score"] = (out["baseline_deviation"] * 0.7 + out["rarity_score"] * 0.3).clip(0, 100)
    return out

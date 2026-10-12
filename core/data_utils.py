"""Dataframe helpers used across FUSION engines."""
from __future__ import annotations

from datetime import datetime, timezone
import pandas as pd


def ensure_timestamp(df: pd.DataFrame, column: str = "timestamp") -> pd.DataFrame:
    out = df.copy()
    if column not in out.columns:
        out[column] = pd.NaT
    out[column] = pd.to_datetime(out[column], errors="coerce", utc=True)
    return out


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def normalize_text(value: object) -> str:
    return str(value or "").strip().casefold()


def utc_datetime(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    ts = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(ts):
        return None
    return ts.to_pydatetime().astimezone(timezone.utc)

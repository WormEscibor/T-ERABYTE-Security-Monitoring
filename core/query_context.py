"""Shared, auditable query context for T-ERABYTE CSIRT SOC PRO.

The QueryContext is intentionally independent of Streamlit so every module can
consume the exact same time window, timezone, search semantics, and detection
threshold. It also provides deterministic filtering for DEMO mode so the UI
behaves the same way as the file-upload mode with respect to scope.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date, time, datetime, timezone, timedelta
import hashlib
import json
import re
from typing import Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pandas as pd

DEFAULT_FAILED_LOGIN_THRESHOLD = 5
DEFAULT_WORKING_DAYS = (0, 1, 2, 3, 4)


@dataclass(frozen=True)
class QueryContext:
    project_id: str
    timezone_name: str
    start_date: date
    end_date: date
    start_time: time
    end_time: time
    search_text: str = ""
    exact_phrase: bool = False
    failed_login_threshold: int = DEFAULT_FAILED_LOGIN_THRESHOLD
    working_days: tuple[int, ...] = DEFAULT_WORKING_DAYS

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.project_id.strip():
            errors.append("GCP Project-ID wajib diisi.")
        try:
            ZoneInfo(self.timezone_name)
        except ZoneInfoNotFoundError:
            errors.append(f"Zona waktu tidak valid: {self.timezone_name}.")
        if self.end_date < self.start_date:
            errors.append("Tanggal Selesai tidak boleh lebih awal daripada Tanggal Mulai.")
        if self.start_date == self.end_date and self.end_time < self.start_time:
            errors.append("Jam Selesai tidak boleh lebih awal daripada Jam Mulai pada tanggal yang sama.")
        if not 1 <= int(self.failed_login_threshold) <= 100000:
            errors.append("Failed Login Threshold harus berada pada rentang 1–100000.")
        if not self.working_days or any(day not in range(7) for day in self.working_days):
            errors.append("Working days tidak valid.")
        return errors

    @property
    def timezone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone_name)

    @property
    def start_local(self) -> datetime:
        return datetime.combine(self.start_date, self.start_time, tzinfo=self.timezone)

    @property
    def end_local(self) -> datetime:
        return datetime.combine(self.end_date, self.end_time, tzinfo=self.timezone)

    @property
    def start_utc(self) -> datetime:
        return self.start_local.astimezone(timezone.utc)

    @property
    def end_utc(self) -> datetime:
        return self.end_local.astimezone(timezone.utc)

    @property
    def window_label(self) -> str:
        return (
            f"{self.start_local:%d %b %Y %H:%M:%S} – "
            f"{self.end_local:%d %b %Y %H:%M:%S} {self.timezone_name}"
        )

    @property
    def query_hash(self) -> str:
        payload = {
            "project_id": self.project_id.strip(),
            "timezone_name": self.timezone_name,
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "search_text": " ".join(self.search_text.split()),
            "exact_phrase": bool(self.exact_phrase),
            "failed_login_threshold": int(self.failed_login_threshold),
            "working_days": list(self.working_days),
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return "QRY-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12].upper()

    def as_dict(self) -> dict:
        data = asdict(self)
        data["start_date"] = self.start_date.isoformat()
        data["end_date"] = self.end_date.isoformat()
        data["start_time"] = self.start_time.isoformat()
        data["end_time"] = self.end_time.isoformat()
        data["working_days"] = list(self.working_days)
        data["query_hash"] = self.query_hash
        data["window_label"] = self.window_label
        return data


def _string_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if pd.api.types.is_object_dtype(df[c]) or pd.api.types.is_string_dtype(df[c])]


def manual_search_mask(df: pd.DataFrame, search_text: str, exact_phrase: bool = False) -> pd.Series:
    """Return a deterministic, case-insensitive search mask across text fields.

    Exact phrase means the normalized phrase must occur as a contiguous substring;
    non-exact search treats the input as a phrase made up of whitespace-separated
    tokens, all of which must be present in the same row.
    """
    if df is None or df.empty or not str(search_text or "").strip():
        return pd.Series(True, index=getattr(df, "index", []), dtype=bool)
    needle = " ".join(str(search_text).split()).casefold()
    cols = _string_columns(df)
    if not cols:
        return pd.Series(False, index=df.index, dtype=bool)
    haystack = df[cols].fillna("").astype(str).agg(" | ".join, axis=1).str.casefold()
    if exact_phrase:
        return haystack.str.contains(re.escape(needle), regex=True, na=False)
    tokens = [re.escape(token) for token in needle.split() if token]
    mask = pd.Series(True, index=df.index, dtype=bool)
    for token in tokens:
        mask &= haystack.str.contains(token, regex=True, na=False)
    return mask


def filter_dataframe(df: pd.DataFrame, ctx: QueryContext, *, apply_project: bool = True) -> pd.DataFrame:
    """Apply QueryContext time/project/manual-search semantics to one DataFrame."""
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return pd.DataFrame(columns=getattr(df, "columns", [])) if isinstance(df, pd.DataFrame) else pd.DataFrame()
    out = df.copy()
    if "timestamp" in out.columns:
        ts = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
        start = pd.Timestamp(ctx.start_utc)
        end = pd.Timestamp(ctx.end_utc)
        out = out.loc[ts.between(start, end, inclusive="both")].copy()
    if apply_project and ctx.project_id.strip():
        project_cols = [c for c in ("project_id", "projectId", "project", "projectID") if c in out.columns]
        if project_cols:
            project = ctx.project_id.strip().casefold()
            normalized = out[project_cols].fillna("").astype(str).apply(lambda col: col.str.strip().str.casefold())
            # Every populated project identifier must agree with the selected
            # security boundary. A conflicting project_id/project/projectId
            # field is rejected instead of allowing an OR-based bypass.
            populated = normalized.ne("")
            project_mask = populated.any(axis=1) & normalized.where(populated, project).eq(project).all(axis=1)
            out = out.loc[project_mask].copy()
    search_mask = manual_search_mask(out, ctx.search_text, ctx.exact_phrase)
    out = out.loc[search_mask].copy()
    if "timestamp" in out.columns:
        out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
        out = out.sort_values("timestamp", ascending=False, kind="stable")
    return out.reset_index(drop=True)


def default_context(today: date | None = None, project_id: str = "dto-asik-prod") -> QueryContext:
    d = today or datetime.now().date()
    return QueryContext(
        project_id=project_id,
        timezone_name="Asia/Jakarta",
        start_date=d - timedelta(days=6),
        end_date=d,
        start_time=time(0, 0),
        end_time=time(23, 59, 59),
    )

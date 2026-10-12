# -*- coding: utf-8 -*-
"""Deteksi fokus Dashboard Monitoring (5 aturan) — fungsi murni tanpa Streamlit.

Aturan:
  1. Akses di luar jam kerja  : hari kerja, di luar 08:00–17:00 WIB.
  2. Akses di luar hari kerja : Sabtu & Minggu.
  3. Download besar           : total volume >= ambang MB dalam 1 jam,
                                ATAU >= ambang jumlah operasi unduh per jam.
  4. Critical command         : skor gabungan token risk_rules.yaml >= 60.
  5. Sering forbidden         : >= 5 kejadian DENIED/… per user.

Semua fungsi menerima DataFrame apa pun dan menormalkannya lewat
``ensure_canonical_event_frame`` sehingga tidak pernah raise karena kolom
yang hilang; input kosong selalu menghasilkan DataFrame kosong yang aman.
"""
from __future__ import annotations

from datetime import time
from pathlib import Path
import json
import re
import threading

import pandas as pd

from core.event_schema import ensure_canonical_event_frame
from core.log_scope import ALL_LOGS, HUMAN_ONLY, filter_log_scope, human_mask as _human_mask

DEFAULT_RULES = {
    "office_hours": {
        "start": "08:00",
        "end": "17:00",
        "timezone": "Asia/Jakarta",
        "working_days": [0, 1, 2, 3, 4],
    },
    "download": {
        "window_minutes": 60,
        "volume_threshold_mb": 1024,
        "ops_threshold": 100,
    },
    "critical_command": {"score_threshold": 60},
    "forbidden": {"threshold": 5},
}

DAY_LABELS = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"]

DENIED_OUTCOMES = {"DENIED", "FORBIDDEN", "UNAUTHORIZED", "PERMISSION_DENIED", "PERMISSION DENIED"}

_RULES_CACHE: dict | None = None
_RULES_LOCK = threading.RLock()


def load_monitor_rules() -> dict:
    """Baca config/monitor_rules.yaml; fallback ke DEFAULT_RULES bila gagal."""
    global _RULES_CACHE
    with _RULES_LOCK:
        if _RULES_CACHE is not None:
            return json.loads(json.dumps(_RULES_CACHE))
        rules = json.loads(json.dumps(DEFAULT_RULES))
        path = Path(__file__).resolve().parents[1] / "config" / "monitor_rules.yaml"
        try:
            import yaml
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for section, values in payload.items():
                if isinstance(values, dict) and section in rules:
                    rules[section].update(values)
        except Exception:
            pass
        _RULES_CACHE = json.loads(json.dumps(rules))
        return json.loads(json.dumps(rules))


def office_hours_info(rules: dict | None = None) -> dict:
    cfg = (rules or load_monitor_rules()).get("office_hours", {})
    days = [int(d) for d in cfg.get("working_days", [0, 1, 2, 3, 4])]
    days = [d for d in days if 0 <= d <= 6] or [0, 1, 2, 3, 4]
    return {
        "start": str(cfg.get("start", "08:00"))[:5],
        "end": str(cfg.get("end", "17:00"))[:5],
        "timezone": str(cfg.get("timezone", "Asia/Jakarta")),
        "working_days": days,
        "working_days_label": ", ".join(DAY_LABELS[d] for d in sorted(days)),
        "off_days_label": ", ".join(DAY_LABELS[d] for d in range(7) if d not in days),
    }


def _parse_clock(value: str) -> time:
    try:
        parts = str(value).split(":")
        return time(int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        return time(8, 0)


_DEFAULT_COMMAND_RULES = {
    "sudo": 30.0, "su": 30.0, "useradd": 35.0, "usermod": 30.0, "passwd": 25.0,
    "curl": 15.0, "wget": 15.0, "nc": 35.0, "ncat": 35.0, "bash -i": 45.0,
    "python -c": 35.0, "chmod": 15.0, "chown": 15.0, "systemctl": 20.0,
    "iptables": 30.0, "ufw": 30.0, "docker": 20.0, "kubectl": 20.0,
    "rm": 20.0, "scp": 15.0, "ssh": 10.0,
}
_COMMAND_RULES_CACHE: dict[str, float] | None = None
_COMMAND_RULES_LOCK = threading.RLock()


def _load_command_rules() -> dict[str, float]:
    """Token perintah berisiko dari config/risk_rules.yaml (cache + fallback)."""
    global _COMMAND_RULES_CACHE
    with _COMMAND_RULES_LOCK:
        if _COMMAND_RULES_CACHE is not None:
            return dict(_COMMAND_RULES_CACHE)
        rules: dict[str, float] = {}
        path = Path(__file__).resolve().parents[1] / "config" / "risk_rules.yaml"
        try:
            import yaml
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for item in payload.get("rules", []):
                token = str(item.get("token") or "").strip().casefold()
                try:
                    score = float(item.get("score", 0) or 0)
                except (TypeError, ValueError):
                    continue
                if token and score > 0:
                    rules[token] = score
        except Exception:
            rules = {}
        if not rules:
            rules = dict(_DEFAULT_COMMAND_RULES)
        _COMMAND_RULES_CACHE = dict(rules)
        return dict(rules)


def command_score(command: str) -> tuple[float, list[str]]:
    """Skor perintah dengan pencocokan word-boundary (menghindari 'su' ikut
    terhitung di dalam 'sudo'). Semantik sama dengan analytics/risk_engine.py."""
    cmd = str(command or "").casefold()
    if not cmd:
        return 0.0, []
    score = 0.0
    matched: list[str] = []
    for token, weight in _load_command_rules().items():
        token = str(token).casefold().strip()
        if not token:
            continue
        if any(ch.isspace() for ch in token):
            pattern = r"(?<![\w-])" + re.escape(token) + r"(?![\w-])"
        else:
            pattern = r"(?<![\w-])" + re.escape(token) + r"(?![\w-])"
        if re.search(pattern, cmd):
            score += weight
            matched.append(token)
    return min(100.0, score), sorted(set(matched))


def human_mask(events: pd.DataFrame, include_service_accounts: bool = False) -> pd.Series:
    """Mask identitas manusia. Parameter lama dipertahankan untuk kompatibilitas."""
    if include_service_accounts:
        return pd.Series(True, index=ensure_canonical_event_frame(events).index, dtype=bool)
    return _human_mask(events)


def _scoped_events(events: pd.DataFrame, scope: str = HUMAN_ONLY, include_service_accounts: bool = False) -> pd.DataFrame:
    """Terapkan cakupan analisis secara konsisten di seluruh deteksi."""
    normalized = ALL_LOGS if include_service_accounts else scope
    return filter_log_scope(events, normalized)


def add_local_time(events: pd.DataFrame) -> pd.DataFrame:
    """Tambahkan kolom waktu WIB (wib_time, wib_hour, wib_weekday, day_label)."""
    out = ensure_canonical_event_frame(events)
    if out.empty:
        for col in ("wib_time", "wib_hour", "wib_minute", "wib_weekday", "day_label"):
            out[col] = pd.Series(dtype="object")
        return out
    tz = office_hours_info().get("timezone", "Asia/Jakarta")
    try:
        local = out["timestamp"].dt.tz_convert(tz)
    except Exception:
        local = out["timestamp"]
    out["wib_time"] = local
    out["wib_hour"] = pd.to_numeric(local.dt.hour, errors="coerce").fillna(-1).astype(int)
    out["wib_minute"] = pd.to_numeric(local.dt.minute, errors="coerce").fillna(0).astype(int)
    out["wib_weekday"] = pd.to_numeric(local.dt.weekday, errors="coerce").fillna(-1).astype(int)
    out["day_label"] = out["wib_weekday"].map(lambda d: DAY_LABELS[d] if 0 <= d <= 6 else "?")
    return out


def _is_working_day(weekday_series: pd.Series, working_days) -> pd.Series:
    return weekday_series.isin(list(working_days))


def outside_office_hours(events: pd.DataFrame, rules: dict | None = None, include_service_accounts: bool = False, scope: str = HUMAN_ONLY) -> pd.DataFrame:
    """Event pada hari kerja di luar rentang jam kerja WIB."""
    cfg = office_hours_info(rules)
    include_sa = include_service_accounts or bool((rules or {}).get("include_service_accounts", False))
    df = add_local_time(_scoped_events(events, scope, include_sa))
    if df.empty:
        return _empty_view()
    # Cakupan sudah diterapkan pada _scoped_events().
    df = df.reset_index(drop=True)
    if df.empty:
        return _empty_view()
    start = _parse_clock(cfg["start"])
    end = _parse_clock(cfg["end"])
    working = _is_working_day(df["wib_weekday"], cfg["working_days"])
    minutes = df["wib_hour"] * 60 + df["wib_minute"]
    start_min = start.hour * 60 + start.minute
    end_min = end.hour * 60 + end.minute
    outside_time = (minutes < start_min) | (minutes > end_min)
    out = df.loc[working & outside_time].copy()
    out["alasan"] = pd.Series(
        [
            "Sebelum jam kerja" if m < start_min else "Setelah jam kerja"
            for m in (out["wib_hour"] * 60 + out["wib_minute"])
        ],
        index=out.index,
        dtype=object,
    )
    return _view_columns(out)


def outside_working_days(events: pd.DataFrame, rules: dict | None = None, include_service_accounts: bool = False, scope: str = HUMAN_ONLY) -> pd.DataFrame:
    """Event pada Sabtu/Minggu (di luar hari kerja)."""
    cfg = office_hours_info(rules)
    include_sa = include_service_accounts or bool((rules or {}).get("include_service_accounts", False))
    df = add_local_time(_scoped_events(events, scope, include_sa))
    if df.empty:
        return _empty_view()
    df = df.reset_index(drop=True)
    if df.empty:
        return _empty_view()
    working = _is_working_day(df["wib_weekday"], cfg["working_days"])
    out = df.loc[~working].copy()
    out["alasan"] = out["day_label"].map(lambda d: f"Aktivitas pada hari {d}")
    return _view_columns(out)


def _download_mask(df: pd.DataFrame) -> pd.Series:
    action = df["event_action"].fillna("").astype(str).str.upper()
    method = df["api_method"].fillna("").astype(str).str.casefold()
    volume = pd.to_numeric(df["data_volume"], errors="coerce").fillna(0.0)
    mask = action.isin({"DATA_ACCESS", "EXPORT", "DOWNLOAD", "STORAGE_GET", "GET", "READ"})
    mask |= method.str.contains("download|export|storage.objects.get|objects.get", na=False, regex=True)
    mask |= volume.gt(0)
    return mask


def download_windows(events: pd.DataFrame, rules: dict | None = None, include_service_accounts: bool = False, scope: str = HUMAN_ONLY) -> pd.DataFrame:
    """Agregat volume/operasi unduh per user per jendela 1 jam; flag bila lewat ambang."""
    cfg = (rules or load_monitor_rules()).get("download", {})
    include_sa = include_service_accounts or bool((rules or {}).get("include_service_accounts", False))
    window_minutes = int(cfg.get("window_minutes", 60) or 60)
    volume_threshold = float(cfg.get("volume_threshold_mb", 1024) or 0)
    ops_threshold = int(cfg.get("ops_threshold", 100) or 0)
    cols = ["principal_id", "window_start_wib", "volume_mb", "ops", "flagged", "risiko", "event_ids", "first_wib", "last_wib"]
    df = add_local_time(_scoped_events(events, scope, include_sa))
    if df.empty:
        return pd.DataFrame(columns=cols)
    df = df.reset_index(drop=True)
    if df.empty:
        return pd.DataFrame(columns=cols)
    sub = df.loc[_download_mask(df)].copy()
    if sub.empty:
        return pd.DataFrame(columns=cols)
    sub["window_start"] = sub["timestamp"].dt.floor(f"{window_minutes}min")
    sub["volume_mb"] = pd.to_numeric(sub["data_volume"], errors="coerce").fillna(0.0)
    rows = []
    for (user, window), frame in sub.groupby(["principal_id", "window_start"], dropna=False):
        volume = float(frame["volume_mb"].sum())
        ops = int(len(frame))
        flagged = volume >= volume_threshold or ops >= ops_threshold
        if not flagged:
            continue
        if volume >= 2 * volume_threshold:
            risk = "KRITIS"
        else:
            risk = "TINGGI"
        rows.append({
            "principal_id": str(user),
            "window_start_wib": pd.Timestamp(window).tz_convert(office_hours_info().get("timezone", "Asia/Jakarta")),
            "volume_mb": round(volume, 2),
            "ops": ops,
            "flagged": True,
            "risiko": risk,
            "event_ids": json.dumps([str(e) for e in frame["event_id"].tolist()], ensure_ascii=False),
            "first_wib": frame["wib_time"].min(),
            "last_wib": frame["wib_time"].max(),
        })
    return pd.DataFrame(rows, columns=cols).sort_values("volume_mb", ascending=False, kind="stable").reset_index(drop=True)


def _score_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def critical_command_rows(events: pd.DataFrame, rules: dict | None = None, include_service_accounts: bool = False, scope: str = HUMAN_ONLY) -> pd.DataFrame:
    """Baris event dengan perintah yang skornya >= ambang kritikal."""
    cfg = (rules or load_monitor_rules()).get("critical_command", {})
    include_sa = include_service_accounts or bool((rules or {}).get("include_service_accounts", False))
    threshold = float(cfg.get("score_threshold", 60) or 0)
    df = add_local_time(_scoped_events(events, scope, include_sa))
    if df.empty:
        return _empty_view(extra=["score", "level", "alasan"])
    df = df.reset_index(drop=True)
    if df.empty:
        return _empty_view(extra=["score", "level", "alasan"])
    cmds = df.loc[df["command"].fillna("").astype(str).str.strip().ne("")].copy()
    if cmds.empty:
        return _empty_view(extra=["score", "level", "alasan"])
    scored = {}
    for command in cmds["command"].fillna("").astype(str):
        key = command.casefold()
        if key not in scored:
            score, tokens = command_score(command)
            scored[key] = (score, sorted(set(tokens)))
    cmds["score"] = cmds["command"].map(lambda c: scored.get(str(c).casefold(), (0.0, []))[0])
    cmds["matched"] = cmds["command"].map(lambda c: ", ".join(scored.get(str(c).casefold(), (0.0, []))[1]))
    cmds["level"] = cmds["score"].map(_score_level)
    cmds["alasan"] = cmds.apply(
        lambda r: f"Skor perintah {int(r['score'])} ({r['level']})" + (f": {r['matched']}" if r["matched"] else ""),
        axis=1,
    )
    out = cmds.loc[cmds["score"] >= threshold].sort_values("score", ascending=False, kind="stable")
    return _view_columns(out, extra=["score", "level", "alasan"])


def forbidden_users(events: pd.DataFrame, rules: dict | None = None, include_service_accounts: bool = False, scope: str = HUMAN_ONLY) -> pd.DataFrame:
    """User dengan kejadian forbidden/unauthorized >= ambang dalam periode query."""
    cfg = (rules or load_monitor_rules()).get("forbidden", {})
    include_sa = include_service_accounts or bool((rules or {}).get("include_service_accounts", False))
    threshold = int(cfg.get("threshold", 5) or 0)
    cols = ["principal_id", "kejadian", "flagged", "risiko", "event_ids", "first_wib", "last_wib"]
    df = add_local_time(_scoped_events(events, scope, include_sa))
    if df.empty:
        return pd.DataFrame(columns=cols)
    df = df.reset_index(drop=True)
    if df.empty:
        return pd.DataFrame(columns=cols)
    outcome = df["event_outcome"].fillna("").astype(str).str.upper()
    denied = outcome.isin(DENIED_OUTCOMES)
    denied |= outcome.str.contains("DENIED", na=False, regex=False)
    denied |= outcome.str.contains("FORBIDDEN", na=False, regex=False)
    denied |= outcome.str.contains("UNAUTHOR", na=False, regex=False)
    # permission_granted=False juga dihitung, KECUALI event login gagal
    # (kegagalan autentikasi adalah ranah deteksi brute force, bukan forbidden).
    is_login = df["event_action"].fillna("").astype(str).str.upper().eq("LOGIN")
    granted = df["permission_granted"]
    denied |= granted.isin([False]) & ~is_login
    sub = df.loc[denied].copy()
    if sub.empty:
        return pd.DataFrame(columns=cols)
    rows = []
    for user, frame in sub.groupby("principal_id", dropna=False):
        count = int(len(frame))
        if count < threshold:
            continue
        risk = "KRITIS" if count >= 2 * threshold else "TINGGI"
        rows.append({
            "principal_id": str(user),
            "kejadian": count,
            "flagged": True,
            "risiko": risk,
            "event_ids": json.dumps([str(e) for e in frame["event_id"].tolist()], ensure_ascii=False),
            "first_wib": frame["wib_time"].min(),
            "last_wib": frame["wib_time"].max(),
        })
    return pd.DataFrame(rows, columns=cols).sort_values("kejadian", ascending=False, kind="stable").reset_index(drop=True)


def _empty_view(extra: list[str] | None = None) -> pd.DataFrame:
    cols = ["event_id", "wib_time", "principal_id", "day_label", "event_action", "event_outcome", "command", "resource_name", "source_ip", "api_method", "detail", "alasan"] + (extra or [])
    return pd.DataFrame(columns=cols)


def _view_columns(df: pd.DataFrame, extra: list[str] | None = None) -> pd.DataFrame:
    cols = ["event_id", "wib_time", "principal_id", "day_label", "event_action", "event_outcome", "command", "resource_name", "source_ip", "api_method", "detail", "alasan"] + (extra or [])
    present = [c for c in cols if c in df.columns]
    return df[present].reset_index(drop=True)


def build_findings(events: pd.DataFrame, rules: dict | None = None, include_service_accounts: bool = False, scope: str = HUMAN_ONLY) -> pd.DataFrame:
    """Tabel gabungan 'Prioritas pemeriksaan' untuk halaman Ringkasan."""
    cfg = rules or load_monitor_rules()
    include_sa = include_service_accounts or bool((rules or {}).get("include_service_accounts", False))
    cols = ["kategori", "user", "indikasi", "risiko", "jumlah", "waktu", "event_ids"]
    rows = []

    def risk_order(risk: str) -> int:
        return {"KRITIS": 0, "TINGGI": 1, "SEDANG": 2}.get(str(risk).upper(), 3)

    hours = outside_office_hours(events, cfg, include_service_accounts=include_sa, scope=scope)
    if not hours.empty:
        for user, frame in hours.groupby("principal_id", dropna=False):
            rows.append({
                "kategori": "Luar Jam Kerja",
                "user": str(user),
                "indikasi": "Akses di luar jam kerja (08:00–17:00 WIB)",
                "risiko": "SEDANG",
                "jumlah": int(len(frame)),
                "waktu": frame["wib_time"].max(),
                "event_ids": json.dumps([str(e) for e in frame["event_id"].tolist()], ensure_ascii=False),
            })
    days = outside_working_days(events, cfg, include_service_accounts=include_sa, scope=scope)
    if not days.empty:
        for user, frame in days.groupby("principal_id", dropna=False):
            rows.append({
                "kategori": "Luar Hari Kerja",
                "user": str(user),
                "indikasi": "Akses pada hari Sabtu/Minggu",
                "risiko": "SEDANG",
                "jumlah": int(len(frame)),
                "waktu": frame["wib_time"].max(),
                "event_ids": json.dumps([str(e) for e in frame["event_id"].tolist()], ensure_ascii=False),
            })
    downloads = download_windows(events, cfg, include_service_accounts=include_sa, scope=scope)
    if not downloads.empty:
        for item in downloads.to_dict("records"):
            rows.append({
                "kategori": "Download Besar",
                "user": str(item.get("principal_id")),
                "indikasi": f"Volume {item.get('volume_mb'):,.0f} MB dalam 1 jam ({item.get('ops')} operasi)",
                "risiko": str(item.get("risiko")),
                "jumlah": int(item.get("ops") or 0),
                "waktu": item.get("first_wib"),
                "event_ids": str(item.get("event_ids") or "[]"),
            })
    commands = critical_command_rows(events, cfg, include_service_accounts=include_sa, scope=scope)
    if not commands.empty:
        for user, frame in commands.groupby("principal_id", dropna=False):
            top = frame.sort_values("score", ascending=False, kind="stable").iloc[0]
            rows.append({
                "kategori": "Critical Command",
                "user": str(user),
                "indikasi": f"Perintah kritikal: {str(top.get('command'))[:80]} (skor {int(top.get('score') or 0)})",
                "risiko": "KRITIS" if float(top.get("score") or 0) >= 80 else "TINGGI",
                "jumlah": int(len(frame)),
                "waktu": frame["wib_time"].max(),
                "event_ids": json.dumps([str(e) for e in frame["event_id"].tolist()], ensure_ascii=False),
            })
    forbidden = forbidden_users(events, cfg, include_service_accounts=include_sa, scope=scope)
    if not forbidden.empty:
        for item in forbidden.to_dict("records"):
            rows.append({
                "kategori": "Forbidden/Unauthorized",
                "user": str(item.get("principal_id")),
                "indikasi": f"{item.get('kejadian')} kejadian akses ditolak",
                "risiko": str(item.get("risiko")),
                "jumlah": int(item.get("kejadian") or 0),
                "waktu": item.get("last_wib"),
                "event_ids": str(item.get("event_ids") or "[]"),
            })
    if not rows:
        return pd.DataFrame(columns=cols)
    out = pd.DataFrame(rows, columns=cols)
    out["_order"] = out["risiko"].map(risk_order)
    out = out.sort_values(["_order", "jumlah"], ascending=[True, False], kind="stable").drop(columns=["_order"])
    return out.reset_index(drop=True)


def risk_rules_table() -> pd.DataFrame:
    """Tabel token perintah berisiko dari config/risk_rules.yaml (untuk UI)."""
    rows = []
    try:
        import yaml
        path = Path(__file__).resolve().parents[1] / "config" / "risk_rules.yaml"
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for item in payload.get("rules", []):
            rows.append({
                "token": str(item.get("token") or ""),
                "skor": int(item.get("score", 0) or 0),
                "keterangan": str(item.get("reason") or ""),
            })
    except Exception:
        rows = []
    if not rows:
        rows = [
            {"token": "sudo", "skor": 30, "keterangan": "Privilege Escalation"},
            {"token": "useradd", "skor": 35, "keterangan": "Account Creation"},
            {"token": "nc", "skor": 35, "keterangan": "Network Utility"},
            {"token": "bash -i", "skor": 45, "keterangan": "Interactive Shell"},
        ]
    return pd.DataFrame(rows).sort_values("skor", ascending=False, kind="stable").reset_index(drop=True)


def events_by_ids(events: pd.DataFrame, event_ids: list[str]) -> pd.DataFrame:
    """Ambil event asli berdasarkan daftar event_id (untuk panel detail)."""
    df = add_local_time(events)
    if df.empty or not event_ids:
        return df.iloc[0:0]
    wanted = {str(e) for e in event_ids}
    return df.loc[df["event_id"].astype(str).isin(wanted)].reset_index(drop=True)

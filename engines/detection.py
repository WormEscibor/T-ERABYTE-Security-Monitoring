"""Deterministic detections and sequence correlation."""
from __future__ import annotations
from datetime import time
from pathlib import Path
import threading

import pandas as pd

from core.event_schema import ensure_canonical_event_frame

DEFAULT_DANGEROUS = {
    "sudo": 30,
    "su": 30,
    "useradd": 35,
    "usermod": 30,
    "passwd": 25,
    "curl": 15,
    "wget": 15,
    "nc": 35,
    "ncat": 35,
    "bash -i": 45,
    "python -c": 35,
    "chmod": 15,
    "chown": 15,
    "systemctl": 20,
    "iptables": 30,
    "ufw": 30,
    "docker": 20,
    "kubectl": 20,
    "rm": 20,
    "scp": 15,
    "ssh": 10,
}

_RULE_CACHE: dict[str, tuple[float, str]] | None = None
_RULE_LOCK = threading.RLock()


def _load_risk_rules() -> dict[str, tuple[float, str]]:
    """Load command rules from the single configured risk_rules.yaml source."""
    global _RULE_CACHE
    with _RULE_LOCK:
        if _RULE_CACHE is not None:
            return dict(_RULE_CACHE)
        rules = {}
        path = Path(__file__).resolve().parents[1] / "config" / "risk_rules.yaml"
        try:
            import yaml
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for item in payload.get("rules", []):
                token = str(item.get("token") or "").strip().casefold()
                if not token:
                    continue
                try:
                    score = float(item.get("score", 0) or 0)
                except (TypeError, ValueError):
                    continue
                reason = str(item.get("reason") or token).strip()
                rules[token] = (max(0.0, score), reason)
        except Exception:
            rules = {}
        if not rules:
            rules = {token: (float(score), token) for token, score in DEFAULT_DANGEROUS.items()}
        _RULE_CACHE = dict(rules)
        return dict(rules)


def is_outside_office_hours(ts, office_start: time = time(8, 0), office_end: time = time(17, 0), working_days=(0,1,2,3,4), timezone_name: str = "Asia/Jakarta") -> bool:
    t = pd.Timestamp(ts)
    if pd.isna(t):
        return False
    if t.tzinfo is None:
        t = t.tz_localize("UTC")
    local = t.tz_convert(timezone_name)
    if local.weekday() not in working_days:
        return True
    return not (office_start <= local.time() <= office_end)


def dangerous_command_score(command: str) -> tuple[float, list[str]]:
    """Score a command using config/risk_rules.yaml, with a safe built-in fallback."""
    cmd = str(command or "").casefold()
    if not cmd:
        return 0.0, []
    score = 0.0
    reasons = []
    for token, (weight, reason) in _load_risk_rules().items():
        if token in cmd:
            score += weight
            reasons.append(reason or token)
    return min(100.0, score), reasons


def detect_after_hours_dangerous(events: pd.DataFrame, window_minutes: int = 30, office_start: time = time(8, 0), office_end: time = time(17, 0), working_days=(0,1,2,3,4), timezone_name: str = "Asia/Jakarta") -> pd.DataFrame:
    """Detect after-hours login followed by a dangerous command.

    Correlation is identity-centric and uses a bounded event-time window.
    """
    events = ensure_canonical_event_frame(events)
    if events.empty:
        return pd.DataFrame()
    out = events.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out["outside_office_hours"] = out["timestamp"].map(lambda value: is_outside_office_hours(value, office_start, office_end, working_days, timezone_name))
    out["dangerous_command_score"] = out["command"].fillna("").map(lambda x: dangerous_command_score(x)[0]) if "command" in out.columns else 0.0
    action_series = out["event_action"] if "event_action" in out.columns else pd.Series("", index=out.index)
    command_series = out["command"] if "command" in out.columns else pd.Series("", index=out.index)
    logins = out[action_series.fillna("").astype(str).str.upper().isin({"LOGIN", "AUTH_SUCCESS", "AUTHENTICATION"}) & out["outside_office_hours"]].copy()
    commands = out[command_series.fillna("").astype(str).str.len().gt(0) & (out["dangerous_command_score"] >= 30)].copy()
    if logins.empty or commands.empty:
        return pd.DataFrame()
    alerts = []
    for _, login in logins.sort_values("timestamp").iterrows():
        identity = str(login.get("principal_id") or "")
        start = pd.Timestamp(login["timestamp"])
        candidates = commands[(commands["principal_id"].astype(str) == identity) & (commands["timestamp"] >= start) & (commands["timestamp"] <= start + pd.Timedelta(window_minutes, unit="min"))]
        for _, cmd in candidates.iterrows():
            score = float(cmd.get("dangerous_command_score") or 0)
            alerts.append({
                "principal_id": identity,
                "timestamp": start,
                "login_timestamp": start,
                "command_timestamp": cmd["timestamp"],
                "command": cmd.get("command", ""),
                "dangerous_command_score": score,
                "detection": "AFTER_HOURS_LOGIN_PLUS_DANGEROUS_COMMAND",
                "severity": "CRITICAL" if score >= 70 else "HIGH",
                "reason": "Login di luar jam kerja diikuti perintah berisiko dalam jendela korelasi.",
            })
    return pd.DataFrame(alerts).drop_duplicates(subset=["principal_id", "login_timestamp", "command_timestamp", "command"])

def sequence_alerts(events: pd.DataFrame, window_minutes: int = 30) -> pd.DataFrame:
    events = ensure_canonical_event_frame(events)
    if events.empty:
        return pd.DataFrame()
    out = events.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out = out.dropna(subset=["timestamp"]).sort_values(["principal_id", "timestamp"], kind="stable")
    alerts = []
    window_delta = pd.Timedelta(window_minutes, unit="min")
    for identity, frame in out.groupby("principal_id", dropna=False):
        actions = frame["event_action"].fillna("").astype(str).str.upper()
        if not actions.isin({"LOGIN", "AUTH_SUCCESS"}).any():
            continue
        cmds = frame["command"].fillna("").astype(str).str.casefold()
        if not (cmds.str.contains("sudo", regex=False) | cmds.str.contains("kubectl exec", regex=False)).any():
            continue

        rows = frame.to_dict("records")
        for idx, row in enumerate(rows):
            act = str(row.get("event_action") or "").upper()
            if act not in {"LOGIN", "AUTH_SUCCESS"}:
                continue
            start = row["timestamp"]
            window_count = 0
            found_cmd = False
            for r in rows[idx:]:
                t = r["timestamp"]
                if t > start + window_delta:
                    break
                window_count += 1
                c = str(r.get("command") or "").casefold()
                if "sudo" in c or "kubectl exec" in c:
                    found_cmd = True
                    break
            if found_cmd:
                alerts.append({
                    "principal_id": identity,
                    "timestamp": start,
                    "detection": "LOGIN_PLUS_PRIVILEGED_COMMAND",
                    "severity": "CRITICAL",
                    "event_count": window_count,
                    "reason": "Autentikasi diikuti aktivitas perintah berisiko dalam jendela korelasi.",
                })
                break
    return pd.DataFrame(alerts)

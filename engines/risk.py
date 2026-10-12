"""Adaptive, explainable risk scoring."""
from __future__ import annotations
from .baseline import apply_baseline
from core.data_utils import clamp

ASSET_WEIGHT = {"LOW": 2, "MEDIUM": 8, "HIGH": 16, "CRITICAL": 25}
CLASS_WEIGHT = {"UNKNOWN": 0, "PUBLIC": 0, "INTERNAL": 5, "CONFIDENTIAL": 10, "RESTRICTED": 15, "HIGHLY RESTRICTED": 22}


def score_event(row: dict, dangerous_command_score: float = 0.0) -> tuple[float, float, list[str]]:
    score = float(dangerous_command_score)
    reasons = []
    anomaly = float(row.get("anomaly_score") or 0)
    baseline = float(row.get("baseline_deviation") or 0)
    rarity = float(row.get("rarity_score") or 0)
    if anomaly >= 70:
        score += 18; reasons.append("Penyimpangan perilaku tinggi")
    elif anomaly >= 40:
        score += 8; reasons.append("Penyimpangan perilaku sedang")
    if baseline >= 50:
        score += 10; reasons.append("Menyimpang dari pola dasar")
    if rarity >= 50:
        score += 8; reasons.append("Aktivitas jarang ditemukan")
    criticality = str(row.get("asset_criticality") or "MEDIUM").upper()
    score += ASSET_WEIGHT.get(criticality, 8)
    if ASSET_WEIGHT.get(criticality, 8) >= 16:
        reasons.append("Aset memiliki tingkat kritikalitas tinggi")
    classification = str(row.get("data_classification") or "UNKNOWN").upper()
    score += CLASS_WEIGHT.get(classification, 0)
    if CLASS_WEIGHT.get(classification, 0) >= 15:
        reasons.append("Akses terhadap data sensitif")
    if bool(row.get("threat_intel_match")):
        ti_conf = float(row.get("threat_intel_confidence") or 0.0)
        score += 15 + min(10, ti_conf * 10)
        reasons.append("Berkorelasi dengan indikator ancaman")
    if str(row.get("event_outcome") or "").upper() in {"DENIED", "FAILURE", "FAILED"}:
        score += 5
    score = clamp(score)
    confidence = clamp(45 + anomaly * 0.35 + rarity * 0.15 + (25 if row.get("threat_intel_match") else 0))
    return score, confidence, reasons


def risk_level(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 30: return "MEDIUM"
    if score > 0: return "LOW"
    return "INFO"


def apply_adaptive_risk(events, baseline=None, command_scores=None):
    out = events.copy()
    if out.empty:
        return out
    if baseline is not None:
        out = apply_baseline(out, baseline)
    command_scores = command_scores or {}
    scores, levels, confidences, reason_list = [], [], [], []
    for _, row in out.iterrows():
        command = str(row.get("command") or "")
        base_cmd = float(command_scores.get(command.casefold(), 0.0))
        s, c, reasons = score_event(row.to_dict(), dangerous_command_score=base_cmd)
        scores.append(s); levels.append(risk_level(s)); confidences.append(c); reason_list.append("; ".join(sorted(set(reasons))))
    out["risk_score"] = scores
    out["risk_level"] = levels
    out["confidence"] = confidences
    out["risk_reasons"] = reason_list
    out["trust_score"] = (100 - out["risk_score"]).clip(0, 100)
    return out

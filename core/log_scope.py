# -*- coding: utf-8 -*-
"""Cakupan analisis log yang konsisten di seluruh aplikasi.

Modul ini menjadi satu-satunya sumber aturan untuk menentukan apakah sebuah
entri log diperlakukan sebagai aktivitas manusia atau sebagai log umum. Pilihan
cakupan pada antarmuka hanya mengubah data yang dianalisis; data sumber tidak
diubah dan tidak dihapus.
"""
from __future__ import annotations

from typing import Final

import pandas as pd

from core.event_schema import ensure_canonical_event_frame

HUMAN_ONLY: Final[str] = "HUMAN_ONLY"
ALL_LOGS: Final[str] = "ALL_LOGS"

_SCOPE_LABELS = {
    HUMAN_ONLY: "Human Only",
    ALL_LOGS: "Semua Log",
}

# Identitas yang secara eksplisit bukan pengguna manusia.
_SYSTEM_IDENTIFIERS = {
    "",
    "unknown",
    "anonymous",
    "system",
    "root",
    "n/a",
    "na",
    "null",
    "none",
    "-",
    "system@google.com",
    "noreply@google.com",
    "cloudservices@google.com",
}

_SERVICE_MARKERS = (
    "gserviceaccount.com",
    "serviceaccount",
    "svc-",
    "sa-",
)

_NON_HUMAN_TYPES = {
    "SERVICE ACCOUNT",
    "SERVICE_ACCOUNT",
    "SERVICE",
    "SYSTEM",
    "AUTOMATION",
    "BOT",
    "WORKLOAD",
    "APPLICATION",
    "MACHINE",
    "UNKNOWN",
}

_HUMAN_TYPES = {
    "HUMAN",
    "USER",
    "PERSON",
    "INDIVIDUAL",
}


def normalize_scope(scope: str | None) -> str:
    """Normalisasi nilai cakupan; nilai yang tidak dikenal kembali ke HUMAN_ONLY."""
    value = str(scope or "").strip().upper()
    aliases = {
        "HUMAN": HUMAN_ONLY,
        "HUMAN ONLY": HUMAN_ONLY,
        "HUMAN_ONLY": HUMAN_ONLY,
        "USER ONLY": HUMAN_ONLY,
        "ALL": ALL_LOGS,
        "ALL LOGS": ALL_LOGS,
        "SEMUA": ALL_LOGS,
        "SEMUA LOG": ALL_LOGS,
        "ALL_LOGS": ALL_LOGS,
    }
    return aliases.get(value, HUMAN_ONLY)


def scope_label(scope: str | None) -> str:
    return _SCOPE_LABELS[normalize_scope(scope)]


def principal_is_human(principal_id: object, principal_type: object = "") -> bool:
    """Tentukan identitas manusia dengan memprioritaskan tipe eksplisit yang valid.

    Identitas sistem yang jelas tetap diperlakukan sebagai non-manusia meskipun
    data sumber memberi nilai ``principal_type=HUMAN`` yang keliru.
    """
    pid = str(principal_id or "").strip().casefold()
    ptype = str(principal_type or "").strip().upper().replace("-", " ")

    if pid in _SYSTEM_IDENTIFIERS:
        return False
    if any(pid.endswith(marker) for marker in _SERVICE_MARKERS):
        return False
    if pid.startswith("uid:"):
        # AUID auditd yang sudah terikat ke sesi login dipertahankan sebagai
        # identitas pengguna. AUID unset ditangani sebagai non-manusia.
        numeric = pid[4:].strip()
        return numeric.isdigit() and numeric not in {"0", "4294967295"}
    if ptype in _NON_HUMAN_TYPES:
        return False
    if ptype in _HUMAN_TYPES:
        return True
    if "service" in ptype or "system" in ptype or "machine" in ptype or "bot" in ptype or "automation" in ptype:
        return False
    # Email/domain yang bukan akun layanan diperlakukan sebagai kandidat manusia.
    if "@" in pid:
        return True
    # Tidak ada identitas yang meyakinkan untuk dianggap sebagai manusia.
    return False


def human_mask(events: pd.DataFrame) -> pd.Series:
    """Kembalikan mask identitas manusia tanpa mengubah data sumber."""
    df = ensure_canonical_event_frame(events)
    if df.empty:
        return pd.Series(dtype=bool, index=df.index)
    return pd.Series(
        [principal_is_human(pid, ptype) for pid, ptype in zip(df["principal_id"], df["principal_type"])],
        index=df.index,
        dtype=bool,
    )


def filter_log_scope(events: pd.DataFrame, scope: str | None) -> pd.DataFrame:
    """Terapkan cakupan analisis tanpa menghapus data dari sumber aslinya."""
    df = ensure_canonical_event_frame(events)
    normalized = normalize_scope(scope)
    if df.empty or normalized == ALL_LOGS:
        return df.copy()
    return df.loc[human_mask(df)].reset_index(drop=True)


def scope_counts(events: pd.DataFrame) -> dict[str, int]:
    """Ringkasan jumlah event manusia dan non-manusia."""
    df = ensure_canonical_event_frame(events)
    if df.empty:
        return {"total": 0, "human": 0, "non_human": 0}
    human = human_mask(df)
    n_human = int(human.sum())
    return {"total": int(len(df)), "human": n_human, "non_human": int(len(df) - n_human)}

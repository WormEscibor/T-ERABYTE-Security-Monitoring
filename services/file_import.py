# -*- coding: utf-8 -*-
"""Impor file log hasil unduhan manual dari GCP Logs Explorer.

Format yang didukung (unduh lewat Logs Explorer > Download > JSON):
- JSON array entry log: ``[{ "insertId": ..., "logName": ..., "protoPayload": ... }, ...]``
- JSON Lines / NDJSON: satu objek entry per baris.
- Objek JSON tunggal (atau pembungkus ``{"entries": [...]}``).

Entry dinormalisasi ke dict (timestamp diubah ke datetime aware UTC bila string)
dan di-dedupe memakai kunci ``(logName | insertId | timestamp)`` — sama dengan
kunci identitas provider yang dipakai pipeline.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

import pandas as pd

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = ["json", "jsonl", "ndjson", "txt", "log"]


def _normalize_entry(item: dict) -> dict:
    """Salin entry; timestamp string diubah menjadi datetime aware UTC."""
    entry = dict(item)
    ts = entry.get("timestamp")
    if isinstance(ts, str):
        try:
            parsed = pd.Timestamp(ts)
            if parsed is not pd.NaT:
                if parsed.tzinfo is None:
                    parsed = parsed.tz_localize("UTC")
                # GCP memakai presisi nanodetik; bulatkan ke milidetik agar
                # konversi ke datetime tidak menimbulkan warning.
                entry["timestamp"] = parsed.floor("ms").to_pydatetime()
        except Exception:
            pass
    return entry


def _entry_key(entry: dict) -> str:
    log_name = str(entry.get("logName") or entry.get("log_name") or "")
    insert_id = str(entry.get("insertId") or entry.get("insert_id") or "")
    ts = entry.get("timestamp")
    ts_text = ts.isoformat() if isinstance(ts, datetime) else str(ts or "")
    return f"{log_name}|{insert_id}|{ts_text}"


_LOG_ENTRY_MARKERS = (
    "logName", "log_name", "insertId", "insert_id", "timestamp",
    "protoPayload", "proto_payload", "jsonPayload", "json_payload",
    "textPayload", "text_payload", "resource", "severity",
)


def _looks_like_entry(item: dict) -> bool:
    return any(key in item for key in _LOG_ENTRY_MARKERS)


def parse_upload(name: str, content: bytes) -> list[dict]:
    """Parse satu file unggahan menjadi daftar entry dict. Raise ValueError bila kosong/gagal."""
    text = content.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise ValueError("file kosong")

    items: list[dict] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and _looks_like_entry(item):
                items.append(item)
    elif isinstance(data, dict):
        inner = data.get("entries")
        if isinstance(inner, list):
            for item in inner:
                if isinstance(item, dict) and _looks_like_entry(item):
                    items.append(item)
        elif _looks_like_entry(data):
            items.append(data)
    else:
        # JSON Lines / NDJSON: satu objek per baris.
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and _looks_like_entry(item):
                items.append(item)

    if not items:
        raise ValueError(
            "tidak ada entry log valid — unduh sebagai JSON dari GCP Logs Explorer "
            "(tombol Download > JSON)"
        )
    return [_normalize_entry(item) for item in items]


def parse_uploads(files) -> tuple[list[dict], dict]:
    """Gabungkan banyak file, dedupe antar file. Return (entries, meta).

    ``files``: iterable berisi tuple ``(nama_file, bytes)``.
    """
    merged: dict[str, dict] = {}
    order: list[str] = []
    meta = {"files": [], "total_raw": 0, "errors": []}
    for name, content in files:
        try:
            items = parse_upload(name, content)
        except Exception as exc:
            meta["errors"].append(f"{name}: {exc}")
            continue
        meta["files"].append({"name": name, "entries": len(items)})
        meta["total_raw"] += len(items)
        for entry in items:
            key = _entry_key(entry)
            if key not in merged:
                merged[key] = entry
                order.append(key)
    entries = [merged[key] for key in order]
    if not entries and meta["errors"]:
        raise ValueError("; ".join(meta["errors"]))
    return entries, meta


def detect_project(entries) -> str:
    """Project ID mayoritas dari entry (untuk mengisi Project-ID otomatis)."""
    from collectors.cloud_scope import extract_project_id
    counts: dict[str, int] = {}
    for entry in entries[:5000]:
        project = str(extract_project_id(entry) or "").strip()
        if project:
            counts[project] = counts.get(project, 0) + 1
    return max(counts, key=counts.get) if counts else ""

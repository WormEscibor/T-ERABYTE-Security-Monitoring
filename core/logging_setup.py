# -*- coding: utf-8 -*-
"""Konfigurasi logging agar jejak proses tampil di terminal.

Streamlit menjalankan ``app.py`` di proses yang sama dengan terminal peluncur
(``run_dashboard.*``), sehingga log yang ditulis ke root logger muncul di
terminal tempat dashboard dijalankan. Ini memudahkan diagnosis saat UI tampak
"membeku" — pengguna bisa melihat apakah proses masih berjalan atau gagal.
"""
from __future__ import annotations

import logging
import os
import sys

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_CONFIGURED = False


def configure_logging(level: int | None = None) -> None:
    """Pasang satu StreamHandler (stdout) pada root logger bila belum ada."""
    global _CONFIGURED
    if level is None:
        level = logging.DEBUG if str(os.getenv("MONITOR_LOG_LEVEL", "")).upper() == "DEBUG" else logging.INFO
    root = logging.getLogger()
    if not _CONFIGURED and not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_FORMAT, datefmt="%H:%M:%S"))
        root.addHandler(handler)
        _CONFIGURED = True
    root.setLevel(level)

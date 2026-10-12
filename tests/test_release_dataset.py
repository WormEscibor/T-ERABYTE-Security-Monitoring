# -*- coding: utf-8 -*-
from pathlib import Path

from core.log_scope import ALL_LOGS, HUMAN_ONLY, scope_counts
from engines import focused_detections as fd
from services.file_import import parse_uploads
from services.pipeline import run_files


FIXTURE = Path(__file__).resolve().parents[1] / "logs-20261007-161759"


def test_release_dataset_end_to_end():
    entries, meta = parse_uploads([(FIXTURE.name, FIXTURE.read_bytes())])
    assert meta["errors"] == []
    assert meta["total_raw"] == 10_000
    assert len(entries) == 10_000

    result = run_files("dto-adaptasi-prod", entries)
    assert result.status == "COMPLETED"
    assert result.errors == []
    assert result.raw_log_entries == 10_000
    assert result.canonical_event_count == 10_000

    events = result.events
    assert scope_counts(events) == {"total": 10_000, "human": 0, "non_human": 10_000}

    rules = fd.load_monitor_rules()
    assert len(fd.outside_office_hours(events, rules, scope=HUMAN_ONLY)) == 0
    assert len(fd.outside_working_days(events, rules, scope=HUMAN_ONLY)) == 0
    assert len(fd.download_windows(events, rules, scope=HUMAN_ONLY)) == 0
    assert len(fd.critical_command_rows(events, rules, scope=HUMAN_ONLY)) == 0
    assert len(fd.forbidden_users(events, rules, scope=HUMAN_ONLY)) == 0

    assert len(fd.outside_office_hours(events, rules, scope=ALL_LOGS)) == 6_168
    assert len(fd.outside_working_days(events, rules, scope=ALL_LOGS)) == 0
    assert len(fd.download_windows(events, rules, scope=ALL_LOGS)) == 0
    assert len(fd.critical_command_rows(events, rules, scope=ALL_LOGS)) == 0
    assert len(fd.forbidden_users(events, rules, scope=ALL_LOGS)) == 1

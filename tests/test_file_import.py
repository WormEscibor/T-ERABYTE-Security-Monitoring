# -*- coding: utf-8 -*-
"""Test impor file log hasil unduhan manual dari GCP Logs Explorer."""
import json
from datetime import datetime, timezone

import pytest

from services.file_import import detect_project, parse_upload, parse_uploads


def _entry(ts, insert_id="i1", project="demo-project", method="v1.compute.instances.get"):
    return {
        "insertId": insert_id,
        "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": ts,
        "severity": "NOTICE",
        "resource": {"type": "gce_instance", "labels": {"project_id": project}},
        "protoPayload": {
            "methodName": method,
            "authenticationInfo": {"principalEmail": "analis@kemkes.go.id"},
        },
    }


def test_parse_json_array():
    entries = [_entry("2026-09-01T03:00:00Z", insert_id="a"), _entry("2026-09-01T04:00:00Z", insert_id="b")]
    out = parse_upload("log.json", json.dumps(entries).encode("utf-8"))
    assert len(out) == 2
    assert isinstance(out[0]["timestamp"], datetime)
    assert out[0]["timestamp"].tzinfo == timezone.utc


def test_parse_jsonl():
    entries = [_entry("2026-09-01T03:00:00Z", insert_id="a"), _entry("2026-09-01T04:00:00Z", insert_id="b")]
    text = "\n".join(json.dumps(e) for e in entries)
    out = parse_upload("log.jsonl", text.encode("utf-8"))
    assert len(out) == 2


def test_parse_single_object_and_wrapper():
    entry = _entry("2026-09-01T03:00:00Z")
    assert len(parse_upload("x.json", json.dumps(entry).encode("utf-8"))) == 1
    assert len(parse_upload("x.json", json.dumps({"entries": [entry]}).encode("utf-8"))) == 1


def test_parse_rejects_garbage():
    with pytest.raises(ValueError):
        parse_upload("x.json", b"not json at all")
    with pytest.raises(ValueError):
        parse_upload("x.json", b"")
    with pytest.raises(ValueError):
        parse_upload("x.json", json.dumps({"foo": "bar"}).encode("utf-8"))


def test_parse_uploads_dedupes_across_files():
    e1 = _entry("2026-09-01T03:00:00Z", insert_id="a")
    e2 = _entry("2026-09-01T04:00:00Z", insert_id="b")
    files = [
        ("a.json", json.dumps([e1]).encode("utf-8")),
        ("b.json", json.dumps([e1, e2]).encode("utf-8")),  # e1 duplikat
    ]
    entries, meta = parse_uploads(files)
    assert len(entries) == 2
    assert meta["total_raw"] == 3
    assert len(meta["files"]) == 2


def test_parse_uploads_skips_bad_files():
    files = [("bad.json", b"garbage"), ("ok.json", json.dumps([_entry("2026-09-01T03:00:00Z")]).encode("utf-8"))]
    entries, meta = parse_uploads(files)
    assert len(entries) == 1
    assert len(meta["errors"]) == 1
    assert meta["errors"][0].startswith("bad.json")


def test_detect_project():
    entries = [
        _entry("2026-09-01T03:00:00Z", project="proj-a", insert_id="1"),
        _entry("2026-09-01T04:00:00Z", project="proj-a", insert_id="2"),
        _entry("2026-09-01T05:00:00Z", project="proj-b", insert_id="3"),
    ]
    assert detect_project(entries) == "proj-a"
    assert detect_project([]) == ""

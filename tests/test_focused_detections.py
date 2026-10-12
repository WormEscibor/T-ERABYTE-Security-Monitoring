# -*- coding: utf-8 -*-
"""Test untuk deteksi fokus Dashboard Monitoring (engines/focused_detections.py)
dan generator data ilustrasi (services/monitor_demo.py)."""
import pandas as pd
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from engines import focused_detections as fd
from services.monitor_demo import generate_monitor_demo_events

WIB = ZoneInfo("Asia/Jakarta")


def _event(ts, user, action="API_CALL", outcome="SUCCESS", command="", volume=0.0,
           method="", granted=None, ip="10.0.0.1", resource="res", ptype="HUMAN"):
    return {
        "timestamp": ts,
        "principal_id": user,
        "principal_type": ptype,
        "event_action": action,
        "event_outcome": outcome,
        "command": command,
        "data_volume": float(volume),
        "api_method": method,
        "permission_granted": granted,
        "source_ip": ip,
        "resource_name": resource,
        "event_category": "ACTIVITY",
        "source_system": "TEST",
    }


def _wib_ts(y, m, d, hour, minute):
    return datetime(y, m, d, hour, minute, tzinfo=WIB).astimezone(timezone.utc)


# 2026-10-05 adalah hari Senin; 2026-10-10 Sabtu; 2026-10-11 Minggu.
MONDAY = _wib_ts(2026, 10, 5, 8, 0)
SATURDAY = _wib_ts(2026, 10, 10, 11, 0)
SUNDAY = _wib_ts(2026, 10, 11, 11, 0)


def test_load_monitor_rules_defaults():
    rules = fd.load_monitor_rules()
    assert rules["office_hours"]["start"] == "08:00"
    assert rules["office_hours"]["end"] == "17:00"
    assert rules["download"]["volume_threshold_mb"] == 1024
    assert rules["download"]["ops_threshold"] == 100
    assert rules["critical_command"]["score_threshold"] == 60
    assert rules["forbidden"]["threshold"] == 5


def test_office_hours_boundaries():
    events = pd.DataFrame([
        _event(_wib_ts(2026, 10, 5, 7, 59), "u1", action="LOGIN"),   # 07:59 -> di luar
        _event(_wib_ts(2026, 10, 5, 8, 0), "u1", action="LOGIN"),    # 08:00 -> di dalam
        _event(_wib_ts(2026, 10, 5, 17, 0), "u1", action="LOGIN"),   # 17:00 -> di dalam (inklusif)
        _event(_wib_ts(2026, 10, 5, 17, 1), "u1", action="LOGIN"),   # 17:01 -> di luar
        _event(SATURDAY, "u2", action="LOGIN"),                       # Sabtu -> bukan deteksi jam kerja
    ])
    out = fd.outside_office_hours(events)
    assert len(out) == 2
    times = sorted(pd.to_datetime(out["wib_time"]).dt.hour.tolist())
    assert times == [7, 17]


def test_working_days():
    events = pd.DataFrame([
        _event(MONDAY, "u1", action="LOGIN"),
        _event(SATURDAY, "u2", action="LOGIN"),
        _event(SUNDAY, "u3", action="LOGIN"),
    ])
    out = fd.outside_working_days(events)
    assert len(out) == 2
    assert set(out["principal_id"]) == {"u2", "u3"}


def test_download_volume_threshold():
    rows = []
    for i in range(11):  # 11 x 100 MB = 1.100 MB dalam 1 jam -> terpicu
        rows.append(_event(_wib_ts(2026, 10, 5, 10, i * 5), "a", action="DATA_ACCESS",
                           volume=100.0, method="storage.objects.get"))
    for i in range(10):  # 10 x 50 MB = 500 MB -> tidak terpicu
        rows.append(_event(_wib_ts(2026, 10, 5, 11, i * 5), "b", action="DATA_ACCESS",
                           volume=50.0, method="storage.objects.get"))
    windows = fd.download_windows(pd.DataFrame(rows))
    assert "a" in set(windows["principal_id"])
    assert "b" not in set(windows["principal_id"])
    row = windows[windows["principal_id"] == "a"].iloc[0]
    assert row["volume_mb"] == 1100.0
    assert row["ops"] == 11


def test_download_ops_threshold():
    rows = []
    for i in range(105):  # 105 operasi tanpa byte -> terpicu lewat jumlah operasi
        rows.append(_event(_wib_ts(2026, 10, 5, 12, i % 60), "c", action="DATA_ACCESS",
                           volume=0.0, method="storage.objects.get"))
    for i in range(99):  # 99 operasi -> tidak terpicu
        rows.append(_event(_wib_ts(2026, 10, 5, 13, i % 60), "d", action="DATA_ACCESS",
                           volume=0.0, method="storage.objects.get"))
    windows = fd.download_windows(pd.DataFrame(rows))
    assert "c" in set(windows["principal_id"])
    assert "d" not in set(windows["principal_id"])


def test_critical_command_threshold():
    events = pd.DataFrame([
        _event(MONDAY, "x", action="COMMAND", command="sudo useradd backdoor"),  # 65 -> terpicu
        _event(MONDAY, "y", action="COMMAND", command="kubectl get pods"),       # 20 -> tidak
        _event(MONDAY, "z", action="COMMAND", command="sudo iptables -L"),       # 60 -> terpicu (batas)
    ])
    out = fd.critical_command_rows(events)
    assert set(out["principal_id"]) == {"x", "z"}
    scores = dict(zip(out["principal_id"], out["score"]))
    assert scores["x"] == 65
    assert scores["z"] == 60


def test_forbidden_threshold_and_login_exclusion():
    rows = []
    for i in range(6):  # 6 DENIED -> terpicu
        rows.append(_event(_wib_ts(2026, 10, 5, 9, i * 10), "f", action="IAM_CHANGE",
                           outcome="DENIED", granted=False))
    for i in range(3):  # 3 DENIED -> tidak terpicu
        rows.append(_event(_wib_ts(2026, 10, 5, 10, i * 10), "g", action="IAM_CHANGE",
                           outcome="DENIED", granted=False))
    for i in range(6):  # 6 login FAILURE -> TIDAK dihitung forbidden
        rows.append(_event(_wib_ts(2026, 10, 5, 11, i * 10), "h", action="LOGIN",
                           outcome="FAILURE", granted=False))
    out = fd.forbidden_users(pd.DataFrame(rows))
    assert set(out["principal_id"]) == {"f"}
    assert int(out.iloc[0]["kejadian"]) == 6


def test_empty_inputs_are_safe():
    empty = pd.DataFrame()
    for fn in (fd.outside_office_hours, fd.outside_working_days, fd.critical_command_rows):
        assert fn(empty).empty
    assert fd.download_windows(empty).empty
    assert fd.forbidden_users(empty).empty
    assert fd.build_findings(empty).empty
    assert fd.add_local_time(empty).empty


def test_non_human_excluded_from_detections():
    rows = []
    for i in range(6):  # service account: 6x akses ditolak + login 07:59
        rows.append(_event(_wib_ts(2026, 10, 5, 7, 59), "svc-data@kemkes.iam.gserviceaccount.com",
                           action="IAM_CHANGE", outcome="DENIED", granted=False, ptype="SERVICE ACCOUNT"))
    rows.append(_event(_wib_ts(2026, 10, 5, 7, 58), "svc-data@kemkes.iam.gserviceaccount.com",
                       action="LOGIN", ptype="SERVICE ACCOUNT"))
    for i in range(6):  # manusia: 6x akses ditolak
        rows.append(_event(_wib_ts(2026, 10, 5, 7, 59), "manusia@kemkes.go.id",
                           action="IAM_CHANGE", outcome="DENIED", granted=False))
    events = pd.DataFrame(rows)

    out = fd.outside_office_hours(events)
    assert set(out["principal_id"]) == {"manusia@kemkes.go.id"}
    forbidden = fd.forbidden_users(events)
    assert set(forbidden["principal_id"]) == {"manusia@kemkes.go.id"}
    findings = fd.build_findings(events)
    assert "svc-data@kemkes.iam.gserviceaccount.com" not in set(findings["user"])


def test_demo_triggers_all_five_detections():
    events = generate_monitor_demo_events()
    assert not events.empty
    assert "raw_payload" in events.columns

    hours = fd.outside_office_hours(events)
    assert "eko@kemkes.go.id" in set(hours["principal_id"])

    days = fd.outside_working_days(events)
    assert "doni@kemkes.go.id" in set(days["principal_id"])

    windows = fd.download_windows(events)
    by_user = windows.groupby("principal_id")["volume_mb"].max().to_dict()
    assert "doni@kemkes.go.id" in windows["principal_id"].tolist()
    assert by_user["doni@kemkes.go.id"] >= 1024
    assert "gita@kemkes.go.id" in windows["principal_id"].tolist()
    assert "budi@kemkes.go.id" not in windows["principal_id"].tolist()

    cmds = fd.critical_command_rows(events)
    cmd_users = set(cmds["principal_id"])
    assert "eko@kemkes.go.id" in cmd_users
    eko_cmds = set(cmds[cmds["principal_id"] == "eko@kemkes.go.id"]["command"])
    assert "sudo useradd backdoor" in eko_cmds

    forbidden = fd.forbidden_users(events)
    fajar = forbidden[forbidden["principal_id"] == "fajar@kemkes.go.id"]
    assert not fajar.empty
    assert int(fajar.iloc[0]["kejadian"]) >= 6

    findings = fd.build_findings(events)
    categories = set(findings["kategori"])
    assert {"Luar Jam Kerja", "Luar Hari Kerja", "Download Besar",
            "Critical Command", "Forbidden/Unauthorized"}.issubset(categories)


def test_monitor_pdf_generation():
    from core.query_context import default_context
    from reports.monitor_pdf import build_monitor_pdf
    events = generate_monitor_demo_events()
    findings = fd.build_findings(events)
    ctx = default_context()
    pdf = build_monitor_pdf(events, findings, ctx, "DEMO")
    assert isinstance(pdf, bytes)
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 2000


def test_run_files_end_to_end():
    """Simulasi penuh jalur FILE: normalize -> enrich -> deteksi fokus."""
    from datetime import date, time, timedelta
    from services.pipeline import run_files
    from core.query_context import QueryContext

    now = datetime.now(timezone.utc)
    entries = [
        {
            "timestamp": now - timedelta(hours=2),
            "logName": "projects/demo-project/logs/cloudaudit.googleapis.com%2Factivity",
            "insertId": "mock-abc123",
            "severity": "NOTICE",
            "resource": {"type": "gce_instance",
                         "labels": {"project_id": "demo-project", "zone": "asia-southeast2-a", "instance_id": "123456"}},
            "protoPayload": {
                "methodName": "v1.compute.instances.setMetadata",
                "authenticationInfo": {"principalEmail": "analis@kemkes.go.id"},
                "requestMetadata": {"callerIp": "10.0.0.5"},
                "resourceName": "projects/demo-project/zones/asia-southeast2-a/instances/web-01",
                "authorizationInfo": [{"permission": "compute.instances.setMetadata", "granted": True}],
            },
        },
        {
            "timestamp": now - timedelta(hours=1),
            "logName": "projects/demo-project/logs/cloudaudit.googleapis.com%2Fdata_access",
            "insertId": "mock-def456",
            "severity": "NOTICE",
            "resource": {"type": "gcs_bucket", "labels": {"project_id": "demo-project"}},
            "protoPayload": {
                "methodName": "storage.objects.get",
                "authenticationInfo": {"principalEmail": "analis@kemkes.go.id"},
                "requestMetadata": {"callerIp": "10.0.0.5"},
                "resourceName": "projects/_/buckets/arsip-data",
                "authorizationInfo": [{"permission": "storage.objects.get", "granted": False}],
                "status": {"code": 7},
            },
        },
        {
            "timestamp": now - timedelta(hours=3),
            "logName": "organizations/123/logs/cloudaudit.googleapis.com%2Fdata_access",
            "insertId": "mock-login-1",
            "severity": "NOTICE",
            "resource": {"type": "gce_instance", "labels": {"project_id": "demo-project"}},
            "protoPayload": {
                "methodName": "google.login.LoginService.loginSuccess",
                "serviceName": "login.googleapis.com",
                "authenticationInfo": {"principalEmail": "analis@kemkes.go.id"},
                "requestMetadata": {"callerIp": "10.0.0.9"},
                "resourceName": "projects/demo-project",
            },
        },
    ]

    today = datetime.now(timezone.utc).date()
    ctx = QueryContext("demo-project", "Asia/Jakarta", today, today, time(0, 0), time(23, 59, 59))
    result = run_files("demo-project", entries)

    assert result.status in {"COMPLETED", "PARTIAL"}
    assert not result.events.empty
    assert "analis@kemkes.go.id" in set(result.events["principal_id"])
    assert "DENIED" in set(result.events["event_outcome"])

    # Metadata koleksi & counter jujur.
    assert result.raw_log_entries == len(entries)
    assert result.canonical_event_count == len(result.events)
    assert result.pre_filter_count >= result.canonical_event_count

    # Login stream terdeteksi dari file unggahan tanpa sumber terpisah.
    assert not result.auth.empty
    assert "SUCCESS" in set(result.auth["status"])

    # Seluruh deteksi fokus harus berjalan di atas hasil file tanpa exception.
    assert isinstance(fd.outside_office_hours(result.events), pd.DataFrame)
    assert isinstance(fd.outside_working_days(result.events), pd.DataFrame)
    assert isinstance(fd.download_windows(result.events), pd.DataFrame)
    assert isinstance(fd.critical_command_rows(result.events), pd.DataFrame)
    assert isinstance(fd.forbidden_users(result.events), pd.DataFrame)
    assert isinstance(fd.build_findings(result.events), pd.DataFrame)


def test_risk_rules_table():
    table = fd.risk_rules_table()
    assert not table.empty
    assert {"token", "skor", "keterangan"}.issubset(table.columns)


def test_events_by_ids():
    events = generate_monitor_demo_events()
    first_id = str(events.iloc[0]["event_id"])
    sub = fd.events_by_ids(events, [first_id])
    assert len(sub) == 1
    assert str(sub.iloc[0]["event_id"]) == first_id

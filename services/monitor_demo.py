# -*- coding: utf-8 -*-
"""Data ilustrasi deterministik untuk Dashboard Monitoring fokus.

Dataset sintetis berlabel ``source_system="DEMO"`` dan dirancang agar
kelima deteksi fokus selalu terpicu di dalam jendela 7 hari terakhir:

  - doni@kemkes.go.id : download ~1,9 GB dalam 1 jam pada Sabtu dini hari
                        (terpicu: luar hari kerja + download besar via volume)
  - gita@kemkes.go.id : 120 operasi unduh dalam 1 jam (terpicu: download
                        besar via jumlah operasi, ukuran byte tidak tercatat)
  - eko@kemkes.go.id  : "sudo useradd backdoor" jam 22:30 WIB hari kerja
                        (terpicu: luar jam kerja + critical command)
  - fajar@kemkes.go.id: 6 kejadian akses ditolak (terpicu: forbidden/unauthorized)
  - budi@kemkes.go.id : unduh ~500 MB dalam 1 jam (TIDAK terpicu — pembanding)

Data ini tidak pernah digunakan untuk mengklaim fakta keamanan operasional.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone, time as datetime_time
from zoneinfo import ZoneInfo
import hashlib
import json
import random

import pandas as pd

WIB = ZoneInfo("Asia/Jakarta")


def _event_id(i: int, user: str, ts: datetime, action: str) -> str:
    return hashlib.sha256(f"monitor-demo|{i}|{user}|{ts.isoformat()}|{action}".encode()).hexdigest()


def _wib_utc(day_offset: int, hour: int, minute: int) -> datetime:
    """UTC timestamp dari (hari ini - day_offset) pukul hour:minute WIB."""
    local_day = datetime.now().date() - timedelta(days=day_offset)
    local = datetime.combine(local_day, datetime_time(hour, minute), tzinfo=WIB)
    return local.astimezone(timezone.utc)


def _recent_weekday_offset(weekday: int) -> int:
    """Offset hari ke belakang menuju hari (weekday) terbaru dalam 7 hari terakhir."""
    today = datetime.now().date().weekday()
    if today >= weekday:
        return today - weekday
    return today + (7 - weekday)


def _recent_working_day_offset() -> int:
    """Offset hari kerja terbaru yang seluruhnya sudah lewat (bukan hari ini)."""
    offset = 1
    for _ in range(7):
        day = datetime.now().date() - timedelta(days=offset)
        if day.weekday() <= 4:
            return offset
        offset += 1
    return 1


def _raw_payload(user: str, ts: datetime, action: str, method: str, ip: str,
                 resource: str, outcome: str, command: str = "",
                 volume_mb: float = 0.0) -> str:
    proto = {
        "methodName": method,
        "authenticationInfo": {"principalEmail": user},
        "requestMetadata": {"callerIp": ip},
        "resourceName": resource,
    }
    if command:
        proto["request"] = {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "command": command}
    if volume_mb:
        proto["response"] = {"downloadedBytes": str(int(volume_mb * 1024 * 1024))}
    if outcome in {"DENIED", "FAILURE"}:
        proto["status"] = {"code": 7, "message": "PERMISSION_DENIED" if outcome == "DENIED" else "UNAUTHENTICATED"}
    payload = {
        "insertId": hashlib.sha256(f"{user}|{ts.isoformat()}|{method}|{outcome}".encode()).hexdigest()[:16],
        "logName": f"projects/kemkes-demo/logs/cloudaudit.googleapis.com%2F{'data_access' if action == 'DATA_ACCESS' else 'activity'}",
        "timestamp": ts.isoformat(),
        "severity": "NOTICE" if outcome == "SUCCESS" else "WARNING",
        "protoPayload": proto,
        "resource": {"type": "gcs_bucket", "labels": {"project_id": "kemkes-demo", "location": "asia-southeast2"}},
    }
    return json.dumps(payload, ensure_ascii=False, default=str)


def generate_monitor_demo_events(seed: int = 20261005, days: int = 7, n: int = 420) -> pd.DataFrame:
    """Buat dataset ilustrasi 7 hari dengan kejadian terjamin untuk kelima deteksi."""
    rng = random.Random(seed)
    users = ["ahmad@kemkes.go.id", "budi@kemkes.go.id", "citra@kemkes.go.id", "dina@kemkes.go.id", "svc-satusehat@kemkes-demo.iam.gserviceaccount.com"]
    ips = ["10.20.10.11", "10.20.10.12", "10.20.10.13", "198.51.100.20"]
    devices = ["KEMKES-WS-01", "KEMKES-WS-02", "KEMKES-WS-03"]
    projects = ["dto-asik-prod", "satusehat-prod", "csirt-monitoring"]
    api_methods = ["storage.objects.get", "compute.instances.list", "iam.serviceAccounts.get", "bigquery.jobs.create", "healthcare.fhirStores.fhir.read"]
    commands = ["", "kubectl get pods", "systemctl status nginx", "tar -czf /tmp/logs.tgz /var/log", "chmod 644 /tmp/file"]
    resources = ["projects/dto-asik-prod", "projects/satusehat-prod/datasets/health", "projects/csirt-monitoring/logs/security", "projects/satusehat-prod/buckets/arsip-data"]
    base = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
    rows: list[dict] = []
    index = 0

    def add(user: str, ts: datetime, action: str, method: str, outcome: str,
            command: str = "", volume_mb: float = 0.0, granted=None,
            classification: str = "UNKNOWN", project: str = "", resource: str = "") -> None:
        nonlocal index
        ip = rng.choice(ips)
        event_id = _event_id(index, user, ts, action)
        index += 1
        rows.append({
            "event_id": event_id,
            "timestamp": ts,
            "ingest_time": ts + timedelta(seconds=rng.randrange(0, 4)),
            "source_system": "DEMO",
            "source_type": "SYNTHETIC",
            "collector": "demo",
            "event_category": "AUTHENTICATION" if action == "LOGIN" else "DATA_ACCESS" if action == "DATA_ACCESS" else "IDENTITY_ACCESS" if action == "IAM_CHANGE" else "COMMAND_EXECUTION" if action == "COMMAND" else "ACTIVITY",
            "event_action": action,
            "event_outcome": outcome,
            "principal_id": user,
            "principal_name": user,
            "principal_type": "SERVICE ACCOUNT" if "gserviceaccount.com" in user else "HUMAN",
            "session_id": f"MON-{index // 3:05d}",
            "device_id": rng.choice(devices),
            "source_ip": ip,
            "destination_ip": "",
            "source_country": "Indonesia",
            "source_asn": "ASN-DEMO",
            "resource_type": "gcs_bucket" if action == "DATA_ACCESS" else "gcp_resource",
            "resource_id": resource or rng.choice(resources),
            "resource_name": (resource or "kemkes-demo").split("/")[-1],
            "project_id": project or rng.choice(projects),
            "folder_id": "",
            "organization_id": "",
            "api_method": method,
            "command": command,
            "process": "bash" if command else "",
            "permission": method if action in {"IAM_CHANGE", "DATA_ACCESS"} else "",
            "permission_type": "DATA_READ" if action == "DATA_ACCESS" else "ADMIN_WRITE" if action == "IAM_CHANGE" else "",
            "permission_granted": (outcome not in {"DENIED", "FAILURE"}) if granted is None else bool(granted),
            "data_classification": classification,
            "data_volume": float(volume_mb),
            "asset_criticality": "HIGH" if "satusehat" in str(resource) else "MEDIUM",
            "mitre_tactic": "Exfiltration" if action == "DATA_ACCESS" else "Privilege Escalation" if action == "IAM_CHANGE" else "",
            "mitre_technique": "T1530" if action == "DATA_ACCESS" else "",
            "threat_intel_match": False,
            "threat_intel_confidence": 0.0,
            "detail": command or method,
            "raw_payload": _raw_payload(user, ts, action, method, ip, resource or "kemkes-demo", outcome, command, volume_mb),
        })

    # --- Lalu lintas normal 7 hari (bukan kejadian terjamin) ---
    now = datetime.now(timezone.utc)
    for _ in range(n):
        user = rng.choice(users)
        day = rng.randrange(days)
        hour = rng.randrange(8, 17)  # mayoritas di jam kerja
        minute = rng.randrange(60)
        ts = base + timedelta(days=day, hours=hour, minutes=minute)
        if ts > now:
            continue  # jangan membuat event di masa depan
        roll = rng.random()
        if roll < 0.22:
            add(user, ts, "LOGIN", "google.login.LoginService.loginSuccess",
                "FAILURE" if rng.random() < 0.04 else "SUCCESS")
        elif roll < 0.40:
            add(user, ts, "IAM_CHANGE", rng.choice(["storage.objects.setIamPolicy", "iam.serviceAccounts.update"]),
                "DENIED" if rng.random() < 0.08 else "SUCCESS", granted=True if rng.random() > 0.08 else False)
        elif roll < 0.80:
            add(user, ts, "DATA_ACCESS", rng.choice(api_methods), "SUCCESS",
                volume_mb=float(rng.randint(1, 200)), classification=rng.choice(["INTERNAL", "CONFIDENTIAL", "PUBLIC"]))
        else:
            cmd = rng.choice(commands)
            add(user, ts, "COMMAND", "compute.instances.osConfigExec", "SUCCESS", command=cmd)

    # --- 1) Download besar ~1,9 GB dalam 1 jam pada Sabtu dini hari (doni) ---
    sat_offset = _recent_weekday_offset(5)
    sat_anchor_hour = 2
    if _wib_utc(sat_offset, sat_anchor_hour, 0) > datetime.now(timezone.utc):
        # Sabtu ini baru dimulai (sebelum 02:00 WIB): gunakan 00:00–01:00 WIB
        # hari ini agar tetap jatuh pada Sabtu di dalam jendela 7 hari.
        sat_anchor_hour = 0
    for i in range(40):
        minute = (i * 59) // 39  # 0..59, tersebar dalam 1 jam
        add("doni@kemkes.go.id", _wib_utc(sat_offset, sat_anchor_hour, minute), "DATA_ACCESS",
            "storage.objects.get", "SUCCESS", volume_mb=48.0,
            classification="CONFIDENTIAL", project="satusehat-prod",
            resource="projects/satusehat-prod/buckets/arsip-data")

    # --- 2) Download besar via jumlah operasi (120 operasi/jam, tanpa byte) ---
    for i in range(120):
        minute = (i * 60) // 120
        add("gita@kemkes.go.id", _wib_utc(sat_offset, sat_anchor_hour + 2, minute), "DATA_ACCESS",
            "storage.objects.get", "SUCCESS", volume_mb=0.0,
            classification="INTERNAL", project="dto-asik-prod",
            resource="projects/dto-asik-prod/buckets/dataset-demo")

    # --- Pembanding: unduh ~500 MB dalam 1 jam, TIDAK terpicu (budi) ---
    work_offset = _recent_working_day_offset()
    for i in range(10):
        add("budi@kemkes.go.id", _wib_utc(work_offset, 11, i * 5), "DATA_ACCESS",
            "storage.objects.get", "SUCCESS", volume_mb=50.0,
            classification="INTERNAL", project="dto-asik-prod",
            resource="projects/dto-asik-prod/buckets/dataset-demo")

    # --- 3) Critical command pada jam 22:30 WIB hari kerja (eko) ---
    add("eko@kemkes.go.id", _wib_utc(work_offset, 22, 30), "LOGIN",
        "google.login.LoginService.loginSuccess", "SUCCESS")
    add("eko@kemkes.go.id", _wib_utc(work_offset, 22, 32), "COMMAND",
        "compute.instances.osConfigExec", "SUCCESS", command="sudo useradd backdoor")
    add("eko@kemkes.go.id", _wib_utc(work_offset, 22, 36), "COMMAND",
        "compute.instances.osConfigExec", "SUCCESS", command="sudo nc -lvp 4444")
    add("eko@kemkes.go.id", _wib_utc(work_offset, 22, 40), "COMMAND",
        "compute.instances.osConfigExec", "SUCCESS", command="chmod 777 /etc/shadow")

    # --- 4) 6 kejadian akses ditolak (fajar) ---
    denied_methods = ["storage.objects.setIamPolicy", "iam.serviceAccounts.createKey",
                      "bigquery.tables.update", "compute.firewalls.create",
                      "storage.buckets.delete", "iam.roles.update"]
    for i, method in enumerate(denied_methods):
        add("fajar@kemkes.go.id", _wib_utc(work_offset, 10, i * 5), "IAM_CHANGE",
            method, "DENIED", granted=False, project="satusehat-prod",
            resource="projects/satusehat-prod/secrets/app-secret")

    # --- 5) Aktivitas Sabtu pagi tambahan (citra) agar tabel luar-hari-kerja kaya ---
    for i in range(6):
        add("citra@kemkes.go.id", _wib_utc(sat_offset, 9, 10 + i * 9), "DATA_ACCESS",
            "healthcare.fhirStores.fhir.read", "SUCCESS", volume_mb=float(rng.randint(2, 60)),
            classification="RESTRICTED", project="satusehat-prod",
            resource="projects/satusehat-prod/datasets/health")

    out = pd.DataFrame(rows)
    out = out.sort_values("timestamp", ascending=False, kind="stable").reset_index(drop=True)
    return out

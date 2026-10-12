"""Deterministic demo telemetry for development and offline validation.

The demo dataset is synthetic and is clearly labeled in the UI; it is never
used to claim operational security facts.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import random
import pandas as pd


def _event_id(i: int, user: str, ts: datetime, action: str) -> str:
    return hashlib.sha256(f"demo|{i}|{user}|{ts.isoformat()}|{action}".encode()).hexdigest()


def generate_demo_events(seed: int = 20260925, days: int = 7, n: int = 420) -> pd.DataFrame:
    rng = random.Random(seed)
    users = ["ahmad@kemkes.go.id", "budi@kemkes.go.id", "citra@kemkes.go.id", "dina@kemkes.go.id", "svc-satusehat@project.iam.gserviceaccount.com"]
    ips = ["10.20.10.11", "10.20.10.12", "10.20.10.13", "198.51.100.20", "203.0.113.44"]
    devices = ["KEMKES-WS-01", "KEMKES-WS-02", "KEMKES-WS-03", "UNKNOWN-DEVICE"]
    projects = ["dto-asik-prod", "satusehat-prod", "csirt-monitoring"]
    api_methods = ["storage.objects.get", "compute.instances.list", "iam.serviceAccounts.get", "bigquery.jobs.create", "healthcare.fhirStores.fhir.read", "healthcare.fhirStores.fhir.search"]
    resources = ["projects/dto-asik-prod", "projects/satusehat-prod/datasets/health", "projects/csirt-monitoring/logs/security", "projects/satusehat-prod/secrets/app-secret"]
    commands = ["", "sudo systemctl restart nginx", "curl https://example.invalid", "kubectl get pods", "kubectl exec -it api -- sh", "tar -czf /tmp/logs.tgz /var/log", "chmod 777 /tmp/file"]
    classifications = ["INTERNAL", "CONFIDENTIAL", "RESTRICTED", "PUBLIC"]
    base = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days-1)
    rows = []
    for i in range(n):
        user = rng.choice(users)
        day = rng.randrange(days)
        hour = rng.randrange(24)
        minute = rng.randrange(60)
        ts = base + timedelta(days=day, hours=hour, minutes=minute)
        action_roll = rng.random()
        if action_roll < 0.18:
            action = "LOGIN"
        elif action_roll < 0.35:
            action = "IAM_CHANGE"
        elif action_roll < 0.55:
            action = "API_CALL"
        elif action_roll < 0.80:
            action = "DATA_ACCESS"
        else:
            action = "COMMAND"
        command = rng.choice(commands) if action == "COMMAND" else ""
        ip = rng.choice(ips)
        device = rng.choice(devices)
        project = rng.choice(projects)
        resource = rng.choice(resources)
        classification = rng.choice(classifications) if action in {"DATA_ACCESS", "API_CALL"} else "UNKNOWN"
        criticality = "CRITICAL" if "satusehat-prod" in resource or "secret" in resource else rng.choice(["MEDIUM", "HIGH"])
        permission_type = "DATA_READ" if action == "DATA_ACCESS" else "ADMIN_WRITE" if action == "IAM_CHANGE" else ""
        granted = action != "IAM_CHANGE" or rng.random() > 0.15
        if action == "LOGIN":
            method = "google.login.LoginService.loginFailure" if rng.random() < 0.06 else "google.login.LoginService.loginSuccess"
            outcome = "FAILURE" if method.endswith("Failure") else "SUCCESS"
        else:
            method = rng.choice(api_methods)
            outcome = "DENIED" if not granted else "SUCCESS"
        rows.append({
            "event_id": _event_id(i, user, ts, action),
            "timestamp": ts,
            "ingest_time": ts + timedelta(seconds=rng.randrange(0, 4)),
            "source_system": "DEMO",
            "source_type": "SYNTHETIC",
            "collector": "demo",
            "event_category": "AUTHENTICATION" if action == "LOGIN" else "IDENTITY_ACCESS" if action == "IAM_CHANGE" else "ACTIVITY",
            "event_action": action,
            "event_outcome": outcome,
            "principal_id": user,
            "principal_name": user,
            "principal_type": "SERVICE ACCOUNT" if "gserviceaccount.com" in user else "HUMAN",
            "session_id": f"SES-{i//3:05d}",
            "device_id": device,
            "source_ip": ip,
            "destination_ip": "",
            "source_country": "Indonesia" if ip.startswith("10.") else rng.choice(["Singapore", "United States", "Indonesia"]),
            "source_asn": "ASN-DEMO",
            "resource_type": "gcp_resource",
            "resource_id": resource,
            "resource_name": resource.split("/")[-1],
            "project_id": project,
            "folder_id": "",
            "organization_id": "",
            "api_method": method,
            "command": command,
            "process": "bash" if command else "",
            "permission": method if action in {"IAM_CHANGE", "DATA_ACCESS"} else "",
            "permission_type": permission_type,
            "permission_granted": bool(granted),
            "data_classification": classification,
            "data_volume": float(rng.randint(1, 5000)) if action == "DATA_ACCESS" else 0.0,
            "asset_criticality": criticality,
            "mitre_tactic": "Credential Access" if action == "LOGIN" else "Privilege Escalation" if action == "IAM_CHANGE" else "",
            "mitre_technique": "T1078" if action == "LOGIN" and outcome == "SUCCESS" else "T1098" if action == "IAM_CHANGE" else "",
            "threat_intel_match": ip in {"203.0.113.44"},
            "threat_intel_confidence": 0.91 if ip == "203.0.113.44" else 0.0,
            "detail": command or method,
        })
    return pd.DataFrame(rows).sort_values("timestamp", ascending=False, kind="stable").reset_index(drop=True)


def demo_inventory() -> pd.DataFrame:
    return pd.DataFrame([
        {"name":"satusehat-api-01","zone":"asia-southeast2-a","status":"RUNNING","criticality":"CRITICAL","internet_exposed":True,"owner":"Platform"},
        {"name":"fhir-gateway-02","zone":"asia-southeast2-b","status":"RUNNING","criticality":"CRITICAL","internet_exposed":True,"owner":"Healthcare"},
        {"name":"csirt-siem-01","zone":"asia-southeast2-a","status":"RUNNING","criticality":"HIGH","internet_exposed":False,"owner":"Tim CSIRT Kementerian Kesehatan Republik Indonesia"},
        {"name":"legacy-app-03","zone":"asia-southeast2-a","status":"STOPPED","criticality":"MEDIUM","internet_exposed":False,"owner":"Application"},
    ])

"""Analytics pipeline for T-ERABYTE CSIRT SOC PRO (mode FILE — tanpa koneksi GCP).

Sumber data: file log yang diunduh manual dari GCP Logs Explorer (JSON) atau
data ilustrasi DEMO. Tidak ada pengambilan data langsung dari server GCP.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import logging

import pandas as pd

from analytics.behavior import parse_auth, parse_gcp_iam_logs
from app_event_adapter import normalize_cloud_entry
from collectors.auditd import parse_execve
from core.event_schema import stable_event_id, ensure_canonical_event_frame
from core.query_context import QueryContext, filter_dataframe
from engines.baseline import build_baseline, apply_baseline
from engines.detection import dangerous_command_score, detect_after_hours_dangerous, sequence_alerts
from engines.entity_graph import build_edges
from engines.identity import resolve_identity
from engines.risk import apply_adaptive_risk
from engines.session import sessionize
from services.demo_data import generate_demo_events, demo_inventory

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    events: pd.DataFrame = field(default_factory=pd.DataFrame)
    auth: pd.DataFrame = field(default_factory=pd.DataFrame)
    behavioral: pd.DataFrame = field(default_factory=pd.DataFrame)
    commands: pd.DataFrame = field(default_factory=pd.DataFrame)
    findings: pd.DataFrame = field(default_factory=pd.DataFrame)
    inventory: pd.DataFrame = field(default_factory=pd.DataFrame)
    sessions: pd.DataFrame = field(default_factory=pd.DataFrame)
    graph_edges: pd.DataFrame = field(default_factory=pd.DataFrame)
    after_hours_alerts: pd.DataFrame = field(default_factory=pd.DataFrame)
    sequence_alerts: pd.DataFrame = field(default_factory=pd.DataFrame)
    scc_diagnostic: str = ""
    connected: bool = False
    errors: list[str] = field(default_factory=list)
    status: str = "STARTING"
    completed_tasks: int = 0
    total_tasks: int = 1
    last_error: str = ""
    raw_log_entries: int = 0
    canonical_event_count: int = 0
    pre_filter_count: int = 0
    slices: int = 0
    truncated: bool = False
    truncated_slices: int = 0
    collector_status: dict[str, str] = field(default_factory=dict)


def _command_principal(command: dict) -> str:
    """Identitas pengguna untuk log perintah OS dari auditd (auid), bila ada.

    Log auditd tidak menyertakan principalEmail seperti Cloud Audit Logs, jadi
    kolom User akan kosong; auid (audit user id) dijadikan identitas pengguna.
    Nilai "unset"/"4294967295" (-1) berarti tidak ada sesi login -> dibiarkan kosong.
    """
    auid = str(command.get("auid") or "").strip()
    if auid and auid not in {"unset", "4294967295"}:
        return f"uid:{auid}"
    return ""


def canonicalize_demo(events: pd.DataFrame) -> pd.DataFrame:
    events = resolve_identity(events)
    baseline = build_baseline(events, "principal_id")
    events = apply_baseline(events, baseline, "principal_id")
    command_scores = {}
    for command in events.get("command", pd.Series(dtype=str)).dropna().astype(str):
        score, _ = dangerous_command_score(command)
        command_scores[command.casefold()] = score
    events = apply_adaptive_risk(events, baseline=None, command_scores=command_scores)
    events = sessionize(events)
    edges = build_edges(events)
    after_hours = detect_after_hours_dangerous(events)
    seq = sequence_alerts(events)
    return events, edges, after_hours, seq


def run_demo(seed: int = 20260925, query_context: QueryContext | None = None) -> PipelineResult:
    events = generate_demo_events(seed=seed)
    if query_context is not None:
        events = filter_dataframe(events, query_context)
    events, edges, after_hours, seq = canonicalize_demo(events)
    auth = events[events["event_category"] == "AUTHENTICATION"].copy()
    behavioral = events[events["event_action"] == "IAM_CHANGE"].copy()
    commands = events[events["command"].fillna("").astype(str).str.len().gt(0)].copy()
    findings = pd.DataFrame(columns=["timestamp", "severity", "finding", "resource_name", "source_log"])
    sessions = events.groupby("session_id", dropna=False).agg(first_seen=("timestamp","min"), last_seen=("timestamp","max"), user=("principal_id","first"), events=("event_id","count"), risk=("risk_score","max")).reset_index()
    return PipelineResult(events, auth, behavioral, commands, findings, demo_inventory(), sessions, edges, after_hours, seq, "Demo telemetry", False, [], "DEMO", 4, 4)


def _process_raw_entries(project, start_dt, end_dt, search, exact_phrase,
                         raw_rows, auth_entries, result: PipelineResult,
                         apply_project: bool = True) -> PipelineResult:
    """Tahap analisis bersama: entry mentah (dict) -> event kanonik + deteksi.

    Entry mentah diparse menjadi event kanonik lalu diberi pengayaan/deteksi
    yang sama untuk semua sumber data. ``result.auth`` harus sudah diisi
    parser auth (parse_auth) sebelum fungsi ini dipanggil; ``auth_entries``
    dipakai untuk merge event kanonik stream login (kosong bila login sudah
    termasuk dalam ``raw_rows`` — kasus file unggahan).

    ``apply_project=False`` (mode file unggahan) melewati penyaringan project:
    isi file adalah batas data yang dipilih pengguna, jadi tidak boleh ada
    event yang dibuang karena ketidakcocokan label project.
    """
    behavioral_df = parse_gcp_iam_logs(raw_rows)
    result.behavioral = behavioral_df.assign(project_id=project) if not behavioral_df.empty else pd.DataFrame()
    commands, canonical_rows = [], []
    for entry in raw_rows:
        c = []
        log_name = str(entry.get("logName") or entry.get("log_name") or "").lower()
        if "auditd" in log_name or "audit.log" in log_name or "type=execve" in str(entry.get("text_payload") or entry.get("textPayload") or "").lower():
            c = parse_execve([entry])
            if c:
                commands.extend(c)
        event = normalize_cloud_entry(entry)
        if event:
            if c:
                for command_index, command in enumerate(c):
                    command_event = event.copy()
                    command_text = str(command.get("command") or "")
                    command_event.update({
                        "event_category": "COMMAND_EXECUTION",
                        "event_action": "COMMAND_EXECUTION",
                        "command": command_text,
                        "principal_id": str(event.get("principal_id") or "") or _command_principal(command),
                        "source_ip": command.get("ip") or event.get("source_ip", ""),
                        "resource_name": command.get("hostname") or event.get("resource_name", ""),
                        "resource_id": command.get("hostname") or event.get("resource_id", ""),
                        "detail": f"{event.get('detail', '')}\ncommand={command_text}",
                    })
                    command_event["event_id"] = stable_event_id({
                        "base_event_id": event.get("event_id", ""),
                        "command": command_text,
                        "command_index": command_index,
                    })
                    canonical_rows.append(command_event)
            else:
                canonical_rows.append(event)
    result.commands = pd.DataFrame(commands).assign(project_id=project) if commands else pd.DataFrame()
    result.auth["project_id"] = result.auth.get("project_id", project) if not result.auth.empty else pd.Series(dtype=str)
    auth_canonical_rows = []
    for entry in auth_entries:
        canonical = normalize_cloud_entry(entry)
        if canonical:
            auth_canonical_rows.append(canonical)
    # Merge only canonical event records.  The dedicated auth parser remains a
    # projection for the authentication module and must never leak its different
    # column schema into the shared event stream.
    result.events = ensure_canonical_event_frame(pd.DataFrame(canonical_rows + auth_canonical_rows), project_id=project)
    result.events = result.events.drop_duplicates(subset=["event_id"], keep="first").reset_index(drop=True)
    result.pre_filter_count = int(len(result.events))
    # Final defense-in-depth: no downstream analytics stage can accidentally
    # reintroduce another project after collection.
    query_start = start_dt.astimezone(timezone.utc) if getattr(start_dt, "tzinfo", None) else start_dt.replace(tzinfo=timezone.utc)
    query_end = end_dt.astimezone(timezone.utc) if getattr(end_dt, "tzinfo", None) else end_dt.replace(tzinfo=timezone.utc)
    run_ctx = QueryContext(project_id=project, timezone_name="UTC", start_date=query_start.date(), end_date=query_end.date(), start_time=query_start.time(), end_time=query_end.time(), search_text=search, exact_phrase=exact_phrase)
    result.auth = filter_dataframe(result.auth, run_ctx, apply_project=apply_project)
    result.commands = filter_dataframe(result.commands, run_ctx, apply_project=apply_project)
    result.behavioral = filter_dataframe(result.behavioral, run_ctx, apply_project=apply_project)
    result.findings = filter_dataframe(result.findings, run_ctx, apply_project=apply_project)
    if not result.events.empty:
        result.events = ensure_canonical_event_frame(filter_dataframe(result.events, run_ctx, apply_project=apply_project), project_id=project)
    if not result.events.empty:
        result.events = resolve_identity(result.events)
        baseline = build_baseline(result.events, "principal_id")
        result.events = apply_baseline(result.events, baseline, "principal_id")
        command_scores = {str(c).casefold(): dangerous_command_score(c)[0] for c in result.commands.get("command", pd.Series(dtype=str))}
        result.events = apply_adaptive_risk(result.events, baseline=None, command_scores=command_scores)
        result.events = sessionize(result.events)
        result.graph_edges = build_edges(result.events)
        result.after_hours_alerts = detect_after_hours_dangerous(result.events)
        result.sequence_alerts = sequence_alerts(result.events)
        result.sessions = result.events.groupby("session_id", dropna=False).agg(first_seen=("timestamp","min"),last_seen=("timestamp","max"),user=("principal_id","first"),events=("event_id","count"),risk=("risk_score","max")).reset_index()
    # Hitung ulang jumlah event kanonik SETELAH filter rentang/project supaya
    # angka yang dilaporkan ke log/UI menggambarkan data yang benar-benar
    # dikirim, bukan jumlah sebelum penyaringan.
    result.canonical_event_count = int(len(result.events))
    result.status = "PARTIAL" if result.errors else "COMPLETED"
    result.last_error = " | ".join(result.errors)
    logger.info("run selesai: status=%s event_kanonik=%d pre_filter=%d error=%s",
                result.status, result.canonical_event_count, result.pre_filter_count, result.last_error or "-")
    return result


def run_files(project: str, entries, search: str = "", exact_phrase: bool = False) -> PipelineResult:
    """Analisis log dari file unggahan — tanpa koneksi GCP dan tanpa filter.

    ``entries`` adalah daftar dict entry log (hasil
    :func:`services.file_import.parse_uploads`). Jendela waktu diturunkan dari
    min/max timestamp isi file sehingga TIDAK ADA event yang terbuang karena
    rentang tanggal; penyaringan project juga dilewati (isi file = batas data
    yang dipilih pengguna). Stream login tidak dipisah: parser auth menyaring
    method LoginService sendiri, dan seluruh entry dinormalisasi satu kali.
    """
    result = PipelineResult(status="CONNECTING", total_tasks=1)
    result.raw_log_entries = int(len(entries))
    timestamps = [
        e.get("timestamp") for e in entries
        if isinstance(e, dict) and isinstance(e.get("timestamp"), datetime)
    ]
    if timestamps:
        start_dt = min(timestamps)
        end_dt = max(timestamps)
    else:
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(days=1)
        end_dt = now
    auth_df = parse_auth(entries)
    result.auth = auth_df if not auth_df.empty else pd.DataFrame()
    result.collector_status["File Unggahan"] = f"OK ({len(entries):,} entri mentah)"
    result.completed_tasks = 1
    logger.info("run_files mulai: project=%s entri=%d jendela=%s..%s",
                project, len(entries), start_dt.isoformat(), end_dt.isoformat())
    return _process_raw_entries(project, start_dt, end_dt, search, exact_phrase,
                                entries, [], result, apply_project=False)

# -*- coding: utf-8 -*-
"""Security Monitoring — 5 deteksi fokus + log mentah (tanpa koneksi GCP).

Aplikasi Streamlit ramping yang hanya menampilkan:
  1. User yang akses di luar jam kerja
  2. User yang akses di luar hari kerja
  3. User yang melakukan download besar
  4. User yang menjalankan critical command
  5. User yang sering mendapat forbidden/unauthorized
  + halaman Log Mentah (bisa diklik per baris dan diekspor CSV)

Sumber data: DEMO (ilustrasi, default) atau FILE (log JSON yang diunduh manual
dari GCP Logs Explorer lalu diunggah). Aplikasi tidak pernah mengambil data
langsung dari server GCP.
"""
from __future__ import annotations

import html
import json
import logging
import os
import platform
import time
from datetime import datetime, date, time as datetime_time, timezone

import pandas as pd
import plotly.express as px
import streamlit as st

from core.constants import KEMENKES_COLORS, ORGANIZATION
from core.event_schema import ensure_canonical_event_frame
from core.logging_setup import configure_logging
from core.query_context import QueryContext, default_context, filter_dataframe
from core.log_scope import ALL_LOGS, HUMAN_ONLY, filter_log_scope, scope_counts, scope_label
from engines import focused_detections as fd
from reports.monitor_pdf import build_monitor_pdf
from services.file_import import SUPPORTED_EXTENSIONS, detect_project, parse_uploads
from services.monitor_demo import generate_monitor_demo_events

configure_logging()
logger = logging.getLogger(__name__)

PAGES = [
    ("ringkasan", "Ringkasan"),
    ("jam_kerja", "Aktivitas di Luar Jam Kerja"),
    ("hari_kerja", "Aktivitas di Luar Hari Kerja"),
    ("download", "Unduhan Data Besar"),
    ("critical", "Perintah Kritikal"),
    ("forbidden", "Akses Ditolak Berulang"),
    ("log_mentah", "Log Mentah"),
    ("debug", "Debug"),
]

RISK_COLORS = {"KRITIS": "#C0392B", "TINGGI": "#E67E22", "SEDANG": "#F1C40F", "LOW": "#27AE60", "INFO": "#7F8C8D"}

st.set_page_config(page_title="Security Monitoring", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")


def _css() -> str:
    c = KEMENKES_COLORS
    return f"""
    <style>
    :root {{
      --mon-teal: {c['turquoise']}; --mon-teal2: {c['turquoise_medium']};
      --mon-ink: {c['ink']}; --mon-lime: {c['lime']}; --mon-grey: {c['grey']};
      --mon-surface: {c['surface']}; --mon-white: {c['white']};
    }}
    .stApp {{ background: var(--mon-surface); color: var(--mon-ink); }}
    section[data-testid="stSidebar"] {{ background: var(--mon-white) !important; border-right: 1px solid var(--mon-teal2); }}
    section[data-testid="stSidebar"] * {{ color: var(--mon-ink); }}
    section[data-testid="stSidebar"] input, section[data-testid="stSidebar"] textarea,
    section[data-testid="stSidebar"] [data-baseweb="select"] {{ color: var(--mon-ink) !important; }}
    section[data-testid="stSidebar"] h1, section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3, section[data-testid="stSidebar"] label {{ color: var(--mon-ink) !important; }}
    section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {{ color: var(--mon-grey); }}
    .block-container {{ max-width: 1500px; padding-top: 1.2rem; padding-bottom: 2.5rem; }}
    .mon-header {{ background: linear-gradient(135deg, var(--mon-teal), var(--mon-teal2)); color: #fff;
                   border-radius: 16px; padding: 16px 22px; margin-bottom: 10px; }}
    .mon-header h1 {{ color: #fff; margin: 0; font-size: 1.5rem; font-weight: 800; }}
    .mon-header p {{ color: #DFF6F4; margin: 2px 0 0 0; }}
    .kpi {{ background: #fff; border-radius: 14px; padding: 14px 16px; border: 1px solid #E3ECEF;
            box-shadow: 0 2px 8px rgba(24,50,58,.06); }}
    .kpi .num {{ font-size: 1.7rem; font-weight: 800; color: var(--mon-ink); line-height: 1.1; }}
    .kpi .lbl {{ font-size: .82rem; color: #6B7280; margin-top: 2px; }}
    .kpi .num.kritis {{ color: #C0392B; }} .kpi .num.tinggi {{ color: #E67E22; }}
    .badge {{ display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .75rem; font-weight: 700; color: #fff; }}
    .mon-menu-info {{ background: var(--mon-teal); border: 1px solid var(--mon-teal2); border-radius: 10px;
                       padding: 8px 10px; font-size: .8rem; color: #FFFFFF; margin: 6px 0 4px; line-height: 1.45; }}
    .mon-narrative {{ background: #FFFFFF; border-left: 5px solid var(--mon-teal); border-radius: 12px;
                      padding: 14px 18px; box-shadow: 0 2px 10px rgba(24,50,58,.07); margin: 4px 0 14px; line-height: 1.7; }}
    .mon-narrative p {{ margin: 0; }}
    .foot {{ color: #6B7280; font-size: .78rem; border-top: 1px solid #E3ECEF; margin-top: 26px; padding-top: 10px; }}
    </style>
    """


st.markdown(_css(), unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Helper
# -----------------------------------------------------------------------------
def _fmt_wib(value) -> str:
    if value is None or pd.isna(value):
        return "-"
    try:
        ts = pd.Timestamp(value)
        if ts.tzinfo is None:
            ts = ts.tz_localize("UTC")
        return ts.tz_convert("Asia/Jakarta").strftime("%d %b %Y %H:%M:%S WIB")
    except Exception:
        return str(value)


def _row_to_json(row) -> dict:
    out = {}
    for key, value in row.items():
        if isinstance(value, pd.Timestamp):
            out[key] = value.isoformat()
        elif isinstance(value, (datetime, date)):
            out[key] = str(value)
        elif isinstance(value, (int, float, bool, str)) or value is None:
            out[key] = value
        else:
            out[key] = str(value)
    return out


def _raw_log_json(events: pd.DataFrame, row: pd.Series) -> dict:
    """Log mentah: pakai raw_payload (DEMO) atau seluruh field event (LIVE)."""
    raw = None
    if "raw_payload" in events.columns and "event_id" in row.index:
        match = events.loc[events["event_id"].astype(str) == str(row.get("event_id", "")), "raw_payload"]
        if not match.empty:
            try:
                raw = json.loads(str(match.iloc[0]))
            except Exception:
                raw = None
    if raw is None:
        raw = _row_to_json(row.to_dict())
        for key in ("detail", "raw_reference", "log_name", "insert_id", "gcp_severity"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, dict):
                        raw[f"{key}_parsed"] = parsed
                except Exception:
                    pass
    return raw


def _kpi_cards(items: list[tuple[str, str, str | None]]) -> None:
    """items: (angka, label, kelas warna opsional: kritis|tinggi|'')."""
    cols = st.columns(len(items))
    for col, (num, label, cls) in zip(cols, items):
        with col:
            color_cls = f" {cls}" if cls else ""
            st.markdown(f"<div class='kpi'><div class='num{color_cls}'>{num}</div><div class='lbl'>{label}</div></div>", unsafe_allow_html=True)


def _badge(risk: str) -> str:
    color = RISK_COLORS.get(str(risk).upper(), "#7F8C8D")
    return f"<span class='badge' style='background:{color}'>{str(risk).upper()}</span>"


def _header(title: str, subtitle: str, mode_label: str) -> None:
    st.markdown(
        f"<div class='mon-header'><h1>{title}</h1><p>{subtitle}</p></div>"
        f"<div style='text-align:right;margin:-6px 0 10px'><span class='badge' style='background:var(--mon-teal)'>{mode_label}</span></div>",
        unsafe_allow_html=True,
    )


def _empty_info() -> None:
    st.info("Tidak ada kejadian pada rentang ini.")


def _mode_label(mode: str, scope: str = HUMAN_ONLY) -> str:
    source = "FILE • LOG UNGGAHAN" if mode != "DEMO" else "DEMO • DATA ILUSTRASI"
    return f"{source} · {scope_label(scope).upper()}"


def _identity_label(value: object) -> str:
    """Label tampilan untuk identitas kosong pada cakupan Semua Log."""
    text = str(value or "").strip()
    return text if text else "(tanpa identitas)"


def _event_view_columns(df: pd.DataFrame, fmt_time: bool = True) -> pd.DataFrame:
    cols = ["wib_time", "principal_id", "day_label", "event_action", "event_outcome", "command", "resource_name", "source_ip", "alasan"]
    present = [c for c in cols if c in df.columns]
    out = df[present].copy()
    renames = {
        "wib_time": "Waktu WIB", "principal_id": "Identitas", "day_label": "Hari",
        "event_action": "Aktivitas", "event_outcome": "Hasil", "command": "Perintah",
        "resource_name": "Resource", "source_ip": "IP", "alasan": "Alasan",
    }
    out = out.rename(columns={k: v for k, v in renames.items() if k in out.columns})
    if "Identitas" in out.columns:
        out["Identitas"] = out["Identitas"].map(_identity_label)
    if fmt_time and "Waktu WIB" in out.columns:
        out["Waktu WIB"] = out["Waktu WIB"].map(_fmt_wib)
    return out.reset_index(drop=True)


def _render_selected_detail(events: pd.DataFrame, row: pd.Series, kind: str) -> None:
    """Panel detail + log mentah untuk baris tabel yang diklik.

    ``row`` adalah baris sumber (detektor) yang kolomnya masih utuh
    (event_id / event_ids / principal_id / volume_mb / kejadian / score).
    """
    st.divider()
    st.markdown(f"### Detail: {kind}")

    sub = pd.DataFrame()
    if "event_ids" in row.index:
        try:
            ids = json.loads(str(row.get("event_ids") or "[]"))
        except Exception:
            ids = []
        sub = fd.events_by_ids(events, ids)
        if not sub.empty:
            st.caption(f"{len(sub)} event terkait:")
            st.dataframe(_event_view_columns(sub), hide_index=True, width="stretch")

    waktu = row.get("wib_time") if "wib_time" in row.index else row.get("first_wib")
    if waktu is None or pd.isna(waktu):
        waktu = row.get("window_start_wib")
    detail_items = [
        ("Identitas", str(row.get("principal_id", "-"))),
        ("Waktu WIB", _fmt_wib(waktu)),
        ("Aktivitas", str(row.get("event_action", "-"))),
        ("Hasil", str(row.get("event_outcome", "-"))),
        ("Perintah", str(row.get("command", "-"))),
        ("Resource", str(row.get("resource_name", "-"))),
        ("IP", str(row.get("source_ip", "-"))),
        ("Alasan", str(row.get("alasan", "-"))),
    ]
    cols = st.columns(4)
    for col, (label, value) in zip(cols, detail_items):
        col.markdown(f"**{label}**\n\n{value}")

    if "score" in row.index:
        st.markdown(f"**Skor:** {int(float(row.get('score') or 0))} — **Level:** {row.get('level', '-')}")
        st.caption(f"Token terdeteksi: {row.get('matched', '-')}")
    if "volume_mb" in row.index:
        st.markdown(f"**Volume:** {float(row.get('volume_mb') or 0):,.2f} MB — **Operasi:** {int(row.get('ops') or 0)}")
    if "kejadian" in row.index:
        st.markdown(f"**Jumlah kejadian ditolak:** {int(row.get('kejadian') or 0)}")

    raw_row = row
    if not sub.empty:
        raw_row = sub.sort_values("timestamp", ascending=False, kind="stable").iloc[0]
    with st.expander("📄 Log Mentah", expanded=False):
        st.json(_raw_log_json(events, raw_row))


def _clickable_table(events: pd.DataFrame, source_df: pd.DataFrame, display_df: pd.DataFrame,
                     key: str, kind: str) -> None:
    """Tabel yang bisa diklik (pilih 1 baris) lalu tampil panel detail + log mentah.

    ``source_df`` adalah output detektor (kolom utuh), ``display_df`` tampilan
    dengan urutan baris yang sama; indeks terpilih dipetakan ke ``source_df``.
    """
    if display_df.empty:
        _empty_info()
        return
    sel = st.dataframe(display_df, on_select="rerun", selection_mode="single-row", key=key, hide_index=True, width="stretch")
    rows = list(sel.selection.rows) if sel and sel.selection is not None else []
    if rows and rows[0] < len(source_df):
        _render_selected_detail(events, source_df.iloc[rows[0]], kind)


def _rules_expander(title: str, body: str) -> None:
    with st.expander(f"📏 Aturan & Ambang — {title}", expanded=True):
        st.markdown(body)


# -----------------------------------------------------------------------------
# Data loading
# -----------------------------------------------------------------------------
def _stage(tahap: str, status: str, pesan: str, mulai: float) -> dict:
    return {"tahap": tahap, "status": status, "pesan": str(pesan), "durasi_s": round(time.perf_counter() - mulai, 3)}


def _drop_unidentified_events(events: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Buang event tanpa identitas sama sekali (user/metode/perintah/resource/IP).

    Log non-audit tanpa payload identitas tampil sebagai LOG_EVENT/UNKNOWN dengan
    kolom kosong; baris seperti itu tidak informatif untuk dashboard aktivitas
    pengguna sehingga dibuang.
    """
    if events is None or events.empty:
        return events, 0
    cols = [c for c in ("principal_id", "api_method", "command", "resource_name", "source_ip") if c in events.columns]
    if not cols:
        return events, 0
    identified = pd.Series(False, index=events.index)
    for col in cols:
        identified |= events[col].fillna("").astype(str).str.strip().ne("")
    dropped = int((~identified).sum())
    return events.loc[identified].reset_index(drop=True), dropped


def _load_result(mode: str, ctx: QueryContext):
    """Muat data sambil mencatat tahapan proses (untuk panel Proses Query & Debug)."""
    stages: list[dict] = []
    t0 = time.perf_counter()
    stages.append(_stage("1. Menyiapkan konteks query", "OK", ctx.window_label, t0))
    if mode == "DEMO":
        t1 = time.perf_counter()
        df = generate_monitor_demo_events()
        stages.append(_stage("2. Membangkitkan data ilustrasi (DEMO)", "OK", f"{len(df):,} baris", t1))
        t2 = time.perf_counter()
        df = filter_dataframe(df, ctx, apply_project=False)
        stages.append(_stage("3. Menerapkan filter rentang tanggal", "OK", f"{len(df):,} baris tersisa", t2))
        t3 = time.perf_counter()
        df = ensure_canonical_event_frame(df)
        stages.append(_stage("4. Normalisasi skema event kanonik", "OK", f"{len(df.columns)} kolom", t3))
        return df, None, "", stages
    from services.pipeline import run_files
    t1 = time.perf_counter()
    files = list(st.session_state.get("mon_file_uploads") or [])
    try:
        with st.spinner(f"Menganalisis log file unggahan … ({ctx.window_label})"):
            entries, meta = parse_uploads(files)
            stages.append(_stage(
                "1b. Baca file unggahan",
                "OK",
                f"{len(meta['files'])} file · {meta['total_raw']:,} entri mentah · {len(entries):,} unik",
                time.perf_counter(),
            ))
            if meta["errors"]:
                stages.append(_stage("1c. File bermasalah", "PARTIAL", "; ".join(meta["errors"]), time.perf_counter()))
            if not entries:
                raise ValueError("tidak ada entry log valid di file yang diunggah")
            result = run_files(ctx.project_id, entries)
    except Exception as exc:  # pragma: no cover - lapisan pengaman UI
        logger.exception("Query FILE gagal: %s", exc)
        stages.append(_stage("2. Analisis file unggahan (run_files)", "ERROR", str(exc), t1))
        return ensure_canonical_event_frame(pd.DataFrame()), None, str(exc), stages
    status_gcp = "OK"
    n_kanonik = int(getattr(result, "canonical_event_count", 0) or 0)
    n_pre = int(getattr(result, "pre_filter_count", n_kanonik) or 0)
    pesan_gcp = f"status={getattr(result, 'status', '?')}; {n_kanonik:,} event kanonik"
    if n_pre != n_kanonik:
        pesan_gcp += f" (dari {n_pre:,} sebelum filter rentang/project)"
    if str(getattr(result, "status", "")) == "FAILED":
        status_gcp, pesan_gcp = "ERROR", str(getattr(result, "last_error", "") or "Analisis gagal")
    elif getattr(result, "errors", []):
        status_gcp, pesan_gcp = "ERROR", "; ".join(str(e) for e in result.errors)
    stages.append(_stage("2. Analisis file unggahan (run_files)", status_gcp, pesan_gcp, t1))
    t4 = time.perf_counter()
    for nama in dict(getattr(result, "collector_status", {}) or {}):
        nilai = str((getattr(result, "collector_status", {}) or {}).get(nama, "NOT RUN"))
        stages.append(_stage(f"3. Sumber: {nama}", "ERROR" if nilai.startswith("ERROR") else "OK", nilai, t4))
        t4 = time.perf_counter()
    events = ensure_canonical_event_frame(getattr(result, "events", pd.DataFrame()), ctx.project_id)
    stages.append(_stage("4. Normalisasi skema event kanonik", "OK", f"{len(events):,} event", t4))
    events, dropped = _drop_unidentified_events(events)
    if dropped:
        stages.append(_stage("5. Buang event tanpa identitas", "OK", f"{dropped:,} event diabaikan", time.perf_counter()))
        logger.info("FILE: %d event tanpa identitas diabaikan", dropped)
    error = ""
    if str(getattr(result, "status", "")) in {"FAILED", "PARTIAL"} and getattr(result, "last_error", ""):
        error = str(result.last_error)
    if len(events) == 0 and int(getattr(result, "raw_log_entries", 0) or 0) > 0:
        stages.append(_stage(
            "6. Perhatian",
            "PARTIAL",
            "semua event dibuang karena tidak memiliki identitas (user/metode/perintah/resource/IP) — "
            "periksa isi file log",
            time.perf_counter(),
        ))
    logger.info("%s selesai: status=%s event=%d error=%s",
                mode, getattr(result, "status", "?"), len(events), error or "-")
    return events, result, error, stages


def _current_ctx() -> QueryContext:
    today = datetime.now().date()
    return st.session_state.get("mon_query") or default_context(
        today=today, project_id=os.getenv("GCP_PROJECT_ID", "dto-asik-prod")
    )


def _range_from_entries(entries) -> tuple[date, date]:
    """Tanggal lokal (Asia/Jakarta) min/max dari isi file untuk konteks query."""
    stamps = [e.get("timestamp") for e in entries
              if isinstance(e, dict) and isinstance(e.get("timestamp"), datetime)]
    if not stamps:
        today = datetime.now().date()
        return today, today
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("Asia/Jakarta")
    except Exception:
        tz = timezone.utc

    def _local(ts):
        if getattr(ts, "tzinfo", None) is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(tz)

    low = _local(min(stamps))
    high = _local(max(stamps))
    return low.date(), high.date()


def _menu_info(page_key: str) -> str:
    """Keterangan singkat aturan untuk setiap menu (nilai diambil dari config)."""
    office = fd.office_hours_info()
    rules = fd.load_monitor_rules()
    dl = rules.get("download", {})
    vol_mb = float(dl.get("volume_threshold_mb", 1024) or 0)
    texts = {
        "ringkasan": "Ringkasan hasil deteksi dari lima aturan pemantauan.",
        "jam_kerja": f"Jam kerja: {office['working_days_label']}, pukul {office['start']}–{office['end']} WIB. Aktivitas hari kerja di luar rentang tersebut terdeteksi.",
        "hari_kerja": f"Hari kerja: {office['working_days_label']}. Aktivitas pada {office['off_days_label']} terdeteksi.",
        "download": f"Unduhan besar = total unduhan ≥ {vol_mb:,.0f} MB ({vol_mb / 1024:g} GB) dalam 1 jam per pengguna, ATAU ≥ {dl.get('ops_threshold', 100)} operasi unduh per jam.",
        "critical": f"Perintah kritikal = skor token perintah ≥ {rules.get('critical_command', {}).get('score_threshold', 60)}. Contoh terdeteksi: sudo useradd = 65; tidak terdeteksi: kubectl get pods = 20.",
        "forbidden": f"Akses ditolak berulang = ≥ {rules.get('forbidden', {}).get('threshold', 5)} kejadian akses ditolak per pengguna dalam periode query.",
        "log_mentah": "Seluruh log dalam periode terpilih. Klik baris untuk JSON asli; tersedia ekspor CSV.",
        "debug": "Diagnostik rinci: tahapan proses query, data aktif, hasil deteksi per aturan, status sumber data, konfigurasi, dan lingkungan runtime.",
    }
    return texts.get(page_key, "")


def _top10(rows: pd.DataFrame, second_col: str = "") -> pd.DataFrame:
    """Daftar maks. 10 user paling anomali dari baris deteksi (jumlah kejadian)."""
    if rows is None or rows.empty or "principal_id" not in rows.columns:
        return pd.DataFrame(columns=["principal_id", "jumlah"])
    out = rows.groupby("principal_id", dropna=False).size().reset_index(name="jumlah")
    if second_col and second_col in rows.columns:
        extra = rows.groupby("principal_id", dropna=False)[second_col].max().reset_index()
        out = out.merge(extra, on="principal_id", how="left")
    out["jumlah"] = out["jumlah"].astype(int)
    return out.sort_values("jumlah", ascending=False, kind="stable").head(10).reset_index(drop=True)


def _summary_and_top10(text_html: str, rank: pd.DataFrame, key: str,
                       value_label: str = "Jumlah", extra_cols: list[tuple[str, str]] | None = None) -> None:
    """Kotak narasi singkat + tabel top-10 user paling anomali."""
    st.markdown(f"<div class='mon-narrative'><p>{text_html}</p></div>", unsafe_allow_html=True)
    if rank.empty:
        return
    view = rank.rename(columns={"principal_id": "Identitas", "jumlah": value_label})
    if "Identitas" in view.columns:
        view["Identitas"] = view["Identitas"].map(_identity_label)
    keep = ["Identitas", value_label]
    for src, dst in (extra_cols or []):
        if src in view.columns:
            view = view.rename(columns={src: dst})
            keep.append(dst)
    st.caption("Pengguna dengan temuan terbanyak (maks. 10):")
    st.dataframe(view[keep], hide_index=True, width="stretch", key=key)


_CAT_LABELS = {
    "Luar Jam Kerja": "melakukan aktivitas di luar jam kerja resmi (Senin–Jumat, 08:00–17:00 WIB)",
    "Luar Hari Kerja": "melakukan aktivitas pada akhir pekan (Sabtu/Minggu)",
    "Download Besar": "melakukan unduhan data melebihi ambang (≥ 1 GB dalam 1 jam)",
    "Critical Command": "menjalankan perintah berisiko tinggi",
    "Forbidden/Unauthorized": "menerima akses ditolak secara berulang",
}


def _narasi_ringkasan(events: pd.DataFrame, findings: pd.DataFrame, scope: str = HUMAN_ONLY) -> str:
    """Ringkasan hasil pemantauan sesuai cakupan log yang sedang dipilih."""
    total_events = int(len(events)) if events is not None else 0
    identities = []
    if events is not None and not events.empty and "principal_id" in events.columns:
        identities = [x for x in events["principal_id"].fillna("").astype(str).str.strip().unique().tolist() if x]
    actor_label = "pengguna" if scope == HUMAN_ONLY else "identitas"
    scope_text = "hanya aktivitas manusia" if scope == HUMAN_ONLY else "seluruh log, termasuk akun layanan dan aktivitas sistem"
    if findings.empty:
        return (f"Pada periode ini tercatat <b>{total_events:,} aktivitas</b> dari <b>{len(identities)} {actor_label}</b>. "
                f"Cakupan analisis saat ini adalah <b>{scope_label(scope)}</b>, yaitu {scope_text}. "
                "Tidak terdapat temuan dari kelima aturan pemantauan.")
    bagian = []
    for cat, label in _CAT_LABELS.items():
        sub = findings[findings["kategori"] == cat]
        if sub.empty:
            continue
        orang = int(sub["user"].nunique())
        total = int(sub["jumlah"].sum())
        top_user = html.escape(str(sub.groupby("user")["jumlah"].sum().sort_values(ascending=False).index[0] or "tanpa identitas"))
        bagian.append(f"<b>{orang} {actor_label}</b> {label} — total <b>{total}</b> kejadian; terbanyak: <b>{top_user}</b>.")
    top_overall = [html.escape(str(u)) for u in findings.groupby("user")["jumlah"].sum().sort_values(ascending=False).head(3).index]
    return (
        f"Pada periode ini tercatat <b>{total_events:,} aktivitas</b> dari <b>{len(identities)} {actor_label}</b>. "
        f"Cakupan analisis saat ini adalah <b>{scope_label(scope)}</b>, yaitu {scope_text}. "
        f"Terdapat <b>{len(bagian)} kategori temuan</b>:<br><br>"
        + "<br>".join("• " + b for b in bagian)
        + "<br><br>Identitas dengan akumulasi temuan tertinggi: " + ", ".join(f"<b>{u}</b>" for u in top_overall) + "."
    )


def _process_and_set_files(files, sig: str) -> None:
    try:
        entries, meta = parse_uploads(files)
        detected = detect_project(entries) or "unknown-project"
        start_date, end_date = _range_from_entries(entries)
        new_ctx = QueryContext(
            project_id=detected,
            timezone_name="Asia/Jakarta",
            start_date=start_date, end_date=end_date,
            start_time=datetime_time(0, 0), end_time=datetime_time(23, 59, 59),
            search_text="",
        )
        if meta["errors"]:
            for err in meta["errors"]:
                st.warning(f"File bermasalah (dilewati): {err}")
        st.session_state.mon_query = new_ctx
        st.session_state.mon_file_uploads = files
        st.session_state.mon_files_sig = sig
        st.session_state.mon_data_ready = True
        st.session_state.mon_result = None
        st.session_state.mon_stages = None
        st.session_state.mon_loaded_hash = ""
        st.session_state.mon_loaded_mode = ""
        st.rerun()
    except Exception as exc:
        st.error(f"Gagal membaca file: {exc}")


def _init_sidebar(events: pd.DataFrame, error: str) -> tuple[str, str, QueryContext, str]:
    today = datetime.now().date()
    with st.sidebar:
        st.markdown(
            "<div style='display:flex;align-items:center;gap:8px;margin-bottom:2px'>"
            "<span style='font-size:1.6rem'>🛡️</span>"
            "<span style='font-size:1.15rem;font-weight:800;color:#18323A'>Security Monitoring</span></div>"
            "<div style='color:#6B7280;font-size:.78rem;margin-bottom:6px'>{}</div>".format(ORGANIZATION),
            unsafe_allow_html=True,
        )
        page = st.selectbox("Menu", [key for key, _ in PAGES], format_func=lambda k: dict(PAGES)[k], key="mon_nav")
        st.markdown(
            f"<div class='mon-menu-info'>ℹ️ {html.escape(_menu_info(page))}</div>",
            unsafe_allow_html=True,
        )
        st.divider()
        st.caption("Sumber data")
        mode = st.radio("Sumber data", ["DEMO", "FILE (Unggah)"], index=0, key="mon_mode_radio",
                        horizontal=True,
                        help="DEMO menggunakan data ilustrasi. FILE menggunakan log JSON yang diunduh dari GCP Logs Explorer.")
        st.caption("Cakupan analisis")
        scope = st.radio(
            "Cakupan analisis",
            [HUMAN_ONLY, ALL_LOGS],
            index=0,
            format_func=lambda value: "Human Only" if value == HUMAN_ONLY else "Semua Log",
            key="mon_scope_radio",
            horizontal=True,
            help="Human Only hanya menganalisis aktivitas manusia. Semua Log juga menyertakan akun layanan, sistem, otomatisasi, dan event tanpa identitas.",
        )
        if mode == "FILE (Unggah)":
            uploaded = st.file_uploader(
                "File log GCP (JSON dari Logs Explorer)",
                type=None, accept_multiple_files=True,
                key="mon_file_uploader",
                help="Unduh log di GCP Logs Explorer lewat tombol Download > JSON, lalu unggah di sini. Analisis langsung berjalan tanpa tombol Terapkan.",
            )
            if uploaded:
                files = [(f.name, f.getvalue()) for f in uploaded]
                sig = "|".join(f"{name}:{len(data)}" for name, data in files)
                if sig != st.session_state.get("mon_files_sig"):
                    _process_and_set_files(files, sig)

            local_logs = [
                f for f in sorted(os.listdir("."))
                if os.path.isfile(f) and (f.startswith("logs-") or f.endswith(".json") or f.endswith(".jsonl") or f.endswith(".ndjson"))
                and not f.startswith(".") and not f.endswith(".py")
            ]
            if local_logs:
                st.caption("Atau pilih file lokal di folder proyek:")
                for lfile in local_logs:
                    size_mb = os.path.getsize(lfile) / (1024 * 1024)
                    if st.button(f"📥 Muat {lfile} ({size_mb:.1f} MB)", key=f"btn_load_{lfile}", width="stretch"):
                        with open(lfile, "rb") as fh:
                            ldata = fh.read()
                        _process_and_set_files([(lfile, ldata)], f"local:{lfile}:{len(ldata)}")

            if st.button("🔄 Muat Ulang File", key="mon_file_reload", width="stretch"):
                st.session_state.mon_files_sig = ""
                st.rerun()
        st.divider()
        st.caption("Proses Query")
        stages = st.session_state.get("mon_stages")
        if stages:
            with st.expander("Tahapan proses terakhir", expanded=bool(error)):
                for s in stages:
                    icon = "✅" if s.get("status") == "OK" else "❌" if s.get("status") == "ERROR" else "⏳"
                    st.markdown(f"{icon} **{s.get('tahap')}** · {s.get('durasi_s')} dtk")
                    if s.get("pesan"):
                        st.caption(str(s.get("pesan"))[:220])
            if error:
                st.error("Proses analisis gagal. Detail: " + error)
        else:
            st.caption("Belum ada proses query yang dijalankan.")
        return page, mode, st.session_state.get("mon_query") or default_context(
            today=today, project_id=os.getenv("GCP_PROJECT_ID", "dto-asik-prod")
        ), scope


def _get_data(mode: str, ctx: QueryContext) -> tuple[pd.DataFrame, str]:
    # FILE hanya diproses setelah file terunggah & terparse (mon_data_ready),
    # sehingga pindah radio tidak langsung memicu analisis.
    if mode == "FILE (Unggah)" and not st.session_state.get("mon_data_ready"):
        return pd.DataFrame(), ""
    if mode != st.session_state.get("mon_loaded_mode") or ctx.query_hash != st.session_state.get("mon_loaded_hash"):
        events, result, error, stages = _load_result(mode, ctx)
        st.session_state.mon_events = events
        st.session_state.mon_error = error
        st.session_state.mon_result = result
        st.session_state.mon_stages = stages
        st.session_state.mon_loaded_mode = mode
        st.session_state.mon_loaded_hash = ctx.query_hash
    return st.session_state.get("mon_events", pd.DataFrame()), st.session_state.get("mon_error", "")


# -----------------------------------------------------------------------------
# Halaman
# -----------------------------------------------------------------------------
def _page_ringkasan(events: pd.DataFrame, mode: str, scope: str, ctx: QueryContext) -> None:
    _header("Ringkasan", "Ringkasan hasil deteksi dari lima aturan pemantauan.", _mode_label(mode, scope))
    rules = fd.load_monitor_rules()
    findings = fd.build_findings(events, rules, scope=scope)
    users = [x for x in events["principal_id"].fillna("").astype(str).str.strip().unique().tolist() if x] if not events.empty and "principal_id" in events.columns else []
    kritis = int((findings["risiko"] == "KRITIS").sum()) if not findings.empty else 0
    forbidden_count = int((findings["kategori"] == "Forbidden/Unauthorized").sum()) if not findings.empty else 0
    _kpi_cards([
        (str(len(users)), "Identitas aktif (periode)", ""),
        (str(len(findings)), "Total deteksi", ""),
        (str(kritis), "Deteksi kritis", "kritis"),
        (str(forbidden_count), "Identitas akses ditolak", "tinggi"),
    ])

    kepala, tombol = st.columns([0.78, 0.22])
    with kepala:
        st.markdown("#### Ringkasan Hasil Pemantauan")
    with tombol:
        pdf_bytes = build_monitor_pdf(events, findings, ctx, mode, scope=scope)
        st.download_button("⬇️ Unduh PDF Ringkasan", pdf_bytes,
                           file_name=f"ringkasan_pemantauan_{datetime.now():%Y%m%d_%H%M}.pdf",
                           mime="application/pdf", key="mon_pdf", width="stretch")
    st.markdown(f"<div class='mon-narrative'><p>{_narasi_ringkasan(events, findings, scope)}</p></div>", unsafe_allow_html=True)

    left, right = st.columns([1.4, 1.0])
    with left:
        st.markdown("#### Tren aktivitas harian")
        if events.empty:
            _empty_info()
        else:
            trend = fd.add_local_time(events).copy()
            trend["tanggal"] = trend["wib_time"].dt.date
            daily = trend.groupby("tanggal").size().reset_index(name="jumlah")
            daily["tanggal"] = pd.to_datetime(daily["tanggal"])
            fig = px.line(daily, x="tanggal", y="jumlah", markers=True,
                          labels={"tanggal": "Tanggal", "jumlah": "Jumlah aktivitas"},
                          color_discrete_sequence=[KEMENKES_COLORS["turquoise"]])
            fig.update_layout(height=280, margin=dict(l=10, r=10, t=10, b=10), plot_bgcolor="white")
            st.plotly_chart(fig, width="stretch", key="mon_trend_chart")
    with right:
        st.markdown("#### Kesehatan sumber log")
        if mode == "DEMO":
            st.markdown("🟢 **Demo Telemetry** — Aktif (data ilustrasi)")
        else:
            st.markdown("🟢 **File Unggahan** — log JSON dari GCP Logs Explorer (diunduh manual)")
            st.caption("Aplikasi tidak pernah mengambil data langsung dari server GCP.")

    st.markdown("#### Prioritas pemeriksaan")
    if findings.empty:
        _empty_info()
        return
    view = findings[["kategori", "user", "indikasi", "risiko", "jumlah", "waktu"]].copy()
    view["waktu"] = view["waktu"].map(_fmt_wib)
    view = view.rename(columns={"kategori": "Kategori", "user": "Identitas", "indikasi": "Indikasi",
                                "risiko": "Risiko", "jumlah": "Jumlah", "waktu": "Waktu"})
    sel = st.dataframe(view, on_select="rerun", selection_mode="single-row", key="tbl_ringkasan", hide_index=True, width="stretch")
    rows = list(sel.selection.rows) if sel and sel.selection is not None else []
    if rows and rows[0] < len(findings):
        row = findings.iloc[rows[0]]
        st.divider()
        st.markdown(f"### Detail: {row.get('kategori')} — {_identity_label(row.get('user', ''))} {_badge(row.get('risiko'))}", unsafe_allow_html=True)
        st.markdown(f"**Indikasi:** {row.get('indikasi')}")
        try:
            ids = json.loads(str(row.get("event_ids") or "[]"))
        except Exception:
            ids = []
        sub = fd.events_by_ids(events, ids)
        if not sub.empty:
            st.caption(f"{len(sub)} event terkait:")
            st.dataframe(_event_view_columns(sub), hide_index=True, width="stretch")
            top = sub.sort_values("timestamp", ascending=False, kind="stable").iloc[0]
            with st.expander("📄 Log Mentah", expanded=False):
                st.json(_raw_log_json(events, top))


def _page_office_hours(events: pd.DataFrame, mode: str, scope: str = HUMAN_ONLY) -> None:
    _header("Aktivitas di Luar Jam Kerja", "Identitas yang beraktivitas di luar jam kerja resmi.", _mode_label(mode, scope))
    info = fd.office_hours_info()
    _rules_expander("Luar Jam Kerja", (
        f"- **Jam kerja:** {info['start']}–{info['end']} WIB ({info['timezone']}) — batas akhir **inklusif** (17:00:00 masih jam kerja).\n"
        f"- **Hari kerja:** {info['working_days_label']}.\n"
        f"- **Terdeteksi:** event pada hari kerja yang terjadi sebelum {info['start']} WIB atau setelah {info['end']} WIB.\n"
        f"- Ambang dapat diubah di `config/monitor_rules.yaml`."
    ))
    rows = fd.outside_office_hours(events, scope=scope)
    users = rows["principal_id"].dropna().astype(str).unique().tolist() if not rows.empty else []
    _kpi_cards([
        (str(len(rows)), "Kejadian di luar jam kerja", ""),
        (str(len(users)), "Pengguna terlibat", ""),
        (_fmt_wib(rows["wib_time"].max()) if not rows.empty else "-", "Kejadian terakhir", ""),
    ])
    rank = _top10(rows)
    top1 = ""
    if not rank.empty:
        top1 = (f" Terbanyak: <b>{html.escape(_identity_label(rank.iloc[0]['principal_id']))}</b>"
                f" ({int(rank.iloc[0]['jumlah'])} kejadian).")
    _summary_and_top10(
        f"Jumlah aktivitas di luar jam kerja pada periode ini: <b>{len(rows)} kejadian</b> oleh "
        f"<b>{len(users)} pengguna</b> (Senin–Jumat, {info['start']}–{info['end']} WIB)." + top1,
        rank, "top10_jam_kerja",
    )
    st.markdown("#### Daftar Kejadian")
    _clickable_table(events, rows, _event_view_columns(rows), "tbl_jam_kerja", "Aktivitas di luar jam kerja")


def _page_working_days(events: pd.DataFrame, mode: str, scope: str = HUMAN_ONLY) -> None:
    _header("Aktivitas di Luar Hari Kerja", "Identitas yang beraktivitas pada akhir pekan.", _mode_label(mode, scope))
    info = fd.office_hours_info()
    _rules_expander("Luar Hari Kerja", (
        f"- **Hari kerja:** {info['working_days_label']}.\n"
        f"- **Luar hari kerja (terdeteksi):** {info['off_days_label']}.\n"
        f"- Ambang dapat diubah di `config/monitor_rules.yaml`."
    ))
    rows = fd.outside_working_days(events, scope=scope)
    users = rows["principal_id"].dropna().astype(str).unique().tolist() if not rows.empty else []
    _kpi_cards([
        (str(len(rows)), "Kejadian di luar hari kerja", ""),
        (str(len(users)), "Pengguna terlibat", ""),
        (_fmt_wib(rows["wib_time"].max()) if not rows.empty else "-", "Kejadian terakhir", ""),
    ])
    rank = _top10(rows)
    top1 = ""
    if not rank.empty:
        top1 = (f" Terbanyak: <b>{html.escape(_identity_label(rank.iloc[0]['principal_id']))}</b>"
                f" ({int(rank.iloc[0]['jumlah'])} kejadian).")
    _summary_and_top10(
        f"Jumlah aktivitas di luar hari kerja pada periode ini: <b>{len(rows)} kejadian</b> oleh "
        f"<b>{len(users)} pengguna</b> ({info['off_days_label']})." + top1,
        rank, "top10_hari_kerja",
    )
    st.markdown("#### Daftar Kejadian")
    _clickable_table(events, rows, _event_view_columns(rows), "tbl_hari_kerja", "Aktivitas di luar hari kerja")


def _page_download(events: pd.DataFrame, mode: str, scope: str = HUMAN_ONLY) -> None:
    _header("Unduhan Data Besar", "Identitas yang melakukan unduhan data dalam jumlah besar.", _mode_label(mode, scope))
    rules = fd.load_monitor_rules()
    dl = rules.get("download", {})
    _rules_expander("Unduhan Data Besar", (
        f"- **Jendela agregasi:** {dl.get('window_minutes', 60)} menit (1 jam) per pengguna.\n"
        f"- **Terdeteksi bila** total volume unduhan ≥ **{dl.get('volume_threshold_mb', 1024):,.0f} MB ({dl.get('volume_threshold_mb', 1024) / 1024:g} GB)** dalam 1 jam, "
        f"**ATAU** ≥ **{dl.get('ops_threshold', 100)} operasi unduh** dalam 1 jam (dipakai bila log tidak mencatat ukuran byte, mis. `data_volume` = 0).\n"
        f"- Operasi unduh = event `DATA_ACCESS`/`EXPORT`/`DOWNLOAD`, metode `storage.objects.get`, atau event dengan `data_volume` > 0.\n"
        f"- Ambang dapat diubah di `config/monitor_rules.yaml`."
    ))
    windows = fd.download_windows(events, rules, scope=scope)
    users = windows["principal_id"].dropna().astype(str).unique().tolist() if not windows.empty else []
    max_vol = float(windows["volume_mb"].max()) if not windows.empty else 0.0
    _kpi_cards([
        (str(len(windows)), "Jendela 1 jam terdeteksi", ""),
        (str(len(users)), "Pengguna terlibat", ""),
        (f"{max_vol:,.0f} MB", "Volume terbesar", "tinggi"),
    ])
    rank = (windows.groupby("principal_id", dropna=False)
            .agg(jumlah=("volume_mb", "sum"), operasi=("ops", "sum"))
            .reset_index().sort_values("jumlah", ascending=False, kind="stable").head(10).reset_index(drop=True))
    top1 = ""
    if not rank.empty:
        top1 = (f" Volume tertinggi: <b>{html.escape(_identity_label(rank.iloc[0]['principal_id']))}</b>"
                f" ({float(rank.iloc[0]['jumlah']):,.0f} MB).")
    vol_mb = float(dl.get("volume_threshold_mb", 1024) or 0)
    st.markdown(
        f"<div class='mon-narrative'><p>Jumlah kejadian unduhan data besar pada periode ini: "
        f"<b>{len(windows)}</b> oleh <b>{len(users)} pengguna</b> "
        f"(ambang ≥ {vol_mb:,.0f} MB dalam 1 jam, atau ≥ {dl.get('ops_threshold', 100)} operasi per jam)."
        + top1 + "</p></div>",
        unsafe_allow_html=True,
    )
    if not rank.empty:
        view = rank.copy()
        view["Volume (MB)"] = view["jumlah"].map(lambda v: f"{float(v):,.0f}")
        view["Operasi"] = view["operasi"]
        view = view.rename(columns={"principal_id": "Pengguna"})[["Pengguna", "Volume (MB)", "Operasi"]]
        view["Pengguna"] = view["Pengguna"].map(_identity_label)
        st.caption("Pengguna dengan temuan terbanyak (maks. 10):")
        st.dataframe(view, hide_index=True, width="stretch", key="top10_download")
    st.markdown("#### Jendela Unduhan Terdeteksi")
    if windows.empty:
        _empty_info()
        return
    view = windows.copy()
    view["volume_mb"] = view["volume_mb"].map(lambda v: f"{v:,.2f}")
    view["window_start_wib"] = view["window_start_wib"].map(_fmt_wib)
    view = view.rename(columns={"principal_id": "Identitas", "window_start_wib": "Mulai (WIB)",
                                "volume_mb": "Volume (MB)", "ops": "Operasi", "risiko": "Risiko"})
    view["Identitas"] = view["Identitas"].map(_identity_label)
    view = view[["Identitas", "Mulai (WIB)", "Volume (MB)", "Operasi", "Risiko"]]
    _clickable_table(events, windows, view, "tbl_download", "Download besar")


def _page_critical(events: pd.DataFrame, mode: str, scope: str = HUMAN_ONLY) -> None:
    _header("Perintah Kritikal", "Identitas yang menjalankan perintah berisiko tinggi.", _mode_label(mode, scope))
    rules = fd.load_monitor_rules()
    threshold = int(rules.get("critical_command", {}).get("score_threshold", 60))
    token_table = fd.risk_rules_table()
    _rules_expander("Perintah Kritikal", (
        f"- **Definisi kritikal:** skor gabungan token perintah ≥ **{threshold}** (= level HIGH/CRITICAL).\n"
        f"- Skor dihitung dari `config/risk_rules.yaml` (skor token dijumlahkan, maksimal 100).\n"
        f"- Contoh yang terdeteksi: `sudo useradd` = 65, `sudo nc` = 65, `sudo bash -i` = 75, `sudo iptables` = 60.\n"
        f"- Contoh yang TIDAK terdeteksi: `kubectl get pods` = 20, `chmod 644 file` = 15."
    ))
    st.markdown("#### Daftar Token Perintah Berisiko")
    token_view = token_table.rename(columns={"token": "Token", "skor": "Skor", "keterangan": "Keterangan"})
    st.dataframe(token_view, hide_index=True, width="stretch", key="tbl_token_rules")
    rows = fd.critical_command_rows(events, rules, scope=scope)
    users = rows["principal_id"].dropna().astype(str).unique().tolist() if not rows.empty else []
    top_score = int(rows["score"].max()) if not rows.empty else 0
    _kpi_cards([
        (str(len(rows)), "Perintah kritikal", ""),
        (str(len(users)), "Pengguna terlibat", ""),
        (str(top_score), "Skor tertinggi", "kritis" if top_score >= 80 else "tinggi"),
    ])
    rank = _top10(rows, second_col="score")
    top1 = ""
    if not rows.empty:
        top = rows.loc[rows["score"].idxmax()]
        top1 = (f" Skor tertinggi: <b>{html.escape(_identity_label(top['principal_id']))}</b> "
                f"(perintah \"{html.escape(str(top['command']))}\", skor {int(top['score'])}).")
    _summary_and_top10(
        f"Jumlah perintah berisiko tinggi pada periode ini: <b>{len(rows)}</b> oleh "
        f"<b>{len(users)} pengguna</b>." + top1,
        rank, "top10_critical", extra_cols=[("score", "Skor Tertinggi")],
    )
    st.markdown("#### Daftar Perintah Kritikal")
    if rows.empty:
        _empty_info()
        return
    view = rows.copy()
    view = view.rename(columns={"wib_time": "Waktu WIB", "principal_id": "Identitas", "day_label": "Hari",
                                "command": "Perintah", "score": "Skor", "level": "Level", "source_ip": "IP"})
    view["Identitas"] = view["Identitas"].map(_identity_label)
    view["Waktu WIB"] = view["Waktu WIB"].map(_fmt_wib)
    view = view[["Waktu WIB", "Hari", "Identitas", "Perintah", "Skor", "Level", "IP"]]
    _clickable_table(events, rows, view, "tbl_critical", "Critical command")


def _page_forbidden(events: pd.DataFrame, mode: str, scope: str = HUMAN_ONLY) -> None:
    _header("Akses Ditolak Berulang", "Identitas yang berulang kali mendapat akses ditolak.", _mode_label(mode, scope))
    rules = fd.load_monitor_rules()
    threshold = int(rules.get("forbidden", {}).get("threshold", 5))
    _rules_expander("Akses Ditolak Berulang", (
        f"- **Definisi kejadian ditolak:** outcome `DENIED`/`FORBIDDEN`/`UNAUTHORIZED`/`PERMISSION_DENIED` "
        f"(atau teks mengandung kata tersebut), atau `permission_granted = False` pada aktivitas non-login.\n"
        f"- Kegagalan login (`FAILURE`) **tidak** dihitung di sini — itu ranah deteksi brute force.\n"
        f"- **Terdeteksi \"sering\"** bila jumlah kejadian ditolak ≥ **{threshold}** dalam periode query.\n"
        f"- Risiko **KRITIS** bila jumlahnya ≥ {2 * threshold}.\n"
        f"- Ambang dapat diubah di `config/monitor_rules.yaml`."
    ))
    rows = fd.forbidden_users(events, rules, scope=scope)
    total_denied = 0
    if not rows.empty:
        total_denied = int(rows["kejadian"].sum())
    _kpi_cards([
        (str(len(rows)), "Pengguna terdeteksi", ""),
        (str(total_denied), "Total kejadian ditolak (pengguna terdeteksi)", ""),
        (str(int(rows["kejadian"].max())) if not rows.empty else "0", "Kejadian terbanyak (1 pengguna)", "kritis"),
    ])
    rank = (rows[["principal_id", "kejadian"]].rename(columns={"kejadian": "jumlah"})
            .sort_values("jumlah", ascending=False, kind="stable").head(10).reset_index(drop=True))
    top1 = ""
    if not rank.empty:
        top1 = (f" Terbanyak: <b>{html.escape(_identity_label(rank.iloc[0]['principal_id']))}</b>"
                f" ({int(rank.iloc[0]['jumlah'])} kejadian ditolak).")
    _summary_and_top10(
        f"Jumlah pengguna dengan akses ditolak berulang pada periode ini: <b>{len(rows)} pengguna</b> "
        f"(ambang ≥ {threshold} kejadian)." + top1,
        rank, "top10_forbidden",
    )
    st.markdown("#### Pengguna dengan Akses Ditolak Berulang")
    if rows.empty:
        _empty_info()
        return
    view = rows.copy()
    view["first_wib"] = view["first_wib"].map(_fmt_wib)
    view["last_wib"] = view["last_wib"].map(_fmt_wib)
    view = view.rename(columns={"principal_id": "Identitas", "kejadian": "Jumlah ditolak", "risiko": "Risiko",
                                "first_wib": "Pertama", "last_wib": "Terakhir"})
    view["Identitas"] = view["Identitas"].map(_identity_label)
    view = view[["Identitas", "Jumlah ditolak", "Risiko", "Pertama", "Terakhir"]]
    _clickable_table(events, rows, view, "tbl_forbidden", "Forbidden/Unauthorized")


def _page_rawlog(events: pd.DataFrame, mode: str, scope: str = HUMAN_ONLY) -> None:
    _header("Log Mentah", "Seluruh log dalam periode terpilih. Klik baris untuk JSON asli; tersedia ekspor CSV.", _mode_label(mode, scope))
    if events.empty:
        _empty_info()
        return
    local = fd.add_local_time(events)
    st.caption(
        f"Cakupan analisis: **{scope_label(scope)}**. Menampilkan **{len(local):,}** event dari data yang sudah disaring sesuai pilihan cakupan."
    )
    csv = local[["wib_time", "principal_id", "event_action", "event_outcome", "command", "api_method",
                 "resource_name", "source_ip", "event_id", "detail"]].copy()
    csv["wib_time"] = csv["wib_time"].map(_fmt_wib)
    st.download_button("⬇️ Ekspor CSV", csv.to_csv(index=False).encode("utf-8"),
                       file_name=f"monitor_log_{datetime.now():%Y%m%d_%H%M}.csv", mime="text/csv", key="mon_csv")
    view = local[["wib_time", "principal_id", "day_label", "event_action", "event_outcome", "command",
                  "resource_name", "source_ip"]].copy()
    view = view.rename(columns={"wib_time": "Waktu WIB", "principal_id": "Identitas", "day_label": "Hari",
                                "event_action": "Aktivitas", "event_outcome": "Hasil", "command": "Perintah",
                                "resource_name": "Resource", "source_ip": "IP"})
    view["Waktu WIB"] = view["Waktu WIB"].map(_fmt_wib)
    sel = st.dataframe(view, on_select="rerun", selection_mode="single-row", key="tbl_rawlog", hide_index=True,
                       height=520, width="stretch")
    rows = list(sel.selection.rows) if sel and sel.selection is not None else []
    if rows and rows[0] < len(local):
        row = local.iloc[rows[0]]
        st.divider()
        st.markdown(f"### Log Mentah — {_fmt_wib(row.get('wib_time'))} · {_identity_label(row.get('principal_id', ''))}")
        with st.expander("📄 JSON Log Mentah", expanded=True):
            st.json(_raw_log_json(events, row))


def _page_debug(events: pd.DataFrame, raw_events: pd.DataFrame, mode: str, scope: str, ctx: QueryContext) -> None:
    _header("Debug", "Diagnostik rinci: proses query, data aktif, hasil deteksi, sumber data, konfigurasi, dan lingkungan runtime.", _mode_label(mode, scope))

    st.markdown("#### 1. Konteks Query")
    st.dataframe(pd.DataFrame([{"Kunci": k, "Nilai": str(v)} for k, v in ctx.as_dict().items()]),
                 hide_index=True, width="stretch", key="dbg_ctx")

    st.markdown("#### 2. Tahapan Proses Terakhir")
    stages = st.session_state.get("mon_stages")
    if stages:
        sdf = pd.DataFrame(stages)
        sdf["durasi_s"] = sdf["durasi_s"].map(lambda v: f"{float(v):.3f}")
        sdf = sdf.rename(columns={"tahap": "Tahap", "status": "Status", "pesan": "Pesan", "durasi_s": "Durasi (detik)"})
        st.dataframe(sdf, hide_index=True, width="stretch", key="dbg_stages")
        gagal = [s for s in stages if s.get("status") == "ERROR"]
        if gagal:
            st.error("Terdapat tahap yang mengalami kegagalan. Lihat kolom Pesan pada tabel di atas.")
        else:
            st.success("Seluruh tahapan selesai tanpa kegagalan.")
    else:
        st.caption("Belum ada proses query yang dijalankan.")

    st.markdown("#### 3. Data Aktif")
    raw_counts = scope_counts(raw_events)
    info_rows = [
        ("Mode sumber data", mode),
        ("Cakupan analisis", scope_label(scope)),
        ("Jumlah event dari sumber", f"{raw_counts['total']:,}"),
        ("Jumlah event manusia", f"{raw_counts['human']:,}"),
        ("Jumlah event non-manusia", f"{raw_counts['non_human']:,}"),
        ("Jumlah event yang dianalisis", f"{len(events):,}"),
        ("Error terakhir", str(st.session_state.get("mon_error") or "-")),
    ]
    if not raw_events.empty and "timestamp" in raw_events.columns:
        info_rows.append(("Rentang waktu event", f"{_fmt_wib(raw_events['timestamp'].min())} s.d. {_fmt_wib(raw_events['timestamp'].max())}"))
    st.dataframe(pd.DataFrame(info_rows, columns=["Kunci", "Nilai"]), hide_index=True, width="stretch", key="dbg_data")

    st.markdown("#### 4. Hasil Deteksi per Aturan")
    rules = fd.load_monitor_rules()
    office = fd.office_hours_info()
    oh = fd.outside_office_hours(events, scope=scope)
    wd = fd.outside_working_days(events, scope=scope)
    dw = fd.download_windows(events, rules, scope=scope)
    cc = fd.critical_command_rows(events, rules, scope=scope)
    fb = fd.forbidden_users(events, rules, scope=scope)
    det_rows = [
        ["Aktivitas di Luar Jam Kerja", f"{office['start']}–{office['end']} WIB", len(oh), 0 if oh.empty else int(oh["principal_id"].nunique())],
        ["Aktivitas di Luar Hari Kerja", office["off_days_label"], len(wd), 0 if wd.empty else int(wd["principal_id"].nunique())],
        ["Unduhan Data Besar", f"≥ {float(rules['download'].get('volume_threshold_mb', 1024)):,.0f} MB/jam atau ≥ {rules['download'].get('ops_threshold', 100)} operasi/jam", len(dw), 0 if dw.empty else int(dw["principal_id"].nunique())],
        ["Perintah Kritikal", f"skor ≥ {rules['critical_command'].get('score_threshold', 60)}", len(cc), 0 if cc.empty else int(cc["principal_id"].nunique())],
        ["Akses Ditolak Berulang", f"≥ {rules['forbidden'].get('threshold', 5)} kejadian", len(fb), 0 if fb.empty else int(fb["principal_id"].nunique())],
    ]
    st.dataframe(pd.DataFrame(det_rows, columns=["Aturan", "Ambang", "Baris Terdeteksi", "Pengguna"]),
                 hide_index=True, width="stretch", key="dbg_deteksi")
    st.caption(f"Hasil deteksi menggunakan cakupan **{scope_label(scope)}** pada seluruh menu.")

    st.markdown("#### 5. Status Sumber Data")
    result = st.session_state.get("mon_result")
    if mode == "DEMO" or result is None:
        st.caption("Mode DEMO — data ilustrasi.")
    else:
        status_map = getattr(result, "collector_status", {}) or {}
        if status_map:
            st.dataframe(pd.DataFrame([{"Sumber": k, "Status": str(v)} for k, v in status_map.items()]),
                         hide_index=True, width="stretch", key="dbg_collectors")
        else:
            st.caption("Tidak ada data status sumber.")
        if getattr(result, "errors", []):
            st.markdown("**Daftar error:**")
            for err in result.errors:
                st.code(str(err))
        st.caption(
            f"status pipeline={getattr(result, 'status', '?')} · "
            f"completed_tasks={getattr(result, 'completed_tasks', 0)}/{getattr(result, 'total_tasks', 0)} · "
            f"entry mentah={getattr(result, 'raw_log_entries', 0):,} · "
            f"event kanonik={getattr(result, 'canonical_event_count', 0):,} "
            f"(pra-filter={getattr(result, 'pre_filter_count', 0):,})"
        )

    st.markdown("#### 6. Konfigurasi Deteksi")
    st.json(fd.load_monitor_rules())
    st.caption(f"Token perintah berisiko: {len(fd.risk_rules_table())} token (config/risk_rules.yaml).")

    st.markdown("#### 7. Struktur dan Alur Aplikasi")
    st.code("""1. Sumber data: DEMO atau file JSON GCP Cloud Logging.
2. Impor dan validasi: file dibaca, format diperiksa, lalu entri duplikat dibuang.
3. Normalisasi: setiap entri diubah menjadi event dengan skema kanonik.
4. Resolusi identitas: principal diklasifikasikan sebagai manusia, akun layanan, sistem, atau identitas lain.
5. Cakupan analisis: Human Only atau Semua Log diterapkan tanpa mengubah data sumber.
6. Analitik: waktu WIB, baseline, risiko, sesi, dan korelasi dihitung pada data terpilih.
7. Deteksi: lima aturan fokus dijalankan dengan ambang pada config/.
8. Penyajian: hasil ditampilkan pada dashboard, Log Mentah, PDF, dan Debug.

Alur ringkas: Sumber → Impor → Normalisasi → Identitas → Cakupan → Analitik → Deteksi → Penyajian""", language="text")
    st.caption("Pilihan cakupan hanya menentukan event yang dihitung oleh analitik. Event pada sumber tetap dipertahankan.")

    st.markdown("#### 8. Lingkungan Runtime")
    env_rows = [
        ("Python", platform.python_version()),
        ("Streamlit", st.__version__),
        ("pandas", pd.__version__),
        ("Zona waktu UI", "Asia/Jakarta (WIB)"),
        ("Direktori kerja", os.getcwd()),
    ]
    st.dataframe(pd.DataFrame(env_rows, columns=["Kunci", "Nilai"]), hide_index=True, width="stretch", key="dbg_env")

    st.markdown("#### 9. Session State (kunci mon_*)")
    ss = {k: str(v)[:160] for k, v in st.session_state.items() if str(k).startswith("mon_")}
    st.dataframe(pd.DataFrame([{"Kunci": k, "Nilai": v} for k, v in ss.items()]),
                 hide_index=True, width="stretch", key="dbg_session")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main() -> None:
    today = datetime.now().date()
    initial_ctx = st.session_state.get("mon_query") or default_context(
        today=today, project_id=os.getenv("GCP_PROJECT_ID", "dto-asik-prod")
    )
    initial_mode = str(st.session_state.get("mon_mode_radio", "DEMO"))
    # Data mentah dimuat sebelum sidebar dirender agar panel proses menampilkan tahap terbaru.
    raw_events, error = _get_data(initial_mode, initial_ctx)
    page_key, mode, ctx, scope = _init_sidebar(raw_events, error)
    events = filter_log_scope(raw_events, scope)

    if mode == "FILE (Unggah)" and not st.session_state.get("mon_data_ready"):
        _header("FILE (Unggah)", "Unggah file log JSON dari GCP Logs Explorer; analisis langsung berjalan.", _mode_label(mode, scope))
        st.info(
            "Mode **FILE** menganalisis log yang diunduh secara manual dari GCP Logs Explorer — "
            "aplikasi tidak pernah mengambil data langsung dari server GCP. Caranya: "
            "di GCP Logs Explorer, atur rentang waktu dan filter yang diperlukan, klik **Download > JSON**, "
            "lalu unggah file tersebut di sidebar. **Analisis langsung berjalan otomatis** "
            "begitu file terunggah — tidak perlu tombol Terapkan."
        )
        st.caption("Bisa mengunggah lebih dari satu file; entri duplikat antar file otomatis dibuang.")
        return

    if mode == "DEMO":
        st.caption("Mode DEMO: seluruh data di layar ini adalah ilustrasi sintetis untuk demonstrasi aturan deteksi.")

    if page_key == "ringkasan":
        _page_ringkasan(events, mode, scope, ctx)
    elif page_key == "jam_kerja":
        _page_office_hours(events, mode, scope)
    elif page_key == "hari_kerja":
        _page_working_days(events, mode, scope)
    elif page_key == "download":
        _page_download(events, mode, scope)
    elif page_key == "critical":
        _page_critical(events, mode, scope)
    elif page_key == "forbidden":
        _page_forbidden(events, mode, scope)
    elif page_key == "log_mentah":
        _page_rawlog(events, mode, scope)
    elif page_key == "debug":
        _page_debug(events, raw_events, mode, scope, ctx)

    st.markdown(
        "<div class='foot'>Waktu: WIB • Aturan dan ambang dijelaskan pada setiap halaman • "
        "Data DEMO bersifat ilustrasi • Deteksi berbasis aturan deterministik (bukan bukti pelanggaran)</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()

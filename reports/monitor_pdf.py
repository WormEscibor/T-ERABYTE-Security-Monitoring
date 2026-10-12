# -*- coding: utf-8 -*-
"""Generator PDF Ringkasan Hasil Pemantauan (reportlab, tanpa template eksternal).

Dokumen ditulis untuk pembaca non-teknis: narasi ringkas, rincian per aturan
dalam bahasa awam, dan daftar tindak lanjut yang disarankan.
"""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
from zoneinfo import ZoneInfo

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from engines import focused_detections as fd
from core.constants import KEMENKES_COLORS, ORGANIZATION
from core.log_scope import HUMAN_ONLY, scope_label

TEAL = colors.HexColor(KEMENKES_COLORS["turquoise"])
TEAL2 = colors.HexColor(KEMENKES_COLORS["turquoise_medium"])
LIME = colors.HexColor(KEMENKES_COLORS["lime"])
INK = colors.HexColor(KEMENKES_COLORS["ink"])
GREY = colors.HexColor(KEMENKES_COLORS["grey"])
LINE = colors.HexColor("#DDE9E8")

def _identity_label(value: object) -> str:
    text = str(value or "").strip()
    return text if text else "(tanpa identitas)"


_CAT_JUDUL = {
    "Luar Jam Kerja": "Aktivitas di Luar Jam Kerja",
    "Luar Hari Kerja": "Aktivitas di Luar Hari Kerja",
    "Download Besar": "Unduhan Data Besar",
    "Critical Command": "Perintah Berisiko Tinggi (Kritikal)",
    "Forbidden/Unauthorized": "Akses Ditolak Berulang",
}

_CAT_PENJELASAN = {
    "Luar Jam Kerja": (
        "Jam kerja yang ditetapkan adalah Senin sampai Jumat, pukul 08:00–17:00 WIB. "
        "Aktivitas yang terjadi pada hari kerja di luar rentang jam tersebut dicatat sebagai temuan."
    ),
    "Luar Hari Kerja": (
        "Hari kerja yang ditetapkan adalah Senin sampai Jumat. "
        "Aktivitas yang terjadi pada hari Sabtu dan Minggu dicatat sebagai temuan."
    ),
    "Download Besar": (
        "Unduhan data dianggap besar apabila seorang pengguna mengunduh total 1.024 MB (1 GB) "
        "atau lebih dalam rentang satu jam, atau melakukan 100 operasi unduh atau lebih dalam satu jam."
    ),
    "Critical Command": (
        "Perintah pada komputer dinilai berisiko tinggi apabila gabungan skor unsur perintahnya "
        "mencapai 60 atau lebih. Contoh perintah yang terdeteksi: 'sudo useradd' dengan skor 65."
    ),
    "Forbidden/Unauthorized": (
        "Akses yang ditolak oleh sistem dianggap perlu perhatian apabila terjadi 5 kali atau lebih "
        "pada satu pengguna dalam periode pemantauan."
    ),
}

_CAT_TINDAKAN = {
    "Luar Jam Kerja": [
        "Konfirmasi kepada pengguna mengenai alasan beraktivitas di luar jam kerja.",
        "Pastikan terdapat persetujuan atasan atau surat tugas apabila memang diperlukan.",
        "Tinjau kebijakan akses di luar jam kerja bila temuan berulang.",
    ],
    "Luar Hari Kerja": [
        "Konfirmasi kepada pengguna mengenai alasan beraktivitas pada akhir pekan.",
        "Pastikan pekerjaan akhir pekan tercatat dan disetujui.",
        "Tinjau kebijakan akses akhir pekan bila temuan berulang.",
    ],
    "Download Besar": [
        "Verifikasi keperluan dan tujuan unduhan data kepada pengguna terkait.",
        "Cocokkan dengan tiket pekerjaan atau perubahan yang disetujui.",
        "Periksa tujuan pengiriman data; blokir dan investigasi apabila tidak dikenal.",
    ],
    "Critical Command": [
        "Konfirmasi kepada pemilik akun mengenai perintah yang dijalankan.",
        "Periksa kesesuaian dengan tiket perubahan yang berlaku.",
        "Ganti kata sandi akun dan periksa sesi aktif apabila aktivitas mencurigakan.",
    ],
    "Forbidden/Unauthorized": [
        "Tinjau hak akses dan peran pengguna yang bersangkutan.",
        "Identifikasi apakah percobaan akses berasal dari pengguna atau pihak tidak sah.",
        "Waspadai pola berulang yang mengindikasikan percobaan akses tidak sah.",
    ],
}


def _per_kategori(findings: pd.DataFrame) -> list[dict]:
    rows = []
    for cat in ["Luar Jam Kerja", "Luar Hari Kerja", "Download Besar", "Critical Command", "Forbidden/Unauthorized"]:
        sub = findings[findings["kategori"] == cat]
        if sub.empty:
            continue
        total = int(sub["jumlah"].sum())
        users = int(sub["user"].nunique())
        top = (sub.groupby("user")["jumlah"].sum().sort_values(ascending=False)
               .head(3).reset_index().values.tolist())
        top = [[_identity_label(user), count] for user, count in top]
        rows.append({"kategori": cat, "pengguna": users, "kejadian": total, "top": top})
    return rows


def build_monitor_pdf(events: pd.DataFrame, findings: pd.DataFrame, ctx, mode: str, scope: str = HUMAN_ONLY) -> bytes:
    """Susun PDF ringkasan dan kembalikan sebagai bytes."""
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("mh1", parent=styles["Heading1"], textColor=TEAL, fontSize=17, leading=21, spaceAfter=2)
    h2 = ParagraphStyle("mh2", parent=styles["Heading2"], textColor=INK, fontSize=12.5, leading=16, spaceBefore=12, spaceAfter=4)
    h3 = ParagraphStyle("mh3", parent=styles["Heading3"], textColor=INK, fontSize=11, leading=14, spaceBefore=8, spaceAfter=2)
    body = ParagraphStyle("mbody", parent=styles["BodyText"], fontSize=10, leading=14.5, spaceAfter=6, textColor=INK)
    bullet = ParagraphStyle("mbullet", parent=body, leftIndent=14, bulletIndent=4, spaceAfter=3)
    small = ParagraphStyle("msmall", parent=styles["BodyText"], fontSize=8.5, leading=11.5, textColor=GREY)
    meta = ParagraphStyle("mmeta", parent=styles["BodyText"], fontSize=9.5, leading=13, textColor=GREY)

    kategori = _per_kategori(findings)
    n_events = int(len(events))
    principal = events["principal_id"].fillna("").astype(str).str.strip() if not events.empty and "principal_id" in events.columns else pd.Series(dtype=str)
    n_identities = int(principal[principal.ne("")].nunique()) if not principal.empty else 0
    cakupan = scope_label(scope)
    now_wib = datetime.now(ZoneInfo("Asia/Jakarta"))

    story = []
    story.append(Paragraph("Ringkasan Hasil Pemantauan Aktivitas Pengguna", h1))
    story.append(Paragraph(ORGANIZATION, meta))
    story.append(Paragraph(f"Periode pemantauan: {ctx.window_label}", meta))
    story.append(Paragraph(f"Dokumen dibuat: {now_wib:%d %B %Y, %H:%M WIB} · Sumber data: {'DEMO (data ilustrasi)' if mode == 'DEMO' else 'FILE (log unggahan)'}", meta))
    story.append(Paragraph(f"Cakupan analisis: {cakupan}", meta))
    story.append(Spacer(1, 8))

    # --- 1. Ringkasan umum ---
    story.append(Paragraph("1. Ringkasan Umum", h2))
    if not kategori:
        story.append(Paragraph(
            f"Pada periode pemantauan ini tercatat {n_events:,} event dari {n_identities} identitas yang memiliki pengenal. "
            + ("Analisis dibatasi pada aktivitas manusia." if scope == HUMAN_ONLY else "Analisis mencakup seluruh log, termasuk akun layanan, aktivitas sistem, otomatisasi, dan event tanpa identitas.") + " "
            + "Tidak terdapat temuan dari kelima aturan pemantauan, sehingga aktivitas pada periode ini "
            + "tidak menunjukkan temuan dari kelima aturan dan tidak memerlukan tindak lanjut khusus.", body))
    else:
        story.append(Paragraph(
            f"Pada periode pemantauan ini tercatat {n_events:,} event dari {n_identities} identitas yang memiliki pengenal. "
            + ("Analisis dibatasi pada aktivitas manusia." if scope == HUMAN_ONLY else "Analisis mencakup seluruh log, termasuk akun layanan, aktivitas sistem, otomatisasi, dan event tanpa identitas.") + " "
            + f"Dari kelima aturan pemantauan yang diterapkan, terdapat {len(kategori)} kategori temuan "
            + "yang memerlukan perhatian. Rincian setiap kategori dijelaskan pada bagian berikutnya.", body))
        top_overall = findings.groupby("user")["jumlah"].sum().sort_values(ascending=False).head(3)
        story.append(Paragraph("Identitas dengan akumulasi temuan tertinggi: " +
                               ", ".join(_identity_label(u) for u in top_overall.index) + ".", body))

        table_rows = [["Kategori", "Ambang", "Pengguna", "Kejadian"]]
        ambang = {
            "Luar Jam Kerja": "di luar 08:00–17:00 WIB (Senin–Jumat)",
            "Luar Hari Kerja": "Sabtu/Minggu",
            "Download Besar": "≥ 1 GB per jam atau ≥ 100 operasi/jam",
            "Critical Command": "skor perintah ≥ 60",
            "Forbidden/Unauthorized": "≥ 5 kejadian per identitas",
        }
        for item in kategori:
            table_rows.append([_CAT_JUDUL[item["kategori"]], ambang[item["kategori"]], str(item["pengguna"]), str(item["kejadian"])])
        table = Table(table_rows, colWidths=[52 * mm, 52 * mm, 28 * mm, 26 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), TEAL),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, LINE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F8F7")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(Spacer(1, 4))
        story.append(table)

    # --- 2. Rincian per aturan ---
    if kategori:
        story.append(Paragraph("2. Rincian Temuan per Aturan", h2))
        for i, item in enumerate(kategori, 1):
            story.append(Paragraph(f"2.{i} {_CAT_JUDUL[item['kategori']]}", h3))
            story.append(Paragraph(_CAT_PENJELASAN[item["kategori"]], body))
            top_text = "; ".join(f"{str(u)} ({int(n)} kejadian)" for u, n in item["top"])
            story.append(Paragraph(
                f"Sebanyak {item['pengguna']} identitas terdeteksi pada kategori ini dengan total "
                f"{item['kejadian']} kejadian. Identitas dengan kejadian terbanyak: {top_text}.", body))

    # --- 3. Tindak lanjut yang disarankan ---
    story.append(Paragraph("3. Tindak Lanjut yang Disarankan", h2))
    story.append(Paragraph("Langkah umum yang disarankan untuk seluruh temuan:", body))
    for langkah in [
        "Konfirmasi kepada pemilik akun mengenai aktivitas yang terdeteksi.",
        "Periksa kesesuaian aktivitas dengan tiket pekerjaan atau persetujuan yang berlaku.",
        "Catat hasil verifikasi sebagai dokumentasi resmi.",
        "Eskalasi kepada tim keamanan apabila aktivitas tidak dapat dijelaskan.",
    ]:
        story.append(Paragraph(langkah, bullet, bulletText="•"))
    if kategori:
        story.append(Paragraph("Langkah khusus per kategori:", body))
        for item in kategori:
            story.append(Paragraph(_CAT_JUDUL[item["kategori"]], h3))
            for tindakan in _CAT_TINDAKAN[item["kategori"]]:
                story.append(Paragraph(tindakan, bullet, bulletText="•"))

    # --- 4. Informasi tambahan ---
    story.append(Paragraph("4. Informasi Tambahan", h2))
    story.append(Paragraph(
        f"Deteksi dilakukan dengan aturan yang deterministik (ambang tetap) pada cakupan {cakupan}; temuan pada dokumen ini "
        "bukan bukti pelanggaran, melainkan daftar aktivitas yang perlu diverifikasi. "
        "Ambang setiap aturan dapat disesuaikan pada berkas konfigurasi config/monitor_rules.yaml.", body))
    if mode == "DEMO":
        story.append(Paragraph("Catatan: dokumen ini dibuat dari data DEMO yang bersifat ilustrasi dan tidak merepresentasikan kondisi produksi.", small))

    def _footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GREY)
        canvas.drawString(18 * mm, 10 * mm, "Security Monitoring · Ringkasan Hasil Pemantauan Aktivitas Pengguna")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Halaman {canvas.getPageNumber()}")
        canvas.restoreState()

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="Ringkasan Hasil Pemantauan Aktivitas Pengguna",
        author="Security Monitoring",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()

# Laporan Validasi Rilis — Security Monitoring (T-ERABYTE) 1.1.0

## Dataset
- Berkas: `logs-20261007-161759`
- Format: JSON Cloud Logging
- Entri mentah terbaca: **10.000**
- Status pipeline: **COMPLETED**
- Error pipeline: **0**
- Event kanonik: **10.000**

## Klasifikasi identitas
- Total event: **10,000**
- Event manusia: **0**
- Event non-manusia: **10,000**

Jenis identitas pada dataset:

| Jenis | Jumlah |
|---|---:|
| SERVICE ACCOUNT | 9,973 |
| SYSTEM | 27 |

## Hasil berdasarkan cakupan

| Cakupan | Event dianalisis | Luar Jam Kerja | Luar Hari Kerja | Unduhan Besar | Perintah Kritikal | Akses Ditolak Berulang |
|---|---:|---:|---:|---:|---:|---:|
| HUMAN ONLY | 0 | 0 | 0 | 0 | 0 | 0 |
| ALL LOGS | 10,000 | 6,168 | 0 | 0 | 0 | 1 |

## Pengujian source
- `python -m compileall -q .` → **PASS**
- `PYTHONPATH=. pytest -q` → **25 passed**
- Import seluruh modul non-UI → **PASS**
- Pemeriksaan istilah informal pada dokumen dan antarmuka → **PASS**
- Pemeriksaan sisa opsi penyaringan lama pada Log Mentah → **PASS**
- Pembuatan PDF untuk kedua cakupan → **PASS**

## Catatan lingkungan
- Smoke test Streamlit tidak dapat dijalankan pada lingkungan pemeriksaan karena paket Streamlit tidak tersedia dan lingkungan tidak memiliki akses jaringan untuk memasangnya.
- Dependency proyek mencantumkan `streamlit>=1.56.0,<2.0.0`; launcher akan menyiapkan virtual environment dan memasang dependency tersebut pada mesin target.

## Kesimpulan
Source telah melewati pemeriksaan sintaks, unit test, regresi cakupan, validasi dataset nyata, import modul inti, pemeriksaan bahasa antarmuka, dan pembuatan PDF. Satu-satunya pemeriksaan yang tidak dapat dieksekusi pada lingkungan ini adalah render runtime Streamlit karena dependency UI tidak tersedia secara lokal.

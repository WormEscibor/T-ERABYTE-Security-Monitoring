# Security Monitoring (T-ERABYTE)

Dashboard pemantauan aktivitas berbasis **log GCP Cloud Logging yang diunduh secara manual** dari Logs Explorer. Aplikasi berjalan secara lokal dengan Streamlit dan tidak mengambil data secara langsung dari server GCP.

## Cakupan analisis

Seluruh menu analisis menggunakan pilihan cakupan yang sama pada sidebar:

| Cakupan | Perilaku |
|---|---|
| **Human Only** | Hanya menghitung event yang memiliki identitas dengan ciri pengguna manusia. Akun layanan, sistem, otomatisasi, dan event tanpa identitas tidak masuk perhitungan. |
| **Semua Log** | Mengikutsertakan seluruh event yang berhasil dinormalisasi, termasuk akun layanan, sistem, otomatisasi, dan event tanpa identitas. |

Pilihan cakupan hanya mengatur data yang dianalisis. **Data sumber tetap utuh dan tidak dihapus.** Cakupan aktif selalu ditampilkan pada setiap menu serta dicantumkan pada laporan PDF.

## Deteksi

| Menu | Aturan (ambang dapat diubah di `config/monitor_rules.yaml`) |
|---|---|
| Aktivitas di Luar Jam Kerja | Hari kerja **Senin–Jumat**, jam kerja **08:00–17:00 WIB** (inklusif). Aktivitas hari kerja di luar rentang tersebut terdeteksi. |
| Aktivitas di Luar Hari Kerja | Aktivitas pada **Sabtu/Minggu** terdeteksi. |
| Unduhan Data Besar | Total unduhan **≥ 1.024 MB (1 GB) dalam 1 jam** per identitas, atau **≥ 100 operasi unduh per jam** apabila log tidak mencatat ukuran data. |
| Perintah Kritikal | Skor gabungan token perintah (`config/risk_rules.yaml`) **≥ 60**. Contoh: `sudo useradd` = 65. |
| Akses Ditolak Berulang | Outcome `DENIED`/`FORBIDDEN`/`UNAUTHORIZED`/`PERMISSION_DENIED` atau `permission_granted=False` (non-login) **≥ 5 kali** per identitas. |

Setiap menu menampilkan ringkasan hasil, daftar identitas dengan temuan terbanyak, tabel yang dapat dipilih untuk melihat detail, serta JSON log mentah. Halaman **Ringkasan** menyediakan ekspor **PDF** yang mencantumkan cakupan analisis.

## Cara pakai

1. Di **GCP Console > Logging > Logs Explorer**, atur project, rentang waktu, dan filter yang diperlukan, kemudian pilih **Download > JSON**.
2. Buka aplikasi, pilih **Data Source: FILE (Unggah)**, lalu unggah satu atau beberapa file JSON dari Logs Explorer.
3. Analisis berjalan otomatis setelah file tersedia. Project dan rentang waktu dideteksi dari isi log.
4. Pilih **Human Only** atau **Semua Log** pada bagian **Cakupan analisis** untuk menentukan ruang lingkup seluruh menu.
5. Buka **Debug** untuk melihat tahapan proses, struktur aplikasi, alur ringkas, jumlah event manusia/non-manusia, hasil lima deteksi, konfigurasi, dan lingkungan runtime.

Entri duplikat antarfile otomatis dibuang. Format yang didukung: JSON array dari Logs Explorer, JSON Lines (NDJSON), atau satu objek JSON. Batas ukuran unggahan mengikuti `.streamlit/config.toml`.

## Instalasi

### Windows

1. Ekstrak arsip ke folder tujuan.
2. Klik dua kali **`run_dashboard.bat`**.
3. Pada penggunaan pertama, launcher menyiapkan virtual environment dan memasang dependency dari `requirements.txt` jika diperlukan.
4. Dashboard tersedia pada `http://127.0.0.1:1500` selama port tersebut belum digunakan.

### Linux/macOS

Jalankan **`run_dashboard.sh`** atau **`run_dashboard.command`**. Port default adalah `1500`.

Tidak diperlukan kredensial GCP, `gcloud`, atau koneksi API GCP untuk menganalisis file yang sudah diunduh.

## Mode DEMO

Mode default menampilkan data ilustrasi sintetis yang dirancang untuk memicu kelima deteksi. Data DEMO tidak merepresentasikan kondisi produksi.

## Pengujian

```bash
PYTHONPATH=. pytest -q
```

Dataset validasi yang digunakan pada rilis ini adalah `logs-20261007-161759`.

## Struktur dan alur aplikasi

```text
Sumber log (DEMO / FILE JSON)
        ↓
Impor & validasi
        ↓
Normalisasi event ke skema kanonik
        ↓
Resolusi identitas
        ↓
Pilihan cakupan: Human Only / Semua Log
        ↓
Waktu lokal WIB + baseline + risiko + sesi + korelasi
        ↓
Lima deteksi fokus
        ↓
Dashboard / Log Mentah / PDF / Debug
```

| Path | Peran |
|---|---|
| `app.py` | Antarmuka Streamlit dan navigasi seluruh menu |
| `core/event_schema.py` | Skema event kanonik dan normalisasi kolom |
| `core/log_scope.py` | Aturan terpusat untuk Human Only / Semua Log |
| `engines/identity.py` | Klasifikasi dan resolusi identitas |
| `engines/focused_detections.py` | Lima fungsi deteksi murni dan agregasi temuan |
| `services/pipeline.py` | Pipeline impor, normalisasi, dan pemrosesan data |
| `services/file_import.py` | Impor serta validasi JSON/JSONL |
| `services/monitor_demo.py` | Generator data ilustrasi |
| `reports/monitor_pdf.py` | Generator laporan PDF |
| `config/monitor_rules.yaml` | Ambang dan aturan deteksi |
| `config/risk_rules.yaml` | Token risiko perintah |
| `tests/` | Pengujian otomatis |

## Catatan keamanan

Deteksi berbasis aturan bersifat indikatif. Temuan bukan bukti pelanggaran dan tetap memerlukan verifikasi oleh analis. Log produksi sebaiknya dikelola sesuai kebijakan retensi, klasifikasi informasi, dan pengendalian akses organisasi.

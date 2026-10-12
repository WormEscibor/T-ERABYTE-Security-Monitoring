# Panduan Instalasi — Security Monitoring (T-ERABYTE)

Aplikasi analisis log berbasis **file unggahan** (JSON yang diunduh manual dari
GCP Logs Explorer). Tidak ada koneksi ke server GCP — tidak butuh kredensial,
gcloud, atau peran IAM apa pun.

## 1. Prasyarat

- Windows 10/11 dengan **Python 3.10–3.14** terpasang
  (cek: `python --version`; disarankan 3.11+).
- Koneksi internet pada pemasangan pertama (unduh dependency).
- Akses ke GCP Console untuk mengunduh log (dilakukan manual, bukan oleh aplikasi).

## 2. Pemasangan Aplikasi

1. Ekstrak arsip ZIP ke folder, misalnya `C:\Tools\security-monitoring`.
2. Klik dua kali **`run_dashboard.bat`**.
3. Tunggu hingga browser terbuka otomatis. Pada jalankan pertama, proses
   pembuatan `.venv` dan pemasangan dependency berlangsung beberapa menit.
4. Setelah selesai, aplikasi dapat diakses di `http://127.0.0.1:1500`
   (atau port berikutnya bila 1500 terpakai).

## 3. Mengunduh Log dari GCP (manual)

1. Buka **GCP Console > Logging > Logs Explorer**.
2. Pilih project, rentang waktu, dan filter yang diperlukan.
3. Klik **Download > JSON**, simpan file.

## 4. Cakupan Analisis

Pada sidebar tersedia satu pilihan cakupan yang berlaku untuk seluruh menu:

- **Human Only** — hanya aktivitas yang teridentifikasi sebagai aktivitas manusia.
- **Semua Log** — seluruh event yang berhasil dinormalisasi, termasuk akun layanan, sistem, otomatisasi, dan event tanpa identitas.

Pilihan ini hanya mengatur data yang dianalisis. Data sumber tetap dipertahankan.

## 5. Penggunaan

1. Buka aplikasi, pilih **Data Source: FILE (Unggah)** di sidebar kiri.
2. Unggah file JSON hasil unduhan (bisa lebih dari satu file; format JSON
   array, JSON Lines, atau satu objek JSON).
3. **Analisis langsung berjalan otomatis** begitu file terunggah — tidak ada
   tombol Terapkan, input project, atau rentang tanggal. Project dan rentang
   dideteksi dari isi file.
4. Tahapan proses terlihat pada panel **Proses Query** di sidebar; bila ada
   kegagalan, tahap yang gagal ditandai ❌ beserta pesannya.
5. Buka menu **Debug** untuk diagnostik lengkap.

## 6. Pemecahan Masalah

| Gejala | Penyebab / Solusi |
|---|---|
| "Tidak ada entry log valid" saat mengunggah | File bukan ekspor JSON Logs Explorer. Unduh ulang lewat **Download > JSON**. |
| "Semua event dibuang karena tidak memiliki identitas" | File berisi log tanpa identitas (user/metode/resource) — periksa panel Proses Query dan isi file. |
| File besar ditolak | Batas unggahan 2 GB (`.streamlit/config.toml` > `maxUploadSize`). Pecah unduhan menjadi beberapa file bila perlu. |
| Browser tidak terbuka | Buka manual `http://127.0.0.1:1500`. |
| Port 1500 terpakai | Launcher otomatis memilih port 1501–1519; lihat URL yang tercetak di jendela launcher. |
| Perintah eksekusi VM tidak muncul di menu Perintah Kritikal | Pastikan Ops Agent mengirim auditd ke Cloud Logging (lihat `setup_auditd.sh` dan `ops_agent_config.yaml`), lalu sertakan log tersebut saat mengunduh JSON. |

## 7. Kalibrasi Ambang

Seluruh ambang deteksi berada di `config/monitor_rules.yaml`:

```yaml
office_hours:
  start: '08:00'
  end: '17:00'
  working_days: [0, 1, 2, 3, 4]   # Senin–Jumat
download:
  volume_threshold_mb: 1024       # 1 GB per jam
  ops_threshold: 100
critical_command:
  score_threshold: 60
forbidden:
  threshold: 5
```

Ubah nilai, simpan, lalu klik **↺ Reset** atau **✅ Terapkan** di aplikasi.

# Security Monitoring — Lima Deteksi Fokus + Log Mentah

Aplikasi utama (`app.py`) adalah dashboard Streamlit untuk analisis log GCP Cloud Logging yang diunduh secara manual. Aplikasi tidak mengambil log langsung dari server GCP.

## Cakupan analisis

Cakupan tersedia pada seluruh menu melalui satu pilihan bersama:

- **Human Only**: hanya event dengan identitas yang terindikasi sebagai manusia.
- **Semua Log**: seluruh event kanonik, termasuk akun layanan, sistem, otomatisasi, dan event tanpa identitas.

Sumber log tidak dimodifikasi. Cakupan hanya menentukan subset yang dikirim ke mesin deteksi dan perhitungan dashboard.

## Interaksi utama

Semua tabel hasil deteksi dapat dipilih untuk membuka detail dan JSON log mentah. Halaman **Log Mentah** mengikuti cakupan aktif sehingga daftar event yang ditampilkan konsisten dengan menu analitik lainnya. Halaman **Debug** menampilkan konteks query, tahapan proses, struktur dan alur aplikasi, distribusi identitas, hasil tiap deteksi, konfigurasi, serta lingkungan runtime.

## Aturan & ambang deteksi

| Deteksi | Aturan |
|---|---|
| Luar jam kerja | Hari kerja Senin–Jumat, di luar 08:00–17:00 WIB. |
| Luar hari kerja | Sabtu dan Minggu. |
| Unduhan data besar | ≥ 1.024 MB dalam satu jam atau ≥ 100 operasi unduh dalam satu jam. |
| Perintah kritikal | Skor token risiko ≥ 60. |
| Akses ditolak berulang | ≥ 5 kejadian penolakan per identitas, dengan login gagal dikecualikan. |

## Alur pengolahan

```text
Impor file → validasi → deduplikasi → normalisasi event → resolusi identitas
→ pilih cakupan → perhitungan waktu/risiko/sesi → lima deteksi → penyajian hasil
```

## Validasi rilis

Dataset `logs-20261007-161759` digunakan untuk menguji jalur impor file, normalisasi event, klasifikasi identitas, penyaringan cakupan, kelima aturan deteksi, dan pembuatan laporan PDF.

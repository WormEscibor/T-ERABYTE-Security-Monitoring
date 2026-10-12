# Catatan Rilis — Security Monitoring (T-ERABYTE)

## 1.1.0 — 7 Oktober 2026

### Cakupan analisis log
- Menambahkan pilihan **Human Only** dan **Semua Log** yang berlaku secara konsisten pada seluruh menu analisis.
- **Human Only** hanya menghitung aktivitas dengan identitas yang terindikasi sebagai manusia.
- **Semua Log** mencakup akun layanan, aktivitas sistem, otomatisasi, dan event yang tidak memiliki identitas.
- Penyaringan dilakukan pada lapisan analisis; data sumber tetap utuh dan tidak dihapus.
- Memperbaiki klasifikasi identitas agar `UNKNOWN` tidak lagi menghentikan proses resolusi identitas dan `system@google.com` tidak keliru dianggap sebagai pengguna manusia.

### Antarmuka dan dokumentasi
- Menyamakan tampilan aktif sumber data dan cakupan analisis pada seluruh menu.
- Menggunakan token warna Kementerian Kesehatan Republik Indonesia dari `core/constants.py` untuk tampilan utama dan laporan PDF.
- Menambahkan penjelasan struktur dan alur aplikasi pada menu **Debug**.
- Menyesuaikan istilah antarmuka agar formal, jelas, dan konsisten dalam bahasa Indonesia.

### Pengujian
- Menambahkan pengujian unit untuk Human Only/All Logs dan kompatibilitas parameter lama.
- Pengujian terhadap dataset `logs-20261007-161759` digunakan sebagai validasi alur impor, normalisasi, klasifikasi identitas, cakupan analisis, dan lima aturan deteksi.

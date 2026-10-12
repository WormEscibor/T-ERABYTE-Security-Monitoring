#!/bin/bash
# Script ini menyiapkan auditd untuk mencatat event eksekusi proses.
# Jalankan hanya pada VM yang menjadi kewenangan organisasi.

set -euo pipefail

# Memastikan script dijalankan sebagai root.
if [ "$(id -u)" -ne 0 ]; then
    echo "Jalankan script sebagai root."
    exit 1
fi

# Memasang auditd berdasarkan package manager yang tersedia.
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y auditd audispd-plugins
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y audit audit-libs
elif command -v yum >/dev/null 2>&1; then
    yum install -y audit audit-libs
else
    echo "Package manager tidak dikenali."
    exit 1
fi

# Mengaktifkan service auditd.
systemctl enable auditd
systemctl start auditd

# Membuat rule eksekusi proses untuk arsitektur umum.
cat >/etc/audit/rules.d/gcp-user-behavior.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -k gcp_command_exec
-a always,exit -F arch=b32 -S execve -k gcp_command_exec
EOF

# Memuat rule auditd.
augenrules --load || true

echo "Auditd siap digunakan."
echo "Konfigurasikan Ops Agent untuk mengirim /var/log/audit/audit.log ke Cloud Logging."

#!/bin/bash
set -euo pipefail

#--------------------------------
# Ensure script runs as root
#--------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Exiting."
    exit 1
fi

# -----------------------------
# Configuration Variables 
# -----------------------------
EMAIL="you@yourhost.com"
SCAN_DIR="/"
QUARANTINE_DIR="/var/lib/clamav/quarantine"
LOG_DIR="/var/log/clamav"
CHECKPOINT="/var/lib/clamav/scan_checkpoint"
MEMORY_LIMIT="4G"
WEEKLY_REPORT="$LOG_DIR/weekly_report.log"

# -----------------------------
# Step 1: Install Packages
# -----------------------------
echo "[+] Installing ClamAV packages..."
dnf install -y clamav clamav-update clamd

# ---------------------------------
# Step 2: Enable & start services
# ---------------------------------
echo "[+] Enabling freshclam..."
systemctl enable --now freshclam

echo "[+] Ensuring clamd notify is enabled..."
grep -q '^NotifyClamd yes' /etc/clamd.d/scan.conf || \
    echo "NotifyClamd yes" >> /etc/clamd.d/scan.conf

echo "[+] Enabling and starting clamd..."
systemctl enable --now clamd@scan

# -------------------------------
# Step 3: Apply systemd override
# -------------------------------
echo "[+] Creating systemd override..."
mkdir -p /etc/systemd/system/clamd@scan.service.d
cat > /etc/systemd/system/clamd@scan.service.d/override.conf <<EOF
[Service]
CPUSchedulingPolicy=idle
Nice=19
IOSchedulingClass=idle
IOSchedulingPriority=7
MemoryMax=${MEMORY_LIMIT}
EOF

systemctl daemon-reload
systemctl restart clamd@scan

# -----------------------------
# Step 4: Create directories
# -----------------------------
echo "[+] Creating directories..."
for DIR in "$QUARANTINE_DIR" "$LOG_DIR"; do
    mkdir -p "$DIR"
    chown -R clamscan:clamscan "$DIR"
    chmod 0750 "$DIR"
done

# -----------------------------
# Step 5: Deploy hourly scan script with injected variables
# -----------------------------
echo "[+] Deploying hourly scan script..."
cat > /usr/local/bin/hourly_secure_scan.sh <<EOF
#!/bin/bash
set -euo pipefail

# -----------------------------
# Configuration (injected)
# -----------------------------
SCAN_DIR="${SCAN_DIR}"
CHECKPOINT="${CHECKPOINT}"
LOG_FILE="${LOG_DIR}/hourly_audit.log"
QUARANTINE_DIR="${QUARANTINE_DIR}"
EMAIL="${EMAIL}"
CONFIG="/etc/clamd.d/scan.conf"
WEEKLY_REPORT="${WEEKLY_REPORT}"

# -----------------------------
# Concurrency lock
# -----------------------------
LOCK_FILE="/var/run/hourly_secure_scan.lock"
exec 200>\$LOCK_FILE
flock -n 200 || exit 0

# -----------------------------
# Temporary file for scan list
# -----------------------------
LIST_FILE=\$(mktemp -t clamscan.XXXXXX)
trap 'rm -f "\$LIST_FILE"' EXIT

# -----------------------------
# Build file list (incremental)
# -----------------------------
if [ ! -f "\$CHECKPOINT" ]; then
    find "\$SCAN_DIR" -type f \
        -not -path "/proc/*" \
        -not -path "/sys/*" \
        -not -path "/dev/*" \
        -not -path "/run/*" \
        -print > "\$LIST_FILE"
else
    find "\$SCAN_DIR" -type f \
        \( -newer "\$CHECKPOINT" -o -cnewer "\$CHECKPOINT" \) \
        -not -path "/proc/*" \
        -not -path "/sys/*" \
        -not -path "/dev/*" \
        -not -path "/run/*" \
        -print > "\$LIST_FILE"
fi

TOTAL_FILES=\$(wc -l < "\$LIST_FILE")
INFECTED=0

# -----------------------------
# Scan and move infected files
# -----------------------------
if [ -s "\$LIST_FILE" ]; then
    clamdscan \
        -c "\$CONFIG" \
        --fdpass \
        --multiscan \
        --move="\$QUARANTINE_DIR" \
        --file-list="\$LIST_FILE" \
        --log="\$LOG_FILE"

    if grep -q "Infected files: [1-9]" "\$LOG_FILE"; then
        INFECTED=\$(grep "Infected files:" "\$LOG_FILE" | awk '{print \$3}')
        grep "FOUND" "\$LOG_FILE" | mail -s "SECURITY ALERT on \$(hostname)" "\$EMAIL"
    fi
fi

# -----------------------------
# Append scan stats to weekly report
# -----------------------------
echo "\$(date '+%Y-%m-%d %H:%M:%S') Files scanned: \$TOTAL_FILES, Infected: \$INFECTED" >> "\$WEEKLY_REPORT"

# -----------------------------
# Update checkpoint
# -----------------------------
touch "\$CHECKPOINT"
EOF

chmod 700 /usr/local/bin/hourly_secure_scan.sh

# -----------------------------
# Step 6: SELinux configuration
# -----------------------------
if [ "$(getenforce)" = "Enforcing" ]; then
    echo "[+] SELinux is enforcing — setting ClamAV booleans..."
    setsebool -P clamav_can_scan_system 1
    setsebool -P clamd_use_jit 1
else
    echo "[+] SELinux not enforcing — skipping SELinux configuration"
fi

# -----------------------------
# Step 7: Configure log rotation
# -----------------------------
echo "[+] Configuring log rotation..."
cat > /etc/logrotate.d/clamav-hourly <<EOF
/var/log/clamav/hourly_audit.log {
    rotate 30
    daily
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/bin/systemctl restart clamd@scan > /dev/null 2>/dev/null || true
    endscript
}
EOF

# -----------------------------
# Step 8: Prime virus definitions
# -----------------------------
echo "[+] Updating virus definitions..."
freshclam || true

# -----------------------------
# Step 9: Weekly report email cron
# -----------------------------
echo "[+] Setting up weekly report email cron..."
(crontab -l 2>/dev/null; echo "59 23 * * 0 mail -s 'Weekly ClamAV Report on \$(hostname)' $EMAIL < $WEEKLY_REPORT && > $WEEKLY_REPORT") | crontab -

# -----------------------------
# Step 10: Verification
# -----------------------------
echo "[+] Verifying installation..."
if [ ! -f /var/lib/clamav/daily.cld ]; then
    echo "ERROR: ClamAV virus definitions not found!"
    exit 1
fi

echo "[+] Provisioning complete. All services active, directories created, weekly report scheduled."

#!/bin/bash
# =============================================================================
# Cron Job Scanner
# Part of PrivEsc Scanner Toolkit
# Author: Ansh Makwana
# =============================================================================

echo "=========================================="
echo "  CRON JOB ENUMERATION"
echo "=========================================="
echo ""

# System crontab
echo "[SYSTEM CRONTAB - /etc/crontab]"
echo "------------------------------------------"
if [ -f /etc/crontab ]; then
    cat /etc/crontab
else
    echo "  File not found"
fi
echo ""

# Cron directories
echo "[CRON DIRECTORIES]"
echo "------------------------------------------"
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$dir" ]; then
        echo "Directory: $dir"
        ls -la "$dir" 2>/dev/null | head -10
        echo ""
    fi
done

# User crontabs
echo "[USER CRONTABS]"
echo "------------------------------------------"
if [ -d /var/spool/cron/crontabs ]; then
    ls -la /var/spool/cron/crontabs/ 2>/dev/null
elif [ -d /var/spool/cron ]; then
    ls -la /var/spool/cron/ 2>/dev/null
else
    echo "  No user crontabs directory found"
fi
echo ""

# Check for writable cron scripts
echo "[CHECKING FOR WRITABLE CRON SCRIPTS]"
echo "------------------------------------------"
find /etc/cron.* -type f -perm -002 2>/dev/null | while read script; do
    echo "  ⚠ WORLD-WRITABLE: $script"
done

find /etc/cron.* -type f ! -user root -perm -002 2>/dev/null | while read script; do
    echo "  ⚠ NON-ROOT WRITABLE: $script"
done
echo ""

# Systemd timers
echo "[SYSTEMD TIMERS]"
echo "------------------------------------------"
if command -v systemctl &> /dev/null; then
    systemctl list-timers --all 2>/dev/null | head -15
else
    echo "  systemctl not available"
fi
echo ""

echo "=========================================="
echo "  Cron enumeration complete"
echo "=========================================="
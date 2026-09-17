#!/bin/bash
# =============================================================================
# System Information Gathering Script
# Part of PrivEsc Scanner Toolkit
# Author: Ansh Makwana
# =============================================================================

echo "=========================================="
echo "  SYSTEM INFORMATION GATHERING"
echo "=========================================="
echo ""

# User information
echo "[USER INFORMATION]"
echo "Username: $(whoami)"
echo "UID: $(id -u)"
echo "GID: $(id -g)"
echo "Groups: $(groups)"
echo ""

# Kernel and OS
echo "[KERNEL & OS]"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Hostname: $(hostname)"
if [ -f /etc/os-release ]; then
    source /etc/os-release
    echo "OS: $PRETTY_NAME"
fi
echo ""

# System uptime
echo "[SYSTEM UPTIME]"
uptime
echo ""

# CPU and Memory
echo "[CPU & MEMORY]"
if [ -f /proc/cpuinfo ]; then
    echo "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)"
fi
if [ -f /proc/meminfo ]; then
    echo "Memory:"
    grep -E 'MemTotal|MemAvailable|MemFree' /proc/meminfo | awk '{print $1, $2, $3}'
fi
echo ""

# Disk usage
echo "[DISK USAGE]"
df -h | grep -E '^/dev'
echo ""

# Network interfaces
echo "[NETWORK INTERFACES]"
ip addr show | grep -E '^[0-9]+:|inet ' | head -20
echo ""

echo "=========================================="
echo "  System info collection complete"
echo "=========================================="
#!/bin/bash
# =============================================================================
# SUID/SGID Binary Scanner
# Part of PrivEsc Scanner Toolkit
# Author: Ansh Makwana
# =============================================================================

echo "=========================================="
echo "  SUID/SGID BINARY SCAN"
echo "=========================================="
echo ""

# Find SUID binaries
echo "[SUID BINARIES - find / -perm -4000 -type f]"
echo "------------------------------------------"
find / -perm -4000 -type f 2>/dev/null | while read binary; do
    echo "$binary"
    # Check if it's in common exploitable list
    basename=$(basename "$binary")
    case $basename in
        bash|sh|python*|perl|ruby|php|vim|vi|nano|less|more|man|find|awk|nmap|bash)
            echo "  ⚠ EXPLOITABLE: $basename (check GTFOBins)"
            ;;
    esac
done
echo ""

# Find SGID binaries
echo "[SGID BINARIES - find / -perm -2000 -type f]"
echo "------------------------------------------"
find / -perm -2000 -type f 2>/dev/null | while read binary; do
    echo "$binary"
done
echo ""

# Count results
suid_count=$(find / -perm -4000 -type f 2>/dev/null | wc -l)
sgid_count=$(find / -perm -2000 -type f 2>/dev/null | wc -l)

echo "=========================================="
echo "  Total SUID: $suid_count"
echo "  Total SGID: $sgid_count"
echo "=========================================="
#!/bin/bash
# =============================================================================
# Test Environment Setup Script
# Creates intentional vulnerabilities for testing PrivEsc Scanner
# WARNING: Only run on isolated VMs or test environments!
# =============================================================================

echo "⚠️  WARNING: This script creates security vulnerabilities!"
echo "   Only run on isolated test VMs or containers."
echo ""
read -p "Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "[*] Setting up test vulnerabilities..."

# Create world-writable file in /etc
echo "[*] Creating world-writable file in /etc..."
sudo touch /etc/test_vuln_file
sudo chmod 777 /etc/test_vuln_file

# Create SUID binary (using python3 as example)
echo "[*] Creating SUID python3 binary..."
if [ -f /usr/bin/python3 ]; then
    sudo cp /usr/bin/python3 /tmp/python3_suid_test
    sudo chmod u+s /tmp/python3_suid_test
fi

# Create writable cron script
echo "[*] Creating writable cron script..."
sudo mkdir -p /opt/test_cron
echo '#!/bin/bash\necho "test"' | sudo tee /opt/test_cron/test_script.sh > /dev/null
sudo chmod 777 /opt/test_cron/test_script.sh

# Add to crontab (if cron is available)
if command -v crontab &> /dev/null; then
    echo "[*] Adding test cron job..."
    (crontab -l 2>/dev/null; echo "*/5 * * * * /opt/test_cron/test_script.sh") | crontab -
fi

# Create world-writable directory in /home
echo "[*] Creating world-writable directory..."
sudo mkdir -p /home/test_vuln_dir
sudo chmod 777 /home/test_vuln_dir

echo ""
echo "[✓] Test environment setup complete!"
echo ""
echo "Run the scanner to detect these vulnerabilities:"
echo "  python3 privesc_scanner.py --verbose"
echo ""
echo "To clean up, run:"
echo "  sudo rm -f /etc/test_vuln_file"
echo "  sudo rm -f /tmp/python3_suid_test"
echo "  sudo rm -rf /opt/test_cron"
echo "  sudo rm -rf /home/test_vuln_dir"
echo "  crontab -l | grep -v test_script | crontab -"
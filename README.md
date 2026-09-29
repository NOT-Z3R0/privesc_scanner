# PrivEsc Scanner

Automated Linux Privilege Escalation Detection Toolkit.

---

## Description

PrivEsc Scanner is an automated security auditing tool that scans Linux systems for privilege escalation vulnerabilities. It detects misconfigurations, weak permissions, and security weaknesses that could allow unauthorized access — **detection only, no exploitation**.

---

## Features

- SUID/SGID binary scanner with GTFOBins integration
- File permission auditor (world-writable files, sensitive files)
- Cron job enumerator (system and user crontabs)
- Systemd service scanner (root-running services)
- Sudo configuration analyzer (NOPASSWD, dangerous commands)
- Kernel vulnerability detector (CVE matching)
- Automated report generation (text and JSON formats)

---

## Installation

```bash
git clone https://github.com/NOT-Z3R0/privesc_scanner.git
cd privesc_scanner
```

**Requirements:**
- Linux OS (Ubuntu, Debian, Kali, CentOS)
- Python 3.6+
- No external dependencies required

---

## Usage

```bash
# Basic scan
python3 privesc_scanner.py

# Verbose output
python3 privesc_scanner.py --verbose

# Custom output directory
python3 privesc_scanner.py --output-dir ./reports


```
Reports are saved to the `output/` directory.

---

## Ethics and Legal Notice

**This tool is for educational purposes and authorized security testing only.**

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- This tool detects vulnerabilities but does not exploit them
- The author is not responsible for misuse or any damages caused

Use responsibly and ethically.
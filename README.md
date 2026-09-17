# PrivEsc Scanner - Linux Privilege Escalation Detection Toolkit

Automated toolkit to scan Linux systems for privilege escalation vulnerabilities.

This project is for **educational purposes and authorized security testing only** — detection only, no exploitation.

---

## Features

- SUID/SGID binary scanner with GTFOBins integration
- File permission auditor
- Cron job enumerator
- Systemd service scanner
- Sudo configuration analyzer
- Kernel vulnerability detector
- Text and JSON report generation

---

## Requirements

- Linux (Ubuntu, Debian, Kali, CentOS)
- Python 3.6+
- No external dependencies

---

## Installation

```bash
git clone https://github.com/NOT-Z3R0/privesc_scanner.git
cd privesc_scanner
```
# Optional: Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

---

## Usage

```bash
# Basic scan
python3 privesc_scanner.py

# Verbose mode
python3 privesc_scanner.py --verbose

# Custom output directory
python3 privesc_scanner.py --output-dir ./reports

# Helper scripts
bash bash_helpers/system_info.sh
bash bash_helpers/suid_scan.sh
bash bash_helpers/cron_scan.sh
```

Reports are saved to `output/` directory.

---

## License

Educational use only. Do not use on systems you don't own or have permission to test.

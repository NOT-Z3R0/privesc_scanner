#!/usr/bin/env python3
"""
PrivEsc Scanner - Automated Linux Privilege Escalation Detection Toolkit
=========================================================================

Author: Ansh Makwana
Date: September 2026
Purpose: Educational security auditing tool for detecting privilege 
         escalation vectors on Linux systems (detection only, no exploitation)

This toolkit performs comprehensive scanning for:
- SUID/SGID binaries with exploitation potential
- World-writable files and directories
- Misconfigured systemd services
- Vulnerable cron jobs
- Kernel version vulnerabilities
- Sudo misconfigurations (NOPASSWD, wildcards)

Usage:
    python3 privesc_scanner.py [--output-dir OUTPUT] [--verbose] [--json]

Requirements:
    - Python 3.6+
    - Root or standard user privileges (works in both modes)
    - Linux operating system
"""

import os
import sys
import json
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Centralized configuration for the scanner."""
    
    # Paths
    GTFOBINS_FILE = Path(__file__).parent / "data" / "gtfobins_exploitable.txt"
    OUTPUT_DIR = Path(__file__).parent / "output"
    
    # Severity levels
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"
    
    # Color codes for terminal output
    COLORS = {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'BOLD': '\033[1m',
        'RESET': '\033[0m'
    }
    
    # Known kernel CVEs (educational reference only)
    KERNEL_CVES = {
        'CVE-2024-1086': {
            'name': 'netfilter nf_tables use-after-free',
            'affected': '3.15 <= kernel < 6.8',
            'severity': SEVERITY_CRITICAL,
            'description': 'Use-after-free vulnerability in netfilter nf_tables'
        },
        'CVE-2022-0847': {
            'name': 'DirtyPipe',
            'affected': '5.8 <= kernel <= 5.16',
            'severity': SEVERITY_CRITICAL,
            'description': 'Arbitrary file overwrite via pipe buffer'
        },
        'CVE-2021-4034': {
            'name': 'PwnKit (pkexec)',
            'affected': 'All versions with pkexec since 2009',
            'severity': SEVERITY_CRITICAL,
            'description': 'SUID pkexec heap overflow vulnerability'
        },
        'CVE-2021-3156': {
            'name': 'Baron Samedit',
            'affected': 'sudo < 1.9.5p2',
            'severity': SEVERITY_CRITICAL,
            'description': 'Heap-based buffer overflow in sudo'
        },
        'CVE-2019-13272': {
            'name': 'PTRACE_TRACEME',
            'affected': 'kernel < 5.1.17',
            'severity': SEVERITY_HIGH,
            'description': 'User namespace privilege escalation via ptrace'
        },
        'CVE-2022-0492': {
            'name': 'cgroup release_agent',
            'affected': 'kernel with unprivileged user namespaces',
            'severity': SEVERITY_HIGH,
            'description': 'Privilege escalation via cgroup namespace'
        }
    }


# ============================================================================
# SYSTEM INFORMATION MODULE
# ============================================================================

class SystemInfo:
    """Gathers comprehensive system information."""
    
    @staticmethod
    def get_user_info() -> Dict:
        """Get current user and group information."""
        info = {
            'username': os.getenv('USER', 'unknown'),
            'uid': os.getuid(),
            'gid': os.getgid(),
            'groups': [],
            'is_root': os.getuid() == 0
        }
        
        try:
            # Get group memberships
            result = subprocess.run(['groups'], capture_output=True, text=True)
            if result.returncode == 0:
                info['groups'] = result.stdout.strip().split(': ')[1].split()
        except Exception:
            pass
        
        return info
    
    @staticmethod
    def get_kernel_info() -> Dict:
        """Get kernel version and OS information."""
        info = {
            'kernel_version': 'unknown',
            'kernel_full': 'unknown',
            'os_release': {},
            'architecture': 'unknown',
            'hostname': 'unknown'
        }
        
        try:
            # Kernel version
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            if result.returncode == 0:
                info['kernel_version'] = result.stdout.strip()
            
            # Full kernel info
            result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                info['kernel_full'] = result.stdout.strip()
            
            # Architecture
            result = subprocess.run(['uname', '-m'], capture_output=True, text=True)
            if result.returncode == 0:
                info['architecture'] = result.stdout.strip()
            
            # Hostname
            result = subprocess.run(['hostname'], capture_output=True, text=True)
            if result.returncode == 0:
                info['hostname'] = result.stdout.strip()
            
            # OS Release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            info['os_release'][key] = value.strip('"')
        except Exception:
            pass
        
        return info
    
    @staticmethod
    def get_system_info() -> Dict:
        """Get additional system information."""
        info = {
            'uptime': 'unknown',
            'cpu_info': 'unknown',
            'memory_info': 'unknown',
            'disk_usage': []
        }
        
        try:
            # Uptime
            if os.path.exists('/proc/uptime'):
                with open('/proc/uptime', 'r') as f:
                    uptime_seconds = float(f.read().split()[0])
                    hours, remainder = divmod(int(uptime_seconds), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    info['uptime'] = f"{hours}h {minutes}m {seconds}s"
            
            # CPU info
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.startswith('model name'):
                            info['cpu_info'] = line.split(':')[1].strip()
                            break
            
            # Memory info
            if os.path.exists('/proc/meminfo'):
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            meminfo[key] = value.strip()
                    total = meminfo.get('MemTotal', '0 kB').split()[0]
                    available = meminfo.get('MemAvailable', '0 kB').split()[0]
                    info['memory_info'] = f"Total: {int(total)//1024} MB, Available: {int(available)//1024} MB"
            
            # Disk usage
            result = subprocess.run(['df', '-h'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        info['disk_usage'].append({
                            'filesystem': parts[0],
                            'size': parts[1],
                            'used': parts[2],
                            'available': parts[3],
                            'use_percent': parts[4],
                            'mounted_on': parts[5]
                        })
        except Exception:
            pass
        
        return info


# ============================================================================
# SUID/SGID SCANNER MODULE
# ============================================================================

class SUIDScanner:
    """Scans for SUID/SGID binaries and checks against GTFOBins."""
    
    def __init__(self):
        self.exploitable_binaries = self._load_gtfobins()
    
    def _load_gtfobins(self) -> Dict[str, Dict]:
        """Load GTFOBins exploitable binaries database."""
        binaries = {}
        
        try:
            if Config.GTFOBINS_FILE.exists():
                with open(Config.GTFOBINS_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split('|')
                            if len(parts) >= 3:
                                binaries[parts[0]] = {
                                    'category': parts[1],
                                    'method': parts[2]
                                }
        except Exception as e:
            print(f"{Config.COLORS['YELLOW']}Warning: Could not load GTFOBins database: {e}{Config.COLORS['RESET']}")
        
        return binaries
    
    def scan_suid_binaries(self) -> List[Dict]:
        """Find all SUID binaries on the system."""
        findings = []
        
        try:
            # Find SUID binaries: find / -perm -4000 -type f 2>/dev/null
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                binaries = result.stdout.strip().split('\n')
                for binary in binaries:
                    if binary:
                        finding = {
                            'path': binary,
                            'type': 'SUID',
                            'permissions': self._get_file_perms(binary),
                            'owner': self._get_file_owner(binary),
                            'is_exploitable': os.path.basename(binary) in self.exploitable_binaries,
                            'gtfobins_info': self.exploitable_binaries.get(os.path.basename(binary), {})
                        }
                        findings.append(finding)
        except subprocess.TimeoutExpired:
            print(f"{Config.COLORS['YELLOW']}SUID scan timed out (2 minute limit){Config.COLORS['RESET']}")
        except Exception as e:
            print(f"{Config.COLORS['RED']}Error scanning SUID binaries: {e}{Config.COLORS['RESET']}")
        
        return findings
    
    def scan_sgid_binaries(self) -> List[Dict]:
        """Find all SGID binaries on the system."""
        findings = []
        
        try:
            # Find SGID binaries: find / -perm -2000 -type f 2>/dev/null
            result = subprocess.run(
                ['find', '/', '-perm', '-2000', '-type', 'f'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                binaries = result.stdout.strip().split('\n')
                for binary in binaries:
                    if binary:
                        finding = {
                            'path': binary,
                            'type': 'SGID',
                            'permissions': self._get_file_perms(binary),
                            'owner': self._get_file_owner(binary),
                            'is_exploitable': os.path.basename(binary) in self.exploitable_binaries,
                            'gtfobins_info': self.exploitable_binaries.get(os.path.basename(binary), {})
                        }
                        findings.append(finding)
        except subprocess.TimeoutExpired:
            print(f"{Config.COLORS['YELLOW']}SGID scan timed out (2 minute limit){Config.COLORS['RESET']}")
        except Exception as e:
            print(f"{Config.COLORS['RED']}Error scanning SGID binaries: {e}{Config.COLORS['RESET']}")
        
        return findings
    
    def _get_file_perms(self, filepath: str) -> str:
        """Get file permissions in octal format."""
        try:
            return oct(os.stat(filepath).st_mode)[-3:]
        except Exception:
            return 'unknown'
    
    def _get_file_owner(self, filepath: str) -> str:
        """Get file owner username."""
        try:
            import pwd
            return pwd.getpwuid(os.stat(filepath).st_uid).pw_name
        except Exception:
            return 'unknown'


# ============================================================================
# FILE PERMISSIONS SCANNER MODULE
# ============================================================================

class PermissionScanner:
    """Scans for weak file and directory permissions."""
    
    def scan_world_writable(self) -> List[Dict]:
        """Find world-writable files and directories."""
        findings = []
        critical_paths = ['/etc', '/usr', '/bin', '/sbin', '/opt', '/home']
        
        try:
            # Find world-writable files: find / -type f -perm -0002 2>/dev/null
            result = subprocess.run(
                ['find', '/', '-type', 'f', '-perm', '-0002'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                files = result.stdout.strip().split('\n')
                for filepath in files:
                    if filepath:
                        severity = Config.SEVERITY_MEDIUM
                        # Higher severity for critical system paths
                        for critical in critical_paths:
                            if filepath.startswith(critical):
                                severity = Config.SEVERITY_HIGH
                                break
                        
                        findings.append({
                            'path': filepath,
                            'type': 'world_writable_file',
                            'severity': severity,
                            'permissions': self._get_file_perms(filepath),
                            'owner': self._get_file_owner(filepath)
                        })
            
            # Find world-writable directories: find / -type d -perm -0002 2>/dev/null
            result = subprocess.run(
                ['find', '/', '-type', 'd', '-perm', '-0002'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                dirs = result.stdout.strip().split('\n')
                for dirpath in dirs:
                    if dirpath and dirpath not in ['/tmp', '/var/tmp', '/dev/shm']:
                        severity = Config.SEVERITY_MEDIUM
                        for critical in critical_paths:
                            if dirpath.startswith(critical):
                                severity = Config.SEVERITY_HIGH
                                break
                        
                        findings.append({
                            'path': dirpath,
                            'type': 'world_writable_directory',
                            'severity': severity,
                            'permissions': self._get_file_perms(dirpath),
                            'owner': self._get_file_owner(dirpath)
                        })
        except subprocess.TimeoutExpired:
            print(f"{Config.COLORS['YELLOW']}World-writable scan timed out{Config.COLORS['RESET']}")
        except Exception as e:
            print(f"{Config.COLORS['RED']}Error scanning world-writable files: {e}{Config.COLORS['RESET']}")
        
        return findings
    
    def scan_sensitive_files(self) -> List[Dict]:
        """Check permissions on sensitive files like /etc/passwd, /etc/shadow."""
        findings = []
        sensitive_files = {
            '/etc/passwd': Config.SEVERITY_HIGH,
            '/etc/shadow': Config.SEVERITY_CRITICAL,
            '/etc/sudoers': Config.SEVERITY_CRITICAL,
            '/etc/gshadow': Config.SEVERITY_HIGH,
            '/etc/ssh/sshd_config': Config.SEVERITY_MEDIUM
        }
        
        for filepath, base_severity in sensitive_files.items():
            if os.path.exists(filepath):
                perms = self._get_file_perms(filepath)
                owner = self._get_file_owner(filepath)
                
                # Check if world-readable or world-writable
                is_world_readable = perms[-1] in ['4', '5', '6', '7']
                is_world_writable = perms[-1] in ['2', '3', '6', '7']
                
                if is_world_writable or (filepath == '/etc/shadow' and is_world_readable):
                    findings.append({
                        'path': filepath,
                        'type': 'sensitive_file_permission',
                        'severity': base_severity,
                        'permissions': perms,
                        'owner': owner,
                        'issue': 'World-writable' if is_world_writable else 'World-readable shadow file'
                    })
        
        return findings
    
    def scan_home_directories(self) -> List[Dict]:
        """Check home directory permissions."""
        findings = []
        
        try:
            # Get all home directories
            result = subprocess.run(
                ['ls', '-la', '/home'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip total line
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 9:
                        perms = parts[0]
                        owner = parts[2]
                        dirname = parts[8]
                        dirpath = f"/home/{dirname}"
                        
                        # Check if world-accessible
                        if len(perms) >= 10:
                            other_perms = perms[7:10]
                            if other_perms != '---':
                                findings.append({
                                    'path': dirpath,
                                    'type': 'home_directory_exposure',
                                    'severity': Config.SEVERITY_MEDIUM,
                                    'permissions': perms,
                                    'owner': owner,
                                    'issue': f'Other users have access: {other_perms}'
                                })
        except Exception as e:
            print(f"{Config.COLORS['YELLOW']}Could not scan home directories: {e}{Config.COLORS['RESET']}")
        
        return findings
    
    def _get_file_perms(self, filepath: str) -> str:
        """Get file permissions."""
        try:
            return oct(os.stat(filepath).st_mode)[-3:]
        except Exception:
            return 'unknown'
    
    def _get_file_owner(self, filepath: str) -> str:
        """Get file owner."""
        try:
            import pwd
            return pwd.getpwuid(os.stat(filepath).st_uid).pw_name
        except Exception:
            return 'unknown'


# ============================================================================
# CRON JOB SCANNER MODULE
# ============================================================================

class CronScanner:
    """Scans for cron job vulnerabilities."""
    
    def scan_system_cron(self) -> List[Dict]:
        """Scan system-wide cron jobs."""
        findings = []
        cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', 
                     '/etc/cron.weekly', '/etc/cron.monthly']
        
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                try:
                    result = subprocess.run(
                        ['ls', '-la', cron_dir],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')[1:]
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 9:
                                perms = parts[0]
                                owner = parts[2]
                                filename = parts[8]
                                filepath = f"{cron_dir}/{filename}"
                                
                                # Check if writable by non-root
                                if owner != 'root' and perms[1] == 'w':
                                    findings.append({
                                        'path': filepath,
                                        'type': 'cron_script_writable',
                                        'severity': Config.SEVERITY_HIGH,
                                        'permissions': perms,
                                        'owner': owner,
                                        'location': cron_dir,
                                        'issue': 'Non-root user can modify cron script'
                                    })
                except Exception:
                    pass
        
        # Check /etc/crontab
        if os.path.exists('/etc/crontab'):
            try:
                with open('/etc/crontab', 'r') as f:
                    content = f.read()
                    # Look for scripts run as root
                    for line in content.split('\n'):
                        if 'root' in line and not line.startswith('#'):
                            parts = line.split()
                            if len(parts) >= 7:
                                script = parts[6]
                                if os.path.exists(script):
                                    # Check if script is writable
                                    if os.access(script, os.W_OK) and os.getuid() != 0:
                                        findings.append({
                                            'path': script,
                                            'type': 'crontab_script_writable',
                                            'severity': Config.SEVERITY_HIGH,
                                            'issue': 'Root cron script is writable by current user'
                                        })
            except Exception:
                pass
        
        return findings
    
    def scan_user_cron(self) -> List[Dict]:
        """Scan user crontabs."""
        findings = []
        
        try:
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                findings.append({
                    'type': 'user_crontab_exists',
                    'severity': Config.SEVERITY_INFO,
                    'issue': 'User has active crontab entries',
                    'entries': result.stdout.strip()
                })
        except Exception:
            pass
        
        return findings


# ============================================================================
# SYSTEMD SERVICE SCANNER MODULE
# ============================================================================

class SystemdScanner:
    """Scans for misconfigured systemd services."""
    
    def scan_services(self) -> List[Dict]:
        """Scan systemd services for security issues."""
        findings = []
        
        try:
            # List all services
            result = subprocess.run(
                ['systemctl', 'list-unit-files', '--type=service', '--no-pager'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        service_name = parts[0]
                        
                        # Get service details
                        result = subprocess.run(
                            ['systemctl', 'show', service_name, '--no-pager'],
                            capture_output=True,
                            text=True
                        )
                        
                        if result.returncode == 0:
                            service_info = result.stdout
                            
                            # Check if running as root
                            if 'User=root' in service_info or 'User=' not in service_info:
                                # Check for writable ExecStart paths
                                for svc_line in service_info.split('\n'):
                                    if svc_line.startswith('ExecStart='):
                                        exec_path = svc_line.split('=')[1].split()[0]
                                        if os.path.exists(exec_path):
                                            if os.access(exec_path, os.W_OK) and os.getuid() != 0:
                                                findings.append({
                                                    'service': service_name,
                                                    'type': 'service_writable_exec',
                                                    'severity': Config.SEVERITY_HIGH,
                                                    'exec_path': exec_path,
                                                    'issue': 'Root service executes user-writable binary'
                                                })
                                            
                                            # Check for scripts in /tmp or /home
                                            if '/tmp/' in exec_path or '/home/' in exec_path:
                                                findings.append({
                                                    'service': service_name,
                                                    'type': 'service_insecure_path',
                                                    'severity': Config.SEVERITY_MEDIUM,
                                                    'exec_path': exec_path,
                                                    'issue': 'Service executes from potentially insecure location'
                                                })
        except Exception as e:
            print(f"{Config.COLORS['YELLOW']}Could not scan systemd services: {e}{Config.COLORS['RESET']}")
        
        return findings
    
    def check_path_in_services(self) -> List[Dict]:
        """Check for insecure PATH configurations in services."""
        findings = []
        
        try:
            # Search for PATH in service files
            result = subprocess.run(
                ['grep', '-r', 'Environment=PATH=', '/etc/systemd/system/', '/lib/systemd/system/'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        # Check if PATH includes current directory or writable locations
                        if '.:' in line or ':.' in line or '/tmp' in line or '/home' in line:
                            findings.append({
                                'type': 'insecure_service_path',
                                'severity': Config.SEVERITY_MEDIUM,
                                'line': line,
                                'issue': 'Service PATH includes potentially unsafe directories'
                            })
        except Exception:
            pass
        
        return findings


# ============================================================================
# SUDO CONFIGURATION SCANNER MODULE
# ============================================================================

class SudoScanner:
    """Scans for sudo misconfigurations."""
    
    def scan_sudo_config(self) -> List[Dict]:
        """Check sudo configuration for security issues."""
        findings = []
        
        try:
            # Run sudo -l to see allowed commands
            result = subprocess.run(
                ['sudo', '-l'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Check for NOPASSWD
                if 'NOPASSWD' in output:
                    findings.append({
                        'type': 'sudo_nopasswd',
                        'severity': Config.SEVERITY_HIGH,
                        'issue': 'NOPASSWD sudo rules detected',
                        'details': self._extract_nopasswd_rules(output)
                    })
                
                # Check for dangerous commands
                dangerous_commands = ['vim', 'vi', 'nano', 'less', 'more', 'man',
                                     'python', 'python3', 'perl', 'ruby', 'php',
                                     'bash', 'sh', 'find', 'awk', 'nmap']
                
                for line in output.split('\n'):
                    for cmd in dangerous_commands:
                        if cmd in line.lower() and 'sudo' not in line.lower():
                            findings.append({
                                'type': 'sudo_dangerous_command',
                                'severity': Config.SEVERITY_HIGH,
                                'command': cmd,
                                'issue': f'Sudo allows {cmd} which can be used for privilege escalation',
                                'gtfobins_reference': f'https://gtfobins.github.io/gtfobins/{cmd}/'
                            })
                            break
                
                # Check for ALL commands
                if '(ALL : ALL)' in output or '(ALL)' in output:
                    findings.append({
                        'type': 'sudo_all_commands',
                        'severity': Config.SEVERITY_CRITICAL,
                        'issue': 'User can run ALL commands with sudo'
                    })
            
            # Check sudoers file directly (if readable)
            sudoers_files = ['/etc/sudoers', '/etc/sudoers.d/']
            for sudoers in sudoers_files:
                if os.path.exists(sudoers):
                    try:
                        if os.path.isfile(sudoers):
                            with open(sudoers, 'r') as f:
                                content = f.read()
                                if 'env_keep' in content.lower() or 'env_reset' in content.lower():
                                    findings.append({
                                        'type': 'sudo_env_keep',
                                        'severity': Config.SEVERITY_MEDIUM,
                                        'issue': 'Sudoers file contains env_keep or missing env_reset',
                                        'risk': 'May allow LD_PRELOAD attacks'
                                    })
                        elif os.path.isdir(sudoers):
                            for subdir_file in os.listdir(sudoers):
                                subdir_path = os.path.join(sudoers, subdir_file)
                                if os.path.isfile(subdir_path):
                                    with open(subdir_path, 'r') as f:
                                        content = f.read()
                                        if 'NOPASSWD' in content:
                                            findings.append({
                                                'type': 'sudoers_nopasswd_file',
                                                'severity': Config.SEVERITY_HIGH,
                                                'file': subdir_path,
                                                'issue': 'Sudoers.d file contains NOPASSWD rule'
                                            })
                    except PermissionError:
                        pass
        except Exception as e:
            print(f"{Config.COLORS['YELLOW']}Could not scan sudo configuration: {e}{Config.COLORS['RESET']}")
        
        return findings
    
    def _extract_nopasswd_rules(self, sudo_output: str) -> List[str]:
        """Extract NOPASSWD rules from sudo -l output."""
        rules = []
        for line in sudo_output.split('\n'):
            if 'NOPASSWD' in line:
                rules.append(line.strip())
        return rules


# ============================================================================
# KERNEL VULNERABILITY SCANNER MODULE
# ============================================================================

class KernelScanner:
    """Scans for kernel vulnerabilities based on version."""
    
    def scan_kernel_version(self) -> List[Dict]:
        """Check kernel version against known CVEs."""
        findings = []
        
        try:
            # Get kernel version
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            if result.returncode != 0:
                return findings
            
            kernel_version = result.stdout.strip()
            
            # Parse version numbers
            version_parts = kernel_version.split('-')[0].split('.')
            if len(version_parts) >= 3:
                major = int(version_parts[0])
                minor = int(version_parts[1])
                patch = int(version_parts[2].split('.')[0])
                
                # Check against known CVEs
                for cve_id, cve_info in Config.KERNEL_CVES.items():
                    affected = cve_info['affected']
                    
                    # Simple version range checking (educational purposes)
                    if self._is_kernel_affected(major, minor, patch, affected):
                        findings.append({
                            'cve_id': cve_id,
                            'name': cve_info['name'],
                            'severity': cve_info['severity'],
                            'kernel_version': kernel_version,
                            'affected_versions': affected,
                            'description': cve_info['description'],
                            'type': 'kernel_vulnerability',
                            'mitigation': f"Update kernel to latest version. Current: {kernel_version}"
                        })
        except Exception as e:
            print(f"{Config.COLORS['YELLOW']}Could not scan kernel version: {e}{Config.COLORS['RESET']}")
        
        return findings
    
    def _is_kernel_affected(self, major: int, minor: int, patch: int, affected_range: str) -> bool:
        """Check if kernel version falls within affected range."""
        try:
            # Parse affected range (simplified logic for educational purposes)
            if '<=' in affected_range and '>=' in affected_range:
                # Range like "3.15 <= kernel <= 5.16"
                parts = affected_range.split()
                low_version = parts[0].split('.')
                high_version = parts[4].split('.')
                
                low_major = int(low_version[0])
                low_minor = int(low_version[1]) if len(low_version) > 1 else 0
                
                high_major = int(high_version[0])
                high_minor = int(high_version[1]) if len(high_version) > 1 else 0
                
                current = major * 100 + minor
                low = low_major * 100 + low_minor
                high = high_major * 100 + high_minor
                
                return low <= current <= high
            
            elif '<' in affected_range:
                # Range like "kernel < 5.1.17"
                parts = affected_range.split()
                for part in parts:
                    if '.' in part and part[0].isdigit():
                        max_version = part.split('-')[0].split('.')
                        max_major = int(max_version[0])
                        max_minor = int(max_version[1]) if len(max_version) > 1 else 0
                        
                        return (major < max_major) or (major == max_major and minor < max_minor)
            
            # Default: assume affected for educational demonstration
            return True
        except Exception:
            return False


# ============================================================================
# REPORT GENERATOR MODULE
# ============================================================================

class ReportGenerator:
    """Generates comprehensive security reports."""
    
    def __init__(self, findings: Dict, system_info: Dict):
        self.findings = findings
        self.system_info = system_info
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    def generate_text_report(self, output_path: Path) -> str:
        """Generate human-readable text report."""
        report = []
        report.append("=" * 80)
        report.append("PRIVILEGE ESCALATION SECURITY AUDIT REPORT")
        report.append("=" * 80)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Hostname: {self.system_info.get('hostname', 'unknown')}")
        report.append(f"User: {self.system_info.get('username', 'unknown')}")
        report.append(f"Kernel: {self.system_info.get('kernel_version', 'unknown')}")
        report.append(f"OS: {self.system_info.get('os_release', {}).get('PRETTY_NAME', 'unknown')}")
        report.append("\n" + "=" * 80)
        
        # Summary
        report.append("\n## EXECUTIVE SUMMARY")
        report.append("-" * 80)
        
        total_findings = sum(len(v) for v in self.findings.values() if isinstance(v, list))
        critical_count = sum(1 for findings_list in self.findings.values() 
                           if isinstance(findings_list, list)
                           for f in findings_list 
                           if isinstance(f, dict) and f.get('severity') == Config.SEVERITY_CRITICAL)
        high_count = sum(1 for findings_list in self.findings.values() 
                        if isinstance(findings_list, list)
                        for f in findings_list 
                        if isinstance(f, dict) and f.get('severity') == Config.SEVERITY_HIGH)
        
        report.append(f"Total Findings: {total_findings}")
        report.append(f"Critical: {critical_count}")
        report.append(f"High: {high_count}")
        report.append(f"Medium/Low: {total_findings - critical_count - high_count}")
        
        # Detailed findings by category
        for category, findings_list in self.findings.items():
            if isinstance(findings_list, list) and findings_list:
                report.append(f"\n## {category.upper().replace('_', ' ')}")
                report.append("-" * 80)
                
                for finding in findings_list:
                    if isinstance(finding, dict):
                        severity = finding.get('severity', 'INFO')
                        color = {
                            Config.SEVERITY_CRITICAL: '🔴',
                            Config.SEVERITY_HIGH: '🟠',
                            Config.SEVERITY_MEDIUM: '🟡',
                            Config.SEVERITY_LOW: '🔵',
                            Config.SEVERITY_INFO: '⚪'
                        }.get(severity, '⚪')
                        
                        report.append(f"\n{color} [{severity}]")
                        for key, value in finding.items():
                            if key != 'severity' and value:
                                report.append(f"   {key.replace('_', ' ').title()}: {value}")
        
        report.append("\n" + "=" * 80)
        report.append("## MITIGATION RECOMMENDATIONS")
        report.append("-" * 80)
        report.append(self._generate_mitigations())
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write report
        report_text = '\n'.join(report)
        with open(output_path, 'w') as f:
            f.write(report_text)
        
        return report_text
    
    def generate_json_report(self, output_path: Path) -> str:
        """Generate JSON report for machine parsing."""
        report_data = {
            'metadata': {
                'timestamp': self.timestamp,
                'scanner_version': '1.0.0',
                'hostname': self.system_info.get('hostname', 'unknown'),
                'kernel': self.system_info.get('kernel_version', 'unknown'),
                'os': self.system_info.get('os_release', {}).get('PRETTY_NAME', 'unknown')
            },
            'findings': self.findings,
            'summary': {
                'total_findings': sum(len(v) for v in self.findings.values() if isinstance(v, list)),
                'by_severity': self._count_by_severity()
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return output_path
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = defaultdict(int)
        for findings_list in self.findings.values():
            if isinstance(findings_list, list):
                for finding in findings_list:
                    if isinstance(finding, dict):
                        severity = finding.get('severity', 'INFO')
                        counts[severity] += 1
        return dict(counts)
    
    def _generate_mitigations(self) -> str:
        """Generate mitigation recommendations based on findings."""
        mitigations = []
        
        # Check for SUID findings
        if self.findings.get('suid_binaries'):
            mitigations.append("""
1. SUID/SGID BINARIES:
   - Review all SUID binaries and remove unnecessary ones: chmod u-s <binary>
   - Ensure SUID binaries are from trusted packages only
   - Monitor SUID binary creation with: auditctl -w /usr/bin -p x -k suid_change
   - Regularly audit SUID binaries: find / -perm -4000 -type f
""")
        
        # Check for permission findings
        if self.findings.get('weak_permissions'):
            mitigations.append("""
2. FILE PERMISSIONS:
   - Remove world-writable permissions: chmod o-w <file/directory>
   - Ensure sensitive files are root-owned: chown root:root /etc/shadow
   - Set proper permissions: chmod 640 /etc/shadow, chmod 644 /etc/passwd
   - Audit home directories: chmod 750 /home/username
""")
        
        # Check for cron findings
        if self.findings.get('cron_vulnerabilities'):
            mitigations.append("""
3. CRON JOBS:
   - Ensure all cron scripts are owned by root: chown root:root /path/to/script
   - Set restrictive permissions: chmod 700 /path/to/script
   - Use absolute paths in crontabs
   - Avoid wildcards in cron commands
   - Monitor cron execution: journalctl -u cron
""")
        
        # Check for sudo findings
        if self.findings.get('sudo_misconfigurations'):
            mitigations.append("""
4. SUDO CONFIGURATION:
   - Remove NOPASSWD rules where possible
   - Restrict sudo to specific commands, not ALL
   - Avoid allowing shell editors (vim, nano) via sudo
   - Use sudoers.d for modular configuration
   - Enable logging: Defaults logfile="/var/log/sudo.log"
""")
        
        # Check for kernel findings
        if self.findings.get('kernel_vulnerabilities'):
            mitigations.append("""
5. KERNEL SECURITY:
   - Update to latest kernel version: sudo apt update && sudo apt upgrade
   - Enable automatic security updates
   - Subscribe to distribution security announcements
   - Consider kernel hardening tools: grsecurity, SELinux, AppArmor
""")
        
        if not mitigations:
            return "No critical findings requiring immediate mitigation."
        
        return '\n'.join(mitigations)


# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================

class PrivEscScanner:
    """Main orchestrator for privilege escalation scanning."""
    
    def __init__(self, output_dir: Optional[Path] = None, verbose: bool = False):
        self.output_dir = output_dir or Config.OUTPUT_DIR
        self.verbose = verbose
        self.findings = defaultdict(list)
        self.system_info = {}
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize scanners
        self.suid_scanner = SUIDScanner()
        self.permission_scanner = PermissionScanner()
        self.cron_scanner = CronScanner()
        self.systemd_scanner = SystemdScanner()
        self.sudo_scanner = SudoScanner()
        self.kernel_scanner = KernelScanner()
    
    def run_full_scan(self) -> Dict:
        """Execute complete privilege escalation scan."""
        print(f"\n{Config.COLORS['BOLD']}{Config.COLORS['CYAN']}")
        print("=" * 70)
        print("  PRIVILEGE ESCALATION SCANNER - SECURITY AUDIT TOOLKIT")
        print("=" * 70)
        print(f"{Config.COLORS['RESET']}")
        
        # STEP 1: System Information
        print(f"\n{Config.COLORS['BOLD']}[STEP 1/6]{Config.COLORS['RESET']} Gathering system information...")
        self._collect_system_info()
        
        # STEP 2: SUID/SGID Scan
        print(f"\n{Config.COLORS['BOLD']}[STEP 2/6]{Config.COLORS['RESET']} Scanning SUID/SGID binaries...")
        self._scan_suid_sgid()
        
        # STEP 3: Permission Scan
        print(f"\n{Config.COLORS['BOLD']}[STEP 3/6]{Config.COLORS['RESET']} Scanning file permissions...")
        self._scan_permissions()
        
        # STEP 4: Cron Scan
        print(f"\n{Config.COLORS['BOLD']}[STEP 4/6]{Config.COLORS['RESET']} Scanning cron jobs...")
        self._scan_cron()
        
        # STEP 5: Systemd & Sudo Scan
        print(f"\n{Config.COLORS['BOLD']}[STEP 5/6]{Config.COLORS['RESET']} Scanning services and sudo...")
        self._scan_services_sudo()
        
        # STEP 6: Kernel Scan
        print(f"\n{Config.COLORS['BOLD']}[STEP 6/6]{Config.COLORS['RESET']} Checking kernel vulnerabilities...")
        self._scan_kernel()
        
        # Generate Reports
        print(f"\n{Config.COLORS['BOLD']}[GENERATING]{Config.COLORS['RESET']} Creating reports...")
        self._generate_reports()
        
        # Print Summary
        self._print_summary()
        
        return self.findings
    
    def _collect_system_info(self):
        """Collect system information."""
        self.system_info['user'] = SystemInfo.get_user_info()
        self.system_info['kernel'] = SystemInfo.get_kernel_info()
        self.system_info['system'] = SystemInfo.get_system_info()
        
        if self.verbose:
            print(f"  User: {self.system_info['user']['username']} (UID: {self.system_info['user']['uid']})")
            print(f"  Kernel: {self.system_info['kernel']['kernel_version']}")
            print(f"  OS: {self.system_info['kernel']['os_release'].get('PRETTY_NAME', 'Unknown')}")
    
    def _scan_suid_sgid(self):
        """Scan for SUID/SGID binaries."""
        suid_binaries = self.suid_scanner.scan_suid_binaries()
        sgid_binaries = self.suid_scanner.scan_sgid_binaries()
        
        self.findings['suid_binaries'] = suid_binaries
        self.findings['sgid_binaries'] = sgid_binaries
        
        # Highlight exploitable ones
        exploitable = [b for b in suid_binaries if b.get('is_exploitable')]
        if exploitable:
            print(f"  {Config.COLORS['RED']}⚠ Found {len(exploitable)} exploitable SUID binaries!{Config.COLORS['RESET']}")
            for binary in exploitable[:5]:  # Show first 5
                print(f"    - {binary['path']} ({binary['gtfobins_info'].get('category', 'unknown')})")
        else:
            print(f"  {Config.COLORS['GREEN']}✓ No exploitable SUID binaries found{Config.COLORS['RESET']}")
        
        print(f"  Total SUID: {len(suid_binaries)}, SGID: {len(sgid_binaries)}")
    
    def _scan_permissions(self):
        """Scan for permission issues."""
        world_writable = self.permission_scanner.scan_world_writable()
        sensitive = self.permission_scanner.scan_sensitive_files()
        home_dirs = self.permission_scanner.scan_home_directories()
        
        self.findings['weak_permissions'] = world_writable + sensitive + home_dirs
        
        critical_perms = [f for f in self.findings['weak_permissions'] 
                         if f.get('severity') in [Config.SEVERITY_CRITICAL, Config.SEVERITY_HIGH]]
        
        if critical_perms:
            print(f"  {Config.COLORS['RED']}⚠ Found {len(critical_perms)} critical/high permission issues!{Config.COLORS['RESET']}")
        else:
            print(f"  {Config.COLORS['GREEN']}✓ No critical permission issues found{Config.COLORS['RESET']}")
        
        print(f"  Total permission findings: {len(self.findings['weak_permissions'])}")
    
    def _scan_cron(self):
        """Scan cron jobs."""
        system_cron = self.cron_scanner.scan_system_cron()
        user_cron = self.cron_scanner.scan_user_cron()
        
        self.findings['cron_vulnerabilities'] = system_cron + user_cron
        
        if system_cron:
            print(f"  {Config.COLORS['YELLOW']}⚠ Found {len(system_cron)} potential cron issues{Config.COLORS['RESET']}")
        else:
            print(f"  {Config.COLORS['GREEN']}✓ No cron vulnerabilities found{Config.COLORS['RESET']}")
    
    def _scan_services_sudo(self):
        """Scan systemd services and sudo configuration."""
        services = self.systemd_scanner.scan_services()
        path_issues = self.systemd_scanner.check_path_in_services()
        sudo_issues = self.sudo_scanner.scan_sudo_config()
        
        self.findings['systemd_services'] = services + path_issues
        self.findings['sudo_misconfigurations'] = sudo_issues
        
        if sudo_issues:
            high_severity = [s for s in sudo_issues if s.get('severity') in 
                           [Config.SEVERITY_CRITICAL, Config.SEVERITY_HIGH]]
            if high_severity:
                print(f"  {Config.COLORS['RED']}⚠ Found {len(high_severity)} critical/high sudo issues!{Config.COLORS['RESET']}")
                for issue in high_severity[:3]:
                    print(f"    - {issue.get('type', 'unknown')}: {issue.get('issue', '')}")
        else:
            print(f"  {Config.COLORS['GREEN']}✓ No sudo misconfigurations found{Config.COLORS['RESET']}")
    
    def _scan_kernel(self):
        """Scan kernel for vulnerabilities."""
        kernel_vulns = self.kernel_scanner.scan_kernel_version()
        
        self.findings['kernel_vulnerabilities'] = kernel_vulns
        
        if kernel_vulns:
            print(f"  {Config.COLORS['RED']}⚠ Found {len(kernel_vulns)} potential kernel vulnerabilities!{Config.COLORS['RESET']}")
            for vuln in kernel_vulns:
                print(f"    - {vuln['cve_id']}: {vuln['name']}")
        else:
            print(f"  {Config.COLORS['GREEN']}✓ No known kernel vulnerabilities detected{Config.COLORS['RESET']}")
    
    def _generate_reports(self):
        """Generate all reports."""
        report_gen = ReportGenerator(dict(self.findings), self.system_info)
        
        # Text report
        text_report_path = self.output_dir / f"privesc_report_{self.system_info['hostname']}_{self.system_info['user']['username']}_{self.system_info['kernel']['kernel_version'].replace('.', '_')}.txt"
        report_gen.generate_text_report(text_report_path)
        print(f"  Text report: {text_report_path}")
        
        # JSON report
        json_report_path = self.output_dir / f"privesc_report_{self.system_info['hostname']}_{self.system_info['user']['username']}_{self.system_info['kernel']['kernel_version'].replace('.', '_')}.json"
        report_gen.generate_json_report(json_report_path)
        print(f"  JSON report: {json_report_path}")
    
    def _print_summary(self):
        """Print final summary."""
        print(f"\n{Config.COLORS['BOLD']}{Config.COLORS['CYAN']}")
        print("=" * 70)
        print("  SCAN COMPLETE - SUMMARY")
        print("=" * 70)
        print(f"{Config.COLORS['RESET']}")
        
        total = sum(len(v) for v in self.findings.values() if isinstance(v, list))
        print(f"\nTotal Findings: {total}")
        
        for category, findings_list in self.findings.items():
            if isinstance(findings_list, list) and findings_list:
                print(f"  • {category.replace('_', ' ').title()}: {len(findings_list)}")
        
        print(f"\n{Config.COLORS['GREEN']}Reports saved to: {self.output_dir.absolute()}{Config.COLORS['RESET']}")
        print(f"\n{Config.COLORS['YELLOW']}⚠ REMEMBER: This is a detection tool only. Do not exploit findings without authorization.{Config.COLORS['RESET']}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='PrivEsc Scanner - Linux Privilege Escalation Detection Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 privesc_scanner.py                    # Run full scan with default output
  python3 privesc_scanner.py --verbose          # Run with verbose output
  python3 privesc_scanner.py --output-dir ./reports  # Custom output directory

Note: This tool is for educational and authorized security auditing only.
      Do not use on systems you do not own or have permission to test.
        """
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        type=Path,
        default=None,
        help='Output directory for reports (default: ./output)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output findings as JSON only (no text report)'
    )
    
    args = parser.parse_args()
    
    # Check if running on Linux
    if os.name != 'posix':
        print(f"{Config.COLORS['RED']}Error: This tool is designed for Linux systems only.{Config.COLORS['RESET']}")
        sys.exit(1)
    
    # Run scanner
    scanner = PrivEscScanner(output_dir=args.output_dir, verbose=args.verbose)
    scanner.run_full_scan()


if __name__ == '__main__':
    main()
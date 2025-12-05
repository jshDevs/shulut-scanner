#!/usr/bin/env python3
"""
SHULUT 2.0 Advanced Detection & Analysis Engine
Professional malware detector for npm packages and projects
Compatible with: Linux, macOS, Windows (WSL)
"""

import os
import sys
import json
import hashlib
import subprocess
import argparse
import tempfile
import shutil
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Set
from collections import defaultdict

# Color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Malware signatures database
MALWARE_SIGNATURES = {
    'van-environment.js': {
        'hash_patterns': [
            'van-environment',
            'setupban',
            'shai-hulut'
        ],
        'file_indicators': ['van-environment.js', 'setupban.js'],
        'severity': 'CRITICAL'
    },
    'preinstall_hooks': {
        'patterns': [
            r'setupban',
            r'van-environment',
            r'shai-hulut',
            r'node.*--exec',
            r'curl.*eval',
            r'wget.*eval'
        ],
        'severity': 'HIGH'
    },
    'malicious_packages': {
        'names': [
            'shulut',
            'shai-hulut',
            'van-environment',
            'setupban',
            'node-setupban',
            'ban-install'
        ],
        'severity': 'CRITICAL'
    },
    'credentials_exfiltration': {
        'patterns': [
            r'\.env',
            r'\.npmrc',
            r'\.git/config',
            r'~/.ssh',
            r'~/.aws/credentials',
            r'process\.env\.(API|SECRET|TOKEN|KEY)',
            r'github\.com.*token'
        ],
        'severity': 'CRITICAL'
    },
    'remote_execution': {
        'patterns': [
            r'eval\(',
            r'exec\(',
            r'Function\(',
            r'child_process\.exec',
            r'require.*spawn',
            r'require.*fork'
        ],
        'severity': 'HIGH'
    }
}

class Logger:
    """Centralized logging system"""
    def __init__(self, log_file: str = None):
        self.log_file = log_file or f"/tmp/shulut_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.findings = []
    
    def info(self, msg: str):
        print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")
        self._log(f"[INFO] {msg}")
    
    def success(self, msg: str):
        print(f"{Colors.GREEN}[✓]{Colors.RESET} {msg}")
        self._log(f"[SUCCESS] {msg}")
    
    def warning(self, msg: str):
        print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")
        self._log(f"[WARNING] {msg}")
    
    def error(self, msg: str):
        print(f"{Colors.RED}[✗]{Colors.RESET} {msg}")
        self._log(f"[ERROR] {msg}")
    
    def critical(self, msg: str):
        print(f"{Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.RESET} {msg}")
        self._log(f"[CRITICAL] {msg}")
    
    def header(self, msg: str):
        border = "=" * 70
        print(f"\n{Colors.CYAN}{Colors.BOLD}{border}")
        print(f"{msg.center(70)}")
        print(f"{border}{Colors.RESET}\n")
        self._log(f"\n{'='*70}\n{msg}\n{'='*70}\n")
    
    def _log(self, msg: str):
        with open(self.log_file, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {msg}\n")
    
    def add_finding(self, finding: Dict):
        self.findings.append(finding)
        self._log(f"FINDING: {json.dumps(finding)}")

logger = Logger()

class MalwareDetector:
    """Advanced malware detection engine"""
    
    def __init__(self):
        self.infected_projects = []
        self.suspicious_packages = set()
        self.credential_exposures = []
    
    def scan_package_json(self, path: Path) -> List[Dict]:
        """Scan package.json for malware indicators"""
        findings = []
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                pkg_data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Cannot read package.json: {path} - {e}")
            return findings
        
        # Check scripts
        scripts = pkg_data.get('scripts', {})
        for script_name, script_cmd in scripts.items():
            if script_name == 'preinstall':
                for pattern in MALWARE_SIGNATURES['preinstall_hooks']['patterns']:
                    if re.search(pattern, script_cmd, re.IGNORECASE):
                        findings.append({
                            'type': 'MALICIOUS_PREINSTALL',
                            'severity': 'HIGH',
                            'path': str(path),
                            'script': script_name,
                            'content': script_cmd[:100],
                            'pattern': pattern
                        })
        
        # Check dependencies
        all_deps = {
            **pkg_data.get('dependencies', {}),
            **pkg_data.get('devDependencies', {}),
            **pkg_data.get('optionalDependencies', {})
        }
        
        for dep_name in all_deps.keys():
            if dep_name in MALWARE_SIGNATURES['malicious_packages']['names']:
                findings.append({
                    'type': 'MALICIOUS_PACKAGE',
                    'severity': 'CRITICAL',
                    'path': str(path),
                    'package': dep_name,
                    'version': all_deps[dep_name]
                })
                self.suspicious_packages.add(dep_name)
        
        return findings
    
    def scan_node_modules(self, project_dir: Path) -> List[Dict]:
        """Scan node_modules for malicious files"""
        findings = []
        node_modules = project_dir / 'node_modules'
        
        if not node_modules.exists():
            return findings
        
        logger.info(f"Scanning node_modules: {node_modules}")
        
        # Check for known malware files
        for indicator in MALWARE_SIGNATURES['van-environment.js']['file_indicators']:
            malicious_files = list(node_modules.rglob(indicator))
            for malicious_file in malicious_files:
                findings.append({
                    'type': 'MALWARE_FILE',
                    'severity': 'CRITICAL',
                    'path': str(malicious_file),
                    'file_name': indicator
                })
        
        # Check for malicious packages
        for pkg_name in MALWARE_SIGNATURES['malicious_packages']['names']:
            pkg_path = node_modules / pkg_name
            if pkg_path.exists():
                findings.append({
                    'type': 'MALICIOUS_PACKAGE_DETECTED',
                    'severity': 'CRITICAL',
                    'path': str(pkg_path),
                    'package': pkg_name
                })
        
        # Scan JavaScript files in suspicious locations
        findings.extend(self._scan_package_files(node_modules))
        
        return findings
    
    def _scan_package_files(self, node_modules: Path) -> List[Dict]:
        """Scan package files for malicious code patterns"""
        findings = []
        
        # Sample scan first 10 packages
        scanned = 0
        for pkg_dir in node_modules.iterdir():
            if scanned >= 50:  # Limit for performance
                break
            
            if not pkg_dir.is_dir() or pkg_dir.name.startswith('.'):
                continue
            
            scanned += 1
            
            # Check package.json
            pkg_json = pkg_dir / 'package.json'
            if pkg_json.exists():
                try:
                    with open(pkg_json, 'r', encoding='utf-8') as f:
                        pkg_data = json.load(f)
                        scripts = pkg_data.get('scripts', {})
                        for script_name, script_cmd in scripts.items():
                            if any(pattern in script_cmd.lower() 
                                   for pattern in ['eval', 'exec', 'spawn', 'fork']):
                                findings.append({
                                    'type': 'SUSPICIOUS_SCRIPT',
                                    'severity': 'MEDIUM',
                                    'path': str(pkg_json),
                                    'script': script_name,
                                    'content': script_cmd[:150]
                                })
                except:
                    pass
        
        return findings
    
    def scan_credentials(self, project_dir: Path) -> List[Dict]:
        """Scan for credential exposure"""
        findings = []
        
        sensitive_files = ['.env', '.npmrc', '.git/config', 'credentials.json']
        
        for filename in sensitive_files:
            file_path = project_dir / filename
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Check for sensitive patterns
                        if any(pattern in content.upper() 
                               for pattern in ['API_KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'AWS_']):
                            findings.append({
                                'type': 'EXPOSED_CREDENTIALS',
                                'severity': 'CRITICAL',
                                'path': str(file_path),
                                'exposure_type': 'File contains sensitive credentials'
                            })
                            self.credential_exposures.append(str(file_path))
                except Exception as e:
                    logger.warning(f"Cannot scan {file_path}: {e}")
        
        return findings
    
    def scan_git_history(self, project_dir: Path) -> List[Dict]:
        """Analyze git history for suspicious activity"""
        findings = []
        git_dir = project_dir / '.git'
        
        if not git_dir.exists():
            return findings
        
        try:
            result = subprocess.run(
                ['git', 'log', '--since=7 days ago', '--oneline'],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            commits = result.stdout.strip().split('\n')
            if len(commits) > 10:
                findings.append({
                    'type': 'SUSPICIOUS_COMMIT_ACTIVITY',
                    'severity': 'MEDIUM',
                    'path': str(git_dir),
                    'recent_commits': len(commits),
                    'note': f'{len(commits)} commits in last 7 days'
                })
        except Exception as e:
            logger.warning(f"Cannot scan git history: {e}")
        
        return findings
    
    def full_scan(self, start_path: Path) -> Dict:
        """Execute full scan of all projects"""
        logger.header("STARTING COMPREHENSIVE SCAN")
        
        results = {
            'scanned_projects': 0,
            'infected_projects': 0,
            'total_findings': 0,
            'critical_findings': 0,
            'projects': []
        }
        
        # Find all package.json files
        projects = list(start_path.rglob('package.json'))
        
        if not projects:
            logger.warning("No npm projects found")
            return results
        
        logger.info(f"Found {len(projects)} npm projects")
        
        for idx, pkg_file in enumerate(projects, 1):
            project_dir = pkg_file.parent
            project_findings = []
            
            logger.info(f"[{idx}/{len(projects)}] Scanning: {project_dir.name}")
            
            # Run all scans
            project_findings.extend(self.scan_package_json(pkg_file))
            project_findings.extend(self.scan_node_modules(project_dir))
            project_findings.extend(self.scan_credentials(project_dir))
            project_findings.extend(self.scan_git_history(project_dir))
            
            results['scanned_projects'] += 1
            results['total_findings'] += len(project_findings)
            results['critical_findings'] += sum(1 for f in project_findings if f.get('severity') == 'CRITICAL')
            
            if project_findings:
                results['infected_projects'] += 1
                results['projects'].append({
                    'path': str(project_dir),
                    'findings_count': len(project_findings),
                    'findings': project_findings
                })
                logger.error(f"INFECTED: {project_dir.name} ({len(project_findings)} findings)")
            else:
                logger.success(f"CLEAN: {project_dir.name}")
        
        return results
    
    def generate_report(self, results: Dict, output_file: str = None):
        """Generate detailed report"""
        logger.header("SCAN REPORT")
        
        print(f"Total Projects Scanned: {results['scanned_projects']}")
        print(f"Infected Projects: {Colors.RED}{results['infected_projects']}{Colors.RESET}")
        print(f"Total Findings: {results['total_findings']}")
        print(f"Critical Findings: {Colors.RED}{results['critical_findings']}{Colors.RESET}")
        print()
        
        if results['projects']:
            print(f"{Colors.YELLOW}Infected Projects Details:{Colors.RESET}\n")
            for project in results['projects']:
                print(f"  {Colors.RED}●{Colors.RESET} {project['path']}")
                for finding in project['findings']:
                    severity_color = {
                        'CRITICAL': Colors.RED,
                        'HIGH': Colors.YELLOW,
                        'MEDIUM': Colors.BLUE
                    }.get(finding.get('severity'), '')
                    
                    print(f"    {severity_color}→{Colors.RESET} {finding['type']}: {finding.get('package', finding.get('file_name', ''))}")
        
        # Save JSON report
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            logger.success(f"Report saved: {output_file}")

class Remediator:
    """Malware remediation engine"""
    
    def __init__(self):
        self.backup_dir = Path(tempfile.mkdtemp(prefix='shulut_backup_'))
        logger.info(f"Backup directory: {self.backup_dir}")
    
    def remediate_project(self, project_dir: Path) -> bool:
        """Clean infected project"""
        logger.header(f"REMEDIATING: {project_dir.name}")
        
        try:
            # 1. Backup
            logger.info("Creating backup...")
            self._backup_project(project_dir)
            
            # 2. Remove malicious files
            logger.info("Removing malicious files...")
            self._remove_malicious_files(project_dir)
            
            # 3. Clean node_modules
            logger.info("Removing contaminated node_modules...")
            self._clean_node_modules(project_dir)
            
            # 4. Clean package.json
            logger.info("Cleaning package.json...")
            self._clean_package_json(project_dir)
            
            # 5. Reinstall dependencies
            logger.info("Reinstalling dependencies...")
            self._reinstall_dependencies(project_dir)
            
            logger.success(f"Remediation completed: {project_dir.name}")
            return True
        
        except Exception as e:
            logger.error(f"Remediation failed: {e}")
            return False
    
    def _backup_project(self, project_dir: Path):
        """Backup project files"""
        backup = self.backup_dir / project_dir.name
        backup.mkdir(parents=True, exist_ok=True)
        
        for file in ['package.json', 'package-lock.json', 'yarn.lock']:
            src = project_dir / file
            if src.exists():
                shutil.copy2(src, backup / file)
    
    def _remove_malicious_files(self, project_dir: Path):
        """Remove known malware files"""
        for pattern in MALWARE_SIGNATURES['van-environment.js']['file_indicators']:
            for file in project_dir.rglob(pattern):
                try:
                    file.unlink()
                    logger.success(f"Removed: {file.name}")
                except Exception as e:
                    logger.warning(f"Cannot remove {file}: {e}")
    
    def _clean_node_modules(self, project_dir: Path):
        """Remove node_modules"""
        nm_dir = project_dir / 'node_modules'
        if nm_dir.exists():
            try:
                shutil.rmtree(nm_dir)
                logger.success("node_modules removed")
            except Exception as e:
                logger.error(f"Cannot remove node_modules: {e}")
    
    def _clean_package_json(self, project_dir: Path):
        """Clean malicious entries from package.json"""
        pkg_file = project_dir / 'package.json'
        
        try:
            with open(pkg_file, 'r', encoding='utf-8') as f:
                pkg_data = json.load(f)
            
            # Remove malicious dependencies
            for dep_type in ['dependencies', 'devDependencies', 'optionalDependencies']:
                if dep_type in pkg_data:
                    for malicious_pkg in MALWARE_SIGNATURES['malicious_packages']['names']:
                        pkg_data[dep_type].pop(malicious_pkg, None)
            
            # Remove malicious scripts
            if 'scripts' in pkg_data:
                preinstall = pkg_data['scripts'].get('preinstall', '')
                for pattern in MALWARE_SIGNATURES['preinstall_hooks']['patterns']:
                    if re.search(pattern, preinstall, re.IGNORECASE):
                        del pkg_data['scripts']['preinstall']
                        break
            
            with open(pkg_file, 'w', encoding='utf-8') as f:
                json.dump(pkg_data, f, indent=2)
            
            logger.success("package.json cleaned")
        
        except Exception as e:
            logger.error(f"Cannot clean package.json: {e}")
    
    def _reinstall_dependencies(self, project_dir: Path):
        """Reinstall clean dependencies"""
        try:
            subprocess.run(
                ['npm', 'install'],
                cwd=project_dir,
                capture_output=True,
                timeout=300
            )
            logger.success("Dependencies reinstalled")
        except Exception as e:
            logger.error(f"npm install failed: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='SHULUT 2.0 Advanced Detection & Remediation Engine'
    )
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')
    parser.add_argument('--scan', action='store_true', help='Run scan only')
    parser.add_argument('--remediate', action='store_true', help='Scan and remediate')
    parser.add_argument('--report', type=str, help='Save JSON report to file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    start_path = Path(args.path).resolve()
    
    if not start_path.exists():
        logger.error(f"Path does not exist: {start_path}")
        sys.exit(1)
    
    # Run detector
    detector = MalwareDetector()
    results = detector.full_scan(start_path)
    
    # Generate report
    detector.generate_report(results, args.report)
    
    # Remediate if requested
    if args.remediate and results['infected_projects'] > 0:
        logger.header("REMEDIATION PHASE")
        remediator = Remediator()
        
        for project in results['projects']:
            remediator.remediate_project(Path(project['path']))
    
    # Exit code based on findings
    sys.exit(0 if results['critical_findings'] == 0 else 1)

if __name__ == '__main__':
    main()

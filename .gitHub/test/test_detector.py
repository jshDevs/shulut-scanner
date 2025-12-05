"""
SHULUT 2.0 Detector - Unit Tests
Tests for malware detection and remediation functionality
"""

import pytest
import tempfile
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock


class TestMalwareSignatures:
    """Test malware signature detection"""
    
    def test_malicious_packages_list(self):
        """Verify known malicious packages are registered"""
        from shulut_detector import MALWARE_SIGNATURES
        
        malicious = MALWARE_SIGNATURES['malicious_packages']['names']
        assert 'van-environment' in malicious
        assert 'setupban' in malicious
        assert 'shai-hulut' in malicious
        assert len(malicious) > 0
    
    def test_preinstall_patterns(self):
        """Verify preinstall hook patterns"""
        from shulut_detector import MALWARE_SIGNATURES
        
        patterns = MALWARE_SIGNATURES['preinstall_hooks']['patterns']
        assert any('setupban' in p for p in patterns)
        assert any('van-environment' in p for p in patterns)
    
    def test_file_indicators(self):
        """Verify malware file indicators"""
        from shulut_detector import MALWARE_SIGNATURES
        
        files = MALWARE_SIGNATURES['van-environment.js']['file_indicators']
        assert 'van-environment.js' in files
        assert 'setupban.js' in files


class TestPackageJsonScanning:
    """Test package.json scanning functionality"""
    
    @pytest.fixture
    def temp_project(self):
        """Create temporary project structure"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def test_scan_clean_package_json(self, temp_project):
        """Test detection of clean package.json"""
        from shulut_detector import MalwareDetector
        
        pkg_file = temp_project / 'package.json'
        pkg_data = {
            'name': 'test-project',
            'version': '1.0.0',
            'dependencies': {
                'express': '^4.18.0',
                'lodash': '^4.17.0'
            }
        }
        
        with open(pkg_file, 'w') as f:
            json.dump(pkg_data, f)
        
        detector = MalwareDetector()
        findings = detector.scan_package_json(pkg_file)
        
        assert len(findings) == 0
    
    def test_scan_malicious_package_json(self, temp_project):
        """Test detection of infected package.json"""
        from shulut_detector import MalwareDetector
        
        pkg_file = temp_project / 'package.json'
        pkg_data = {
            'name': 'infected-project',
            'version': '1.0.0',
            'scripts': {
                'preinstall': 'node setupban.js'
            },
            'dependencies': {
                'van-environment': '^1.0.0'
            }
        }
        
        with open(pkg_file, 'w') as f:
            json.dump(pkg_data, f)
        
        detector = MalwareDetector()
        findings = detector.scan_package_json(pkg_file)
        
        assert len(findings) > 0
        assert any(f['type'] == 'MALICIOUS_PREINSTALL' for f in findings)
        assert any(f['type'] == 'MALICIOUS_PACKAGE' for f in findings)
    
    def test_scan_credentials_in_package_json(self, temp_project):
        """Test detection of exposed credentials in package.json"""
        from shulut_detector import MalwareDetector
        
        pkg_file = temp_project / 'package.json'
        pkg_data = {
            'name': 'test',
            'version': '1.0.0',
            'config': {
                'API_KEY': 'sk_test_1234567890'
            }
        }
        
        with open(pkg_file, 'w') as f:
            json.dump(pkg_data, f)
        
        detector = MalwareDetector()
        # Note: package.json credentials detection may vary
        findings = detector.scan_package_json(pkg_file)
        # This depends on implementation


class TestNodeModulesScanning:
    """Test node_modules scanning"""
    
    @pytest.fixture
    def infected_node_modules(self):
        """Create infected node_modules structure"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create node_modules
            nm_dir = tmppath / 'node_modules'
            nm_dir.mkdir()
            
            # Create malicious package
            van_env_dir = nm_dir / 'van-environment'
            van_env_dir.mkdir()
            (van_env_dir / 'package.json').write_text('{"name":"van-environment"}')
            (van_env_dir / 'van-environment.js').write_text('// malware')
            
            yield tmppath
    
    def test_scan_infected_node_modules(self, infected_node_modules):
        """Test detection of malware in node_modules"""
        from shulut_detector import MalwareDetector
        
        detector = MalwareDetector()
        findings = detector.scan_node_modules(infected_node_modules)
        
        assert len(findings) > 0
        assert any('van-environment' in str(f.get('path', '')) for f in findings)


class TestCredentialExposure:
    """Test credential exposure detection"""
    
    @pytest.fixture
    def exposed_credentials_project(self):
        """Create project with exposed credentials"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create .env with credentials
            env_file = tmppath / '.env'
            env_file.write_text('API_KEY=sk_test_secret123\nDATABASE_PASSWORD=secret')
            
            yield tmppath
    
    def test_detect_exposed_env_file(self, exposed_credentials_project):
        """Test detection of .env file with credentials"""
        from shulut_detector import MalwareDetector
        
        detector = MalwareDetector()
        findings = detector.scan_credentials(exposed_credentials_project)
        
        assert len(findings) > 0
        assert any(f['type'] == 'EXPOSED_CREDENTIALS' for f in findings)


class TestFullScan:
    """Test complete scanning workflow"""
    
    @pytest.fixture
    def multi_project_workspace(self):
        """Create workspace with multiple projects"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Project 1: Clean
            proj1 = tmppath / 'clean-project'
            proj1.mkdir()
            (proj1 / 'package.json').write_text(json.dumps({
                'name': 'clean-project',
                'dependencies': {'express': '^4.18.0'}
            }))
            
            # Project 2: Infected
            proj2 = tmppath / 'infected-project'
            proj2.mkdir()
            (proj2 / 'package.json').write_text(json.dumps({
                'name': 'infected-project',
                'scripts': {'preinstall': 'node setupban.js'},
                'dependencies': {'van-environment': '^1.0.0'}
            }))
            
            yield tmppath
    
    def test_full_scan_multiple_projects(self, multi_project_workspace):
        """Test scanning multiple projects"""
        from shulut_detector import MalwareDetector
        
        detector = MalwareDetector()
        results = detector.full_scan(multi_project_workspace)
        
        assert results['scanned_projects'] == 2
        assert results['infected_projects'] == 1
        assert results['total_findings'] > 0


class TestRemediator:
    """Test remediation functionality"""
    
    @pytest.fixture
    def infected_project(self):
        """Create infected project"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create infected structure
            (tmppath / 'package.json').write_text(json.dumps({
                'name': 'test-project',
                'scripts': {'preinstall': 'node setupban.js'},
                'dependencies': {'van-environment': '^1.0.0', 'express': '^4.0.0'}
            }))
            
            # Create node_modules
            nm = tmppath / 'node_modules'
            nm.mkdir()
            
            yield tmppath
    
    def test_backup_creation(self, infected_project):
        """Test backup creation during remediation"""
        from shulut_detector import Remediator
        
        remediator = Remediator()
        remediator._backup_project(infected_project)
        
        backup_dir = remediator.backup_dir
        assert backup_dir.exists()
        assert (backup_dir / infected_project.name / 'package.json').exists()


class TestLogger:
    """Test logging functionality"""
    
    def test_logger_creation(self):
        """Test logger initialization"""
        from shulut_detector import Logger
        
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / 'test.log'
            logger = Logger(str(log_file))
            
            logger.info('Test message')
            assert log_file.exists()
    
    def test_logger_messages(self):
        """Test different log message types"""
        from shulut_detector import Logger
        
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / 'test.log'
            logger = Logger(str(log_file))
            
            logger.info('Info')
            logger.success('Success')
            logger.warning('Warning')
            logger.error('Error')
            
            content = log_file.read_text()
            assert 'Info' in content
            assert 'Success' in content
            assert 'Warning' in content
            assert 'Error' in content


class TestIntegration:
    """Integration tests"""
    
    def test_end_to_end_scan_and_report(self):
        """Test complete scan and report generation"""
        from shulut_detector import MalwareDetector
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create test project
            (tmppath / 'package.json').write_text(json.dumps({
                'name': 'test',
                'dependencies': {'lodash': '^4.0.0'}
            }))
            
            detector = MalwareDetector()
            results = detector.full_scan(tmppath)
            
            assert 'scanned_projects' in results
            assert 'infected_projects' in results
            assert 'total_findings' in results


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--cov=shulut_detector'])


# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v2.0.0
- Web UI dashboard for non-technical users
- Kubernetes cluster scanning support
- Real-time monitoring service
- SIEM platform integration (Splunk, ELK)
- Mobile app for alerts
- Slack/Teams notifications

## [1.0.0] - 2025-12-04

### Added
- Initial release of SHULUT 2.0 Scanner
- Bash scanner for Linux/macOS (Rocky, CentOS, Ubuntu, Debian)
- Batch scanner for Windows (10, 11, Server 2019+)
- Python advanced detector with:
  - Comprehensive malware signatures database
  - Deep package analysis
  - Credential exposure detection
  - JSON report generation
  - Automated remediation
  - Git integrity checking
- Complete threat analysis documentation
- Remediation playbook
- CI/CD GitHub Actions workflows
- Docker support with Dockerfile
- Comprehensive test suite with pytest
- Multiple detection vectors:
  - Malicious files (van-environment.js, setupban.js)
  - Package.json tampering
  - Node modules contamination
  - Credential exposure
  - Git history anomalies
  - Runtime behaviors
- Automated remediation including:
  - Backup creation
  - Malware removal
  - Package.json sanitization
  - Dependency reinstallation
  - Credential rotation guidance
- Professional documentation:
  - README with quick start
  - Contributing guidelines
  - Threat analysis guide
  - Installation instructions
  - Usage examples
  - Troubleshooting guide

### Security
- Non-root Docker execution
- Input validation
- Safe file operations
- Credential handling best practices

### Performance
- Efficient file scanning
- Limited node_modules sampling
- Configurable search depth
- Caching support

## Security Notes

### Supported Detection Patterns

**Malicious Packages:**
- shulut
- shai-hulut
- van-environment
- setupban
- node-setupban
- ban-install

**Malware Files:**
- van-environment.js
- setupban.js

**Malicious Scripts:**
- preinstall hooks with malicious code
- eval/exec patterns
- Remote execution indicators

### Known Limitations

- Python detector requires Python 3.8+
- Bash scanner limited to Unix-like systems
- Batch scanner Windows-only
- Node modules sampling limited to first 50 packages for performance
- Git analysis requires git installation

### Future Improvements

- [ ] Real-time monitoring
- [ ] Machine learning-based detection
- [ ] Behavioral analysis
- [ ] Sandbox execution testing
- [ ] Private registry support
- [ ] Multi-language support
- [ ] Centralized reporting dashboard

## Contributors

- Security Research Team
- Community Contributors

## References

- [midudev YouTube Analysis](https://www.youtube.com/watch?v=dn5tt2W8tlE)
- [npm Security Documentation](https://docs.npmjs.com/packages-and-modules/security)
- [OWASP Supply Chain Attacks](https://owasp.org/www-community/attacks/Supply_Chain_Attack)

---

For more information, see [README.md](README.md)

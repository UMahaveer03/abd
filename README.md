# Automated Bug Discovery (ABD)

A comprehensive automated bug hunting application with 4 stages for complete security assessment.

## Overview

ABD (Automated Bug Discovery) is a professional-grade security testing framework that automates the entire bug hunting process through four distinct stages:

1. **Preparation** - Target validation, environment setup, and scope definition
2. **Reconnaissance** - Information gathering, subdomain enumeration, and service discovery  
3. **Vulnerability Identification** - Automated vulnerability scanning and testing
4. **Exploitation** - Safe proof-of-concept development and reporting

## Features

### 🎯 **Stage 1: Preparation**
- Target validation (domain/IP)
- Environment and tool availability checks
- Workspace setup and configuration
- Assessment scope definition
- Security tool inventory

### 🔍 **Stage 2: Reconnaissance**
- DNS enumeration (A, MX, NS, TXT, CNAME records)
- Subdomain discovery with threading
- Port scanning and service detection
- Technology fingerprinting
- HTTP information gathering
- SSL/TLS certificate analysis

### 🔍 **Stage 3: Vulnerability Identification**
- Web vulnerability scanning (XSS, SQLi, LFI, Directory Traversal)
- SSL/TLS vulnerability assessment
- Service-specific vulnerability checks
- Security misconfiguration detection
- Sensitive file exposure testing
- Security header analysis

### 💥 **Stage 4: Exploitation**
- Safe proof-of-concept development
- Automated exploitation attempts
- Risk assessment and prioritization
- Comprehensive reporting (JSON, HTML, Executive Summary)
- Security recommendations
- Remediation guidance

## Installation

### Prerequisites
- Python 3.7+
- Basic security tools (optional but recommended):
  - nmap
  - dig
  - curl/wget

### Setup
```bash
# Clone the repository
git clone https://github.com/UMahaveer03/abd.git
cd abd

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x abd.py
```

## Usage

### Basic Usage
```bash
# Run complete assessment
python3 abd.py -t example.com

# Run with custom configuration
python3 abd.py -t example.com -c config.json

# Enable verbose output
python3 abd.py -t example.com -v
```

### Stage-Specific Execution
```bash
# Run only preparation stage
python3 abd.py -t example.com --stage preparation

# Run only reconnaissance 
python3 abd.py -t example.com --stage reconnaissance

# Run only vulnerability identification
python3 abd.py -t example.com --stage vulnerability

# Run only exploitation
python3 abd.py -t example.com --stage exploitation
```

### Configuration

ABD uses a JSON configuration file (`config.json`) for customization:

```json
{
  "output_dir": "output",
  "timeout": 30,
  "threads": 10,
  "user_agent": "ABD/1.0 Security Scanner",
  "subdomain_wordlist": "wordlists/subdomains.txt",
  "ports": [80, 443, 8080, 8443],
  "vulnerable_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443],
  "payloads": {
    "xss": ["<script>alert('ABD-XSS-Test')</script>"],
    "sqli": ["'", "' OR '1'='1"],
    "lfi": ["../../../etc/passwd"],
    "rce": ["id", "whoami"]
  }
}
```

## Output and Reporting

ABD generates comprehensive reports in multiple formats:

### Output Structure
```
output/
└── target_domain_com/
    ├── assessment_scope.json
    ├── exploitation_report_YYYYMMDD_HHMMSS.json
    ├── exploitation_report_YYYYMMDD_HHMMSS.html
    └── executive_summary_YYYYMMDD_HHMMSS.txt
```

### Report Types

1. **JSON Report** - Technical details for integration
2. **HTML Report** - Visual report for stakeholders  
3. **Executive Summary** - High-level findings for management
4. **Assessment Scope** - Documented scope and limitations

## Security Features

### Safety Measures
- Non-destructive testing only
- Rate limiting and request throttling
- WAF detection and evasion
- Safe exploitation techniques
- Comprehensive logging

### Ethical Considerations
- Only test systems you own or have permission to test
- Respect rate limits and server resources
- Follow responsible disclosure practices
- Comply with local laws and regulations

## Architecture

### Modular Design
```
abd.py                 # Main application entry point
├── modules/
│   ├── preparation.py    # Stage 1: Preparation
│   ├── reconnaissance.py # Stage 2: Reconnaissance  
│   ├── vulnerability.py  # Stage 3: Vulnerability ID
│   ├── exploitation.py   # Stage 4: Exploitation
│   └── utils.py         # Utilities and helpers
├── wordlists/           # Attack wordlists
├── config.json         # Configuration file
└── requirements.txt    # Python dependencies
```

### Threading and Performance
- Multi-threaded subdomain enumeration
- Concurrent port scanning
- Parallel vulnerability testing
- Optimized for large-scale assessments

## Examples

### Complete Assessment
```bash
$ python3 abd.py -t vulnerablesite.com -v

 █████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗
███████║██████╔╝██║  ██║
██╔══██║██╔══██╗██║  ██║
██║  ██║██████╔╝██████╔╝
╚═╝  ╚═╝╚═════╝ ╚═════╝ 

Automated Bug Discovery v1.0
Target: vulnerablesite.com
═══════════════════════════════════

[INFO] ═══ STAGE 1: PREPARATION ═══
[SUCCESS] Target validated: vulnerablesite.com (domain)
[SUCCESS] Preparation stage completed successfully

[INFO] ═══ STAGE 2: RECONNAISSANCE ═══
[SUCCESS] Found subdomain: admin.vulnerablesite.com -> 192.168.1.100
[SUCCESS] Found open port: 80
[SUCCESS] Reconnaissance completed: 3 subdomains, 4 open ports, 4 services detected

[INFO] ═══ STAGE 3: VULNERABILITY IDENTIFICATION ═══
[SUCCESS] Vulnerability scan completed: 12 total findings, 3 critical/high severity

[INFO] ═══ STAGE 4: EXPLOITATION ═══
[SUCCESS] Exploitation completed: 5 PoCs developed, 3 successful exploits, 3 reports generated

═══ EXECUTION SUMMARY ═══
✓ PREPARATION: Preparation completed successfully
✓ RECONNAISSANCE: Reconnaissance completed successfully
✓ VULNERABILITY: Vulnerability identification completed successfully
✓ EXPLOITATION: Exploitation stage completed successfully
```

### Targeted Assessment
```bash
# Focus on web vulnerabilities
python3 abd.py -t webapp.com --stage vulnerability

# Quick reconnaissance only
python3 abd.py -t target.com --stage reconnaissance
```

## Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Setup
```bash
git clone https://github.com/UMahaveer03/abd.git
cd abd
pip3 install -r requirements.txt
pip3 install -r requirements-dev.txt  # Development dependencies
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The developers are not responsible for any misuse or damage caused by this tool.

## Support

- 📧 Email: support@abd-security.com
- 🐛 Issues: [GitHub Issues](https://github.com/UMahaveer03/abd/issues)
- 📖 Documentation: [Wiki](https://github.com/UMahaveer03/abd/wiki)
- 💬 Discussions: [GitHub Discussions](https://github.com/UMahaveer03/abd/discussions)

## Roadmap

### Upcoming Features
- [ ] Cloud security assessments (AWS, Azure, GCP)
- [ ] API security testing framework
- [ ] Machine learning-based vulnerability detection
- [ ] Integration with popular CI/CD pipelines
- [ ] Mobile application security testing
- [ ] Advanced evasion techniques
- [ ] Custom payload development framework

---

**ABD - Automated Bug Discovery** | Making security assessments efficient and comprehensive.

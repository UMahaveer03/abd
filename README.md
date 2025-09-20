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
- **OWASP Top 10 2021 Coverage:**
  - A01: Broken Access Control (IDOR, privilege escalation)
  - A02: Cryptographic Failures (SSL/TLS vulnerabilities)
  - A03: Injection (SQL, NoSQL, XSS, XXE, LDAP, SSTI)
  - A04: Insecure Design (business logic flaws)
  - A05: Security Misconfiguration (headers, CORS, files)
  - A06: Vulnerable Components (service versions)
  - A07: Authentication Failures (JWT flaws, bypasses)
  - A08: Software/Data Integrity Failures (XXE, deserialization)
  - A09: Security Logging Failures (monitoring gaps)
  - A10: Server-Side Request Forgery (SSRF)
- **Advanced Vulnerability Detection:**
  - Cross-Site Scripting (XSS) - Reflected, DOM-based
  - SQL Injection with WAF bypass techniques
  - NoSQL Injection (MongoDB, CouchDB)
  - XML External Entity (XXE) attacks
  - Server-Side Template Injection (SSTI)
  - LDAP Injection vulnerabilities
  - Cross-Site Request Forgery (CSRF)
  - HTTP Parameter Pollution (HPP)
  - Host Header Injection
  - CORS Misconfigurations
  - JWT Vulnerabilities (none algorithm, weak secrets)
  - Authentication Bypass techniques
  - File Upload vulnerabilities
  - Subdomain Takeover detection
  - Business Logic Flaws
- **Advanced Evasion Techniques:**
  - WAF bypass with payload encoding
  - User-Agent rotation
  - Rate limiting evasion
  - Case variation and comment insertion
  - HTTP verb tampering
  - Header manipulation

### 💥 **Stage 4: Exploitation**
- **Advanced Proof-of-Concept Development:**
  - OWASP Top 10 2021 exploit demonstrations
  - Safe exploitation with bypass techniques
  - JWT manipulation and forgery
  - Authentication bypass demonstrations
  - Business logic abuse scenarios
  - SSRF and XXE exploitation
  - Template injection payloads
- **Comprehensive Reporting:**
  - Risk assessment and CVSS scoring
  - Executive summary reports
  - Technical vulnerability reports
  - Remediation guidelines
  - Proof-of-concept documentation
  - Security recommendations
- **Advanced Features:**
  - WAF evasion techniques
  - Rate limiting bypass
  - Multi-vector attack chains
  - Custom payload generation

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
    "nosqli": ["true, $where: '1 == 1'", "$ne: null"],
    "lfi": ["../../../etc/passwd"],
    "xxe": ["<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"],
    "ssrf": ["http://127.0.0.1:22", "http://169.254.169.254/latest/meta-data/"],
    "ssti": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
    "ldap": ["*", "*)(&", "*)(uid=*"],
    "rce": ["id", "whoami"]
  },
  "advanced_techniques": {
    "waf_bypass": {
      "user_agents": ["GoogleBot/2.1", "facebookexternalhit/1.1"],
      "encoding_techniques": ["url_encode", "double_url_encode", "unicode_encode"],
      "case_variation": true,
      "comment_insertion": true,
      "payload_fragmentation": true
    },
    "rate_limiting": {
      "delays": [1, 2, 3, 5],
      "random_delay": true,
      "concurrent_requests": 3
    },
    "evasion": {
      "http_parameter_pollution": true,
      "verb_tampering": ["GET", "POST", "PUT", "PATCH"],
      "header_manipulation": true,
      "payload_encoding": true
    }
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

### OWASP Top 10 2021 Coverage
ABD provides comprehensive coverage of the latest OWASP Top 10 vulnerabilities:

1. **A01:2021 – Broken Access Control**
   - Insecure Direct Object References (IDOR)
   - Authentication bypass techniques
   - Privilege escalation testing

2. **A02:2021 – Cryptographic Failures**
   - SSL/TLS vulnerability assessment
   - Weak encryption detection
   - Certificate validation issues

3. **A03:2021 – Injection**
   - SQL injection with WAF bypass
   - NoSQL injection (MongoDB, CouchDB)
   - LDAP injection
   - XSS (Reflected, DOM-based)
   - XXE (XML External Entity)
   - SSTI (Server-Side Template Injection)

4. **A04:2021 – Insecure Design**
   - Business logic flaw detection
   - Workflow bypass testing

5. **A05:2021 – Security Misconfiguration**
   - Missing security headers
   - CORS misconfigurations
   - Directory listing
   - Sensitive file exposure

6. **A06:2021 – Vulnerable and Outdated Components**
   - Service version detection
   - Known vulnerability identification

7. **A07:2021 – Identification and Authentication Failures**
   - JWT vulnerability testing
   - Authentication bypass
   - Session management flaws

8. **A08:2021 – Software and Data Integrity Failures**
   - XXE attack vectors
   - Insecure deserialization detection

9. **A09:2021 – Security Logging and Monitoring Failures**
   - Security header analysis
   - Monitoring gap identification

10. **A10:2021 – Server-Side Request Forgery (SSRF)**
    - Internal network access
    - Cloud metadata exposure
    - Port scanning via SSRF

### Advanced Evasion Techniques
- **WAF Bypass:** Payload encoding, case variation, comment insertion
- **Rate Limiting Evasion:** Random delays, user agent rotation
- **Detection Evasion:** HTTP verb tampering, header manipulation

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

### Recently Added (v2.0) ✅
- [x] Complete OWASP Top 10 2021 vulnerability coverage
- [x] Advanced WAF bypass techniques
- [x] JWT vulnerability testing
- [x] NoSQL injection detection
- [x] SSRF (Server-Side Request Forgery) testing
- [x] XXE (XML External Entity) attack detection
- [x] SSTI (Server-Side Template Injection) testing
- [x] Business logic flaw detection
- [x] Advanced authentication bypass techniques
- [x] HTTP Parameter Pollution testing
- [x] CORS misconfiguration detection
- [x] Host header injection testing
- [x] Subdomain takeover detection

### Upcoming Features (v3.0)
- [ ] Cloud security assessments (AWS, Azure, GCP)
- [ ] API security testing framework with GraphQL support
- [ ] Machine learning-based vulnerability detection
- [ ] Integration with popular CI/CD pipelines
- [ ] Mobile application security testing
- [ ] Advanced payload generation with genetic algorithms
- [ ] Blockchain and smart contract security testing
- [ ] Container and Kubernetes security assessment
- [ ] Real-time threat intelligence integration
- [ ] Automated exploit chaining

---

**ABD - Automated Bug Discovery** | Making security assessments efficient and comprehensive.

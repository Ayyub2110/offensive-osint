# AI Offensive OSINT Framework

> **An autonomous, AI-powered reconnaissance framework for offensive security operations**

A production-grade OSINT framework built with LangGraph orchestration, designed for red team operations, penetration testing, and security research. This system automates the complete reconnaissance phase of offensive security engagements through intelligent agent coordination.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Red Team](https://img.shields.io/badge/Red%20Team-Ready-red.svg)]()

---

## 🎯 Project Overview

The AI Offensive OSINT Framework is a comprehensive reconnaissance automation platform that combines multiple specialized agents to perform systematic target analysis. Built on LangGraph for intelligent workflow orchestration, it transforms raw target data into actionable intelligence for offensive security operations.

**Key Capabilities:**
- **Autonomous Reconnaissance**: Multi-stage intelligence gathering with minimal human intervention
- **Target Prioritization**: AI-driven exploitability scoring for efficient resource allocation
- **Attack Surface Mapping**: Comprehensive enumeration of digital assets and entry points
- **Intelligence Correlation**: Automated analysis and synthesis of reconnaissance data
- **Adaptive Workflow**: Dynamic decision-making to prevent endless loops and optimize coverage

**Designed For:**
- Red Team Operations
- Penetration Testing Engagements
- Bug Bounty Reconnaissance
- Security Research
- Threat Intelligence Gathering

---

## 🏗️ Architecture

### Workflow Graph

```
┌─────────────────────────────────────────────────────────────────┐
│                     AI OFFENSIVE OSINT WORKFLOW                 │
└─────────────────────────────────────────────────────────────────┘

                            ┌─────────┐
                            │  START  │
                            └────┬────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Username Correlation    │
                    │ • Platform discovery    │
                    │ • Social media presence │
                    │ • Code repositories     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Email Pattern Inference │
                    │ • Domain validation     │
                    │ • Email generation      │
                    │ • Confidence scoring    │
                    └────────────┬────────────┘
                                 │
              ┌─────────────────▼──────────────────┐
              │                                     │
         ┌────▼────────┐                      ┌────▼─────┐
         │   Asset     │◄─────────────────────┤ Continue?│
         │  Discovery  │   YES (Loop Back)    └────┬─────┘
         │ • Subdomains│                           │ NO
         │ • Endpoints │                           │
         │ • Files     │                      ┌────▼────┐
         └────┬────────┘                      │   END   │
              │                               └─────────┘
    ┌─────────▼─────────┐
    │  Tech Stack       │
    │  Fingerprinting   │
    │ • Web server      │
    │ • Backend tech    │
    │ • Security posture│
    └─────────┬─────────┘
              │
    ┌─────────▼─────────┐
    │ Attack Surface    │
    │  Prioritization   │
    │ • Scoring         │
    │ • Ranking         │
    │ • Attack vectors  │
    └─────────┬─────────┘
              │
    ┌─────────▼─────────┐
    │  Recon Decision   │
    │ • Stop conditions │
    │ • Continue/Exit   │
    └───────────────────┘
```

### Agent Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    SPECIALIZED AGENTS                    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────┐│
│  │   Username     │  │     Email      │  │   Asset    ││
│  │  Correlation   │  │    Pattern     │  │ Discovery  ││
│  │                │  │   Inference    │  │            ││
│  │ • GitHub       │  │ • DNS/MX check │  │ • Subdomains││
│  │ • Reddit       │  │ • Name parsing │  │ • robots.txt││
│  │ • Twitter      │  │ • 14+ patterns │  │ • Sitemaps ││
│  │ • Instagram    │  │ • Confidence   │  │ • Sensitive││
│  └────────────────┘  └────────────────┘  └────────────┘│
│                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────┐│
│  │   Tech Stack   │  │ Attack Surface │  │   Recon    ││
│  │ Fingerprinting │  │ Prioritization │  │  Decision  ││
│  │                │  │                │  │            ││
│  │ • Server IDs   │  │ • Scoring (0-100)│ • Diminishing││
│  │ • Frameworks   │  │ • Ranking      │  │   returns  ││
│  │ • Auth methods │  │ • Attack recs  │  │ • Thresholds││
│  │ • WAF/CDN      │  │ • Risk assess  │  │ • Loop ctrl││
│  └────────────────┘  └────────────────┘  └────────────┘│
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 🤖 Agent Descriptions

### 1. **Username Correlation Agent**
Discovers target presence across multiple platforms using HTTP-based enumeration.

**Capabilities:**
- Platform detection (GitHub, Reddit, Twitter, Instagram)
- Status code analysis and redirect following
- Concurrent checks with timeout protection
- Response time tracking

**Offensive Value:** Identifies social media accounts, code repositories, and forums for social engineering, credential reuse analysis, and information gathering.

### 2. **Email Pattern Inference Agent**
Generates probable email addresses using common corporate naming conventions.

**Capabilities:**
- 14+ email format patterns (firstname.lastname, f.lastname, etc.)
- DNS/MX record validation for deliverability
- Name component parsing (first, middle, last)
- Confidence scoring for each pattern

**Offensive Value:** Creates target lists for credential stuffing, password spraying, and phishing campaigns.

### 3. **Asset Discovery Agent**
Enumerates the complete attack surface through multi-source reconnaissance.

**Capabilities:**
- Subdomain enumeration (100+ common patterns + DNS brute force)
- robots.txt parsing (discovers hidden/restricted paths)
- Sitemap analysis (recursive sitemap index processing)
- Sensitive file detection (.git, .env, backups, configs)
- HTTP response analysis (header + body link extraction)

**Offensive Value:** Expands attack surface by discovering dev/staging environments, admin panels, APIs, and exposed configuration files.

### 4. **Tech Stack Fingerprinting Agent**
Identifies technologies, frameworks, and security mechanisms through passive analysis.

**Capabilities:**
- Web server detection (nginx, Apache, IIS, etc.)
- Backend technology identification (PHP, Node.js, Python, Java)
- Frontend framework detection (React, Vue, Angular)
- CMS recognition (WordPress, Drupal, Joomla)
- WAF/CDN detection (Cloudflare, Akamai, ModSecurity)
- Authentication mechanism analysis (JWT, OAuth, Basic Auth)
- Security header evaluation

**Offensive Value:** Enables CVE lookup for detected versions, framework-specific exploit selection, and WAF bypass strategy planning.

### 5. **Attack Surface Prioritization Agent**
Assigns exploitability scores and ranks targets using weighted scoring algorithms.

**Capabilities:**
- Multi-factor scoring (admin panels, auth endpoints, APIs, legacy tech, missing WAF)
- Weighted score calculation (0-100 scale)
- Priority classification (Critical, High, Medium, Low, Minimal)
- Attack vector recommendations
- Detailed reasoning for each score

**Offensive Value:** Optimizes penetration testing resources by focusing on highest-value, most exploitable targets first.

### 6. **Recon Stop Decision Agent**
Determines when to terminate reconnaissance based on diminishing returns analysis.

**Capabilities:**
- New asset rate evaluation
- Exploitability threshold checking
- Duplicate intelligence detection
- Iteration and time limits
- Confidence-weighted decision making

**Offensive Value:** Prevents detection through excessive scanning and ensures efficient time-boxed reconnaissance operations.

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.10 or higher
- pip package manager
- Internet connection for target reconnaissance

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ai_offensive_osint.git
cd ai_offensive_osint

# Install dependencies
pip install -r requirements.txt

# Configure environment (optional)
cp .env.example .env
# Edit .env with your API keys if using LLM features
```

### Configuration

The framework can operate without API keys for basic OSINT operations. LLM integration (future feature) requires:

```bash
# .env file
OPENAI_API_KEY=your_openai_api_key_here
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.7
```

---

## 💻 Usage Examples

### Basic Domain Reconnaissance

```bash
python main.py --domain targetcorp.com
```

**Output:**
- Subdomain enumeration
- Asset discovery (sensitive files, endpoints)
- Technology stack fingerprinting
- Prioritized target list

### Complete User & Domain Intel

```bash
python main.py \
  --username johndoe \
  --name "John Doe" \
  --domain targetcorp.com
```

**Output:**
- Username correlation across platforms
- Email pattern generation
- Complete domain reconnaissance
- Attack surface prioritization

### Custom Output Paths

```bash
python main.py \
  --domain targetcorp.com \
  --output recon_results.json \
  --markdown pentest_report.md
```

### Advanced Options

```bash
python main.py \
  --domain targetcorp.com \
  --url https://app.targetcorp.com \
  --max-iterations 5 \
  --output results.json
```

### Sample Output

**Console Summary:**
```
=================================================================
OSINT WORKFLOW EXECUTION STARTED
=================================================================
Target: targetcorp.com
Start time: 2025-12-29T15:30:45.123456

[ASSET DISCOVERY] Discovering assets for domain: targetcorp.com
[ASSET DISCOVERY] Found 127 assets
[ASSET DISCOVERY] Breakdown: {'subdomain': 45, 'endpoint': 23, 'sensitive_file': 12, 'url': 47}

[TECH FINGERPRINT] Fingerprinting URL: https://targetcorp.com
[TECH FINGERPRINT] Server: nginx, Backend: php
[TECH FINGERPRINT] No WAF detected - direct access possible

[PRIORITIZATION] Analyzed 127 assets
[PRIORITIZATION] Critical: 3, High: 12, Medium: 45

[PRIORITIZATION] Top 3 targets:
  1. admin.targetcorp.com/login (score: 87.5, priority: critical)
  2. api.targetcorp.com/v1 (score: 78.3, priority: critical)
  3. dev.targetcorp.com (score: 72.1, priority: high)

=================================================================
FINAL INTELLIGENCE REPORT
=================================================================

📊 Assets Discovered: 127
   - subdomain: 45
   - endpoint: 23
   - sensitive_file: 12
   - url: 47

🎯 Priority Targets:
   - Critical: 3
   - High: 12
   - Medium: 45

🔥 Top 3 Targets:
   1. admin.targetcorp.com/login
      Score: 87.5/100 | Priority: CRITICAL
   2. api.targetcorp.com/v1
      Score: 78.3/100 | Priority: CRITICAL
   3. dev.targetcorp.com
      Score: 72.1/100 | Priority: HIGH

💾 JSON report saved: /path/to/osint_report_20251229_153045.json
📄 Markdown report saved: /path/to/osint_report_20251229_153045.md

✅ OSINT workflow completed successfully!
```

---

## 🎯 Real-World Offensive Use Cases

### 1. **Red Team Engagement - Initial Reconnaissance**

**Scenario:** External penetration test with minimal target information

**Workflow:**
```bash
python main.py --domain client-company.com --max-iterations 5
```

**Value:**
- Discover forgotten dev/staging environments
- Identify admin panels with weak authentication
- Find exposed configuration files and backups
- Map complete external attack surface
- Prioritize targets for exploitation phase

### 2. **Credential Attack Campaign**

**Scenario:** Targeted credential stuffing/password spraying

**Workflow:**
```bash
python main.py \
  --username john.smith \
  --name "John Smith" \
  --domain targetcorp.com
```

**Value:**
- Generate probable email addresses for target
- Validate email deliverability (MX records)
- Identify authentication endpoints
- Correlate username across breach databases
- Create focused target list for credential attacks

### 3. **Bug Bounty Reconnaissance**

**Scenario:** Expanding attack surface for bug bounty programs

**Workflow:**
```bash
python main.py --domain bugcrowd-target.com --output bb_recon.json
```

**Value:**
- Discover undocumented subdomains and endpoints
- Identify technology stack for vulnerability research
- Find sensitive file exposure (high-severity bugs)
- Locate legacy systems (old WordPress, Drupal versions)
- Prioritize testing efforts on highest-value assets

### 4. **Social Engineering Preparation**

**Scenario:** Spear-phishing campaign against executive team

**Workflow:**
```bash
python main.py \
  --username ceo \
  --name "Jane Doe" \
  --domain executive-target.com
```

**Value:**
- Discover CEO's social media presence
- Generate executive email patterns
- Identify corporate email infrastructure
- Map authentication mechanisms (OAuth providers)
- Build target dossier for social engineering

### 5. **Vulnerability Intelligence Correlation**

**Scenario:** Proactive vulnerability management for client

**Workflow:**
```bash
python main.py --domain client.com --markdown vuln_report.md
```

**Value:**
- Detect legacy/EOL technology versions
- Identify missing WAF/CDN protection
- Flag weak security header configurations
- Discover outdated CMS installations
- Generate prioritized remediation list

---

## 📊 Output Formats

### JSON Report
Complete raw data for programmatic analysis:
```json
{
  "domain": "targetcorp.com",
  "asset_discovery": {
    "total_assets": 127,
    "assets": [...],
    "categorized": {...}
  },
  "attack_surface_prioritization": {
    "top_targets": [...],
    "summary": {
      "critical": 3,
      "high": 12
    }
  }
}
```

### Markdown Report
Pentester-friendly formatted report with:
- Executive summary
- Asset breakdown
- Technology stack analysis
- Top 10 priority targets with attack recommendations
- Detailed scoring justifications

---

## ⚠️ Legal & Ethical Disclaimer

### **IMPORTANT: AUTHORIZED USE ONLY**

This framework is designed for **authorized security testing and research purposes only**. Unauthorized access to computer systems, networks, or data is illegal and punishable under various laws including:

- **United States**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **European Union**: General Data Protection Regulation (GDPR), Network and Information Security Directive
- **United Kingdom**: Computer Misuse Act 1990
- **International**: Council of Europe Convention on Cybercrime

### Authorized Use Cases

✅ **PERMITTED:**
- Red team engagements with signed contracts and scope agreements
- Penetration testing with explicit written authorization
- Bug bounty programs within defined scope
- Security research on owned infrastructure
- Educational purposes in controlled environments

❌ **PROHIBITED:**
- Scanning targets without explicit permission
- Unauthorized access to systems or data
- Harassment or stalking via OSINT
- Corporate espionage or competitive intelligence without authorization
- Any activity violating local, state, or federal laws

### User Responsibilities

By using this framework, you agree to:

1. **Obtain proper authorization** before conducting any reconnaissance
2. **Respect scope limitations** defined in engagement contracts
3. **Comply with all applicable laws** in your jurisdiction
4. **Use responsibly** and ethically in accordance with security industry standards
5. **Accept full responsibility** for your actions and their consequences

### Developer Disclaimer

The developers and contributors of this project:

- **Do not endorse** illegal or unethical use of this software
- **Are not responsible** for misuse or damages caused by users
- **Provide this tool** "as-is" without warranties of any kind
- **Encourage responsible disclosure** of vulnerabilities

**If you discover vulnerabilities using this tool, follow responsible disclosure practices and report findings to the affected organization through appropriate channels.**

---

## 🛠️ Project Structure

```
ai_offensive_osint/
├── README.md                              # This file
├── requirements.txt                       # Python dependencies
├── main.py                                # CLI entry point
├── .env.example                           # Environment template
├── .gitignore                            # Git ignore rules
│
├── agents/                                # Specialized OSINT agents
│   ├── __init__.py
│   ├── username_correlation_agent.py      # Username enumeration
│   ├── email_pattern_inference_agent.py   # Email generation
│   ├── asset_discovery_agent.py          # Attack surface mapping
│   ├── tech_stack_fingerprint_agent.py   # Technology detection
│   ├── attack_surface_prioritizer_agent.py # Target scoring
│   ├── recon_stop_decision_agent.py      # Workflow control
│   ├── recon_agent.py                    # Base recon (placeholder)
│   ├── vulnerability_agent.py            # Vuln scanning (placeholder)
│   └── intelligence_agent.py             # Intel correlation (placeholder)
│
├── graph/                                 # LangGraph orchestration
│   ├── __init__.py
│   ├── osint_langgraph.py                # Complete workflow implementation
│   ├── state.py                          # State definitions
│   ├── nodes.py                          # Node implementations
│   └── workflow.py                       # Workflow assembly
│
├── config/                                # Configuration management
│   └── __init__.py                       # Config loader
│
└── utils/                                 # Utility functions
    └── __init__.py
```

---

## 🔧 Development Roadmap

### Current Features (v1.0)
- ✅ Username correlation across 4 platforms
- ✅ Email pattern inference with DNS validation
- ✅ Comprehensive asset discovery
- ✅ Technology stack fingerprinting
- ✅ Attack surface prioritization
- ✅ Intelligent recon stop decisions
- ✅ LangGraph workflow orchestration
- ✅ JSON + Markdown reporting

### Future Enhancements (v2.0)
- [ ] LLM-powered intelligence analysis
- [ ] Shodan/Censys API integration
- [ ] Certificate transparency log analysis
- [ ] Breach data correlation
- [ ] Passive DNS lookup
- [ ] Screenshot capture for visual recon
- [ ] Port scanning integration
- [ ] Vulnerability correlation with CVE databases
- [ ] Real-time collaborative reporting
- [ ] Web UI dashboard

---

## 🤝 Contributing

Contributions are welcome! This project is designed for security professionals to extend and customize.

**Areas for contribution:**
- Additional reconnaissance agents
- New platform integrations
- Enhanced scoring algorithms
- Reporting format improvements
- Performance optimizations

**Guidelines:**
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit pull request with detailed description
5. Ensure all use cases remain **authorized and legal**

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

Built with:
- **LangGraph** - Workflow orchestration framework
- **aiohttp** - Asynchronous HTTP client
- **dnspython** - DNS resolution library
- **Python 3.10+** - Core programming language

Inspired by:
- OWASP reconnaissance methodologies
- Red team operational frameworks
- Open-source intelligence (OSINT) best practices

---

## 📞 Contact & Support

**Maintainer:** [Your Name]  
**Repository:** https://github.com/yourusername/ai_offensive_osint  
**Issues:** https://github.com/yourusername/ai_offensive_osint/issues

**For security-related questions or responsible disclosure:**  
Email: security@yourdomain.com

---

<div align="center">

**⚡ Built for Red Teams, by Security Professionals ⚡**

*Automate reconnaissance. Prioritize exploitation. Maximize impact.*

</div>

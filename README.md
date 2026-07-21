<div align="center">

# ⚔️ ReconX
### All-in-One Security Reconnaissance Framework

<p align="center">
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python">
<img src="https://img.shields.io/badge/Platform-Linux-success?style=for-the-badge&logo=linux">
<img src="https://img.shields.io/badge/License-MIT-orange?style=for-the-badge">
<img src="https://img.shields.io/badge/Version-v2.0-purple?style=for-the-badge">
<img src="https://img.shields.io/badge/Made%20for-Authorized%20Security%20Testing-red?style=for-the-badge">
</p>

**ReconX** is a modern **all-in-one Python security reconnaissance framework** that combines **20+ offensive security modules** into a single CLI application.

Designed for **penetration testers, bug bounty hunters, red teamers, and security researchers**, ReconX automates the entire reconnaissance phase—from DNS enumeration to vulnerability discovery and exposure hunting.

> ⚠️ **ReconX is intended for authorized security testing only.**
> Never scan systems without explicit permission.

</div>

---

# ✨ Features

ReconX combines multiple reconnaissance tools into a single command.

| Category | Modules |
|----------|---------|
| 🌐 Network | Port Scanner, Banner Grabbing, Service Detection, CVE Matching (NVD), Exploit Suggestions |
| 🌍 Web | Security Header Audit, Common File Checks, Directory Brute Force, Virtual Host Discovery, Parameter Fuzzing, API Discovery, Website Crawler |
| 🏗 Infrastructure | DNS Enumeration, WHOIS Lookup, SSL/TLS Analysis, Certificate Inspection, Security Grade |
| 🔍 OSINT | Subdomain Enumeration (crt.sh + HackerTarget), Wayback Machine URLs, Website Screenshots |
| ☁ Exposure Hunting | Secret Detection, AWS/GCP/Slack/GitHub Tokens, JWT Detection, Database Strings, Exposed .git Detection, Cloud Bucket Discovery |
| 🛡 Fingerprinting | WAF Detection, CMS Detection, Framework Detection, Web Server Detection, Technology Fingerprinting |

---

# 🚀 Highlights

- ⚡ High-speed multithreaded scanner
- 📊 Beautiful HTML reports
- 📄 JSON / Markdown / HTML / TXT export
- 🔥 Exploit suggestions
- 🎯 CVE matching via NVD
- 🧩 Plugin support
- 🛡 SSL/TLS grading (A-F)
- 📸 Website screenshots
- ☁ Cloud storage bucket discovery
- 🔑 Hardcoded secret detection
- 🌍 DNS & WHOIS enumeration
- 🔍 Wayback Machine integration
- 📡 Technology fingerprinting
- 🧠 Smart vulnerability suggestions

---

# 📦 Modules

## Network

- Port Scanner
- Banner Grabbing
- Service Detection
- CVE Lookup
- Exploit Suggestions

---

## Web

- Security Headers
- Directory Bruteforce
- Virtual Host Discovery
- API Endpoint Discovery
- Common File Detection
- Parameter Reflection Fuzzing
- Website Crawler

---

## Infrastructure

- DNS Enumeration
- WHOIS Lookup
- SSL/TLS Scanner
- Certificate Analysis
- Cipher Enumeration
- SSL Grade (A–F)

---

## OSINT

- Subdomain Enumeration
- Wayback URL Collection
- Website Screenshot (Selenium)

---

## Exposure Hunting

- AWS Keys
- GCP Keys
- Slack Tokens
- GitHub Tokens
- Stripe Keys
- JWT Detection
- Database Connection Strings
- Exposed .git Repository Detection
- Cloud Bucket Discovery
  - Amazon S3
  - Google Cloud Storage
  - Azure Blob

---

## Fingerprinting

- WAF Detection
- CMS Detection
- Framework Detection
- Technology Detection
- Server Fingerprinting

---

# 🖥 Installation

```bash
git clone https://github.com/USERNAME/ReconX.git

cd ReconX

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt
```

---

# Usage

```bash
python reconx.py -h
```

Example:

```bash
python reconx.py -t example.com -m all
```

Run specific modules

```bash
python reconx.py \
-t example.com \
-m portscan,cve,webaudit
```

Scan all ports

```bash
python reconx.py \
-t 192.168.1.10 \
-m portscan \
-p all \
--threads 300
```

Generate HTML report

```bash
python reconx.py \
-t example.com \
-m all \
--format html
```

---

# CLI Options

| Option | Description |
|---------|------------|
| `-t` | Target Host / Domain |
| `-m` | Modules |
| `-p` | Ports |
| `--threads` | Thread Count |
| `--timeout` | Timeout |
| `--cve-api-key` | NVD API Key |
| `--report` | Generate report from JSON |
| `--format` | txt/html/md/json |
| `--plugins` | List plugins |
| `--output` | Output Directory |

---

# 📷 Screenshots

## Help Menu

<p align="center">
<img src="images/help.png" width="95%">
</p>

---

## Port Scanner

<p align="center">
<img src="images/portscan.png" width="95%">
</p>

---

# 📷 Screenshots

## Help Menu

<p align="center">
<img src="images/1.png" width="95%">
</p>

---

## Port Scanner

<p align="center">
<img src="images/2.png" width="95%">
</p>

---

## Exploit Suggestions

<p align="center">
<img src="images/3.png" width="95%">
</p>

---

## HTML Report Dashboard

<p align="center">
<img src="images/4.png" width="95%">
</p>

---

## HTML Exploit Report

<p align="center">
<img src="images/5.png" width="95%">
</p>

---

## DNS + SSL Analysis

<p align="center">
<img src="images/6.png" width="95%">
</p>

---

# 📊 Report Formats

ReconX supports:

- HTML
- Markdown
- JSON
- TXT

Example:

```bash
python reconx.py \
-t google.com \
-m all \
--format html
```

---

# Example Commands

Scan everything

```bash
python reconx.py \
-t example.com \
-m all
```

Network assessment

```bash
python reconx.py \
-t 192.168.1.20 \
-m portscan,cve,exploits
```

Infrastructure

```bash
python reconx.py \
-t google.com \
-m ssl,dns,whois
```

Web Assessment

```bash
python reconx.py \
-t example.com \
-m webaudit,dirsearch,apis,crawler
```

OSINT

```bash
python reconx.py \
-t example.com \
-m subdomains,wayback,screenshot
```

Exposure Hunting

```bash
python reconx.py \
-t example.com \
-m secrets,git,buckets
```

---

# Project Structure

```
ReconX/
│
├── reconx.py
├── modules/
├── plugins/
├── reports/
├── screenshots/
├── templates/
├── requirements.txt
└── README.md
```

---

# Roadmap

- [ ] AI-assisted vulnerability explanations
- [ ] Shodan integration
- [ ] Censys integration
- [ ] IPv6 support
- [ ] Nuclei integration
- [ ] Masscan integration
- [ ] Async scanning engine
- [ ] Docker support
- [ ] PDF reports
- [ ] CVSS Risk Dashboard
- [ ] REST API
- [ ] Web UI

---

# Security Notice

ReconX is developed **strictly for legal and authorized penetration testing**.

The developers assume **no liability** for misuse.

Always obtain written authorization before scanning any system.

---

# Contributing

Pull requests are welcome.

For major changes, open an issue first to discuss what you would like to improve.

---

# Author

## root_0xM

Python Security Researcher

ReconX Framework Creator

---

<div align="center">

### ⭐ If you like ReconX, don't forget to Star the repository!

Made with ❤️ for the Cyber Security Community.

</div>

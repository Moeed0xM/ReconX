#!/usr/bin/env python3
"""
ReconX - All-in-One Security Scanner
=====================================
Port scan + CVE matching | Web audit | DNS | SSL | WHOIS | Subdomains |
Directories | VHosts | Param Fuzzing | API endpoints | Crawling |
Wayback | Screenshots | WAF detection | Tech fingerprint |
Secret/Git exposure | Cloud bucket discovery

Author: Internship Project
License: Educational use only - get written authorization before scanning.
"""

import argparse
import concurrent.futures
import json
import os
import re
import html
import socket
import ssl
import sys
import threading
import time
import hashlib
import base64
import datetime
import subprocess
import shutil
from urllib.parse import urljoin, urlparse, urlsplit
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any

# Suppress Unverified HTTPS Warnings
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
    from rich.markdown import Markdown
    from rich.text import Text
    from rich.align import Align
    from rich import box as rich_box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    class _StubConsole:
        def print(self, *args, **kwargs):
            try:
                print(args[0].__str__() if hasattr(args[0], '__str__') else args[0])
            except Exception:
                print(*args)
        def rule(self, *a, **k): print("=" * 60)
    console = _StubConsole()

# Optional libs (degrade gracefully)
try:
    import dns.resolver
    DNSPY_AVAILABLE = True
except ImportError:
    DNSPY_AVAILABLE = False

try:
    from selenium import webdriver
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# ============================================================
# CONFIGURATION
# ============================================================
DEFAULT_CONFIG = {
    "threads": 50,
    "timeout": 5,
    "user_agent": "Mozilla/5.0 (compatible; ReconX/1.0; SecurityScanner)",
    "cve_api": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cpe_api": "https://services.nvd.nist.gov/rest/json/cpes/2.0",
    "epss_api": "https://api.first.org/data/v1/epss",
    "cisa_kev_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cve_api_key": "",  # optional NVD API key
    "wordlist_dir": "wordlists",
    "report_dir": "reports",
    "subdomains_top": 1000,
    "verify_ssl": False,
    "follow_redirects": True,
    "nmap_fallback": True,
}

# ============================================================
# DATA CLASSES
# ============================================================
@dataclass
class ScanResult:
    target: str
    timestamp: str = ""
    port_scan: Dict = field(default_factory=dict)
    cves: List = field(default_factory=list)
    web_audit: Dict = field(default_factory=dict)
    dns: Dict = field(default_factory=dict)
    ssl: Dict = field(default_factory=dict)
    whois: Dict = field(default_factory=dict)
    subdomains: List = field(default_factory=list)
    directories: List = field(default_factory=list)
    vhosts: List = field(default_factory=list)
    param_fuzz: List = field(default_factory=list)
    api_endpoints: List = field(default_factory=list)
    crawl: List = field(default_factory=list)
    wayback: List = field(default_factory=list)
    screenshots: List = field(default_factory=list)
    waf: Dict = field(default_factory=dict)
    tech: Dict = field(default_factory=dict)
    secrets: List = field(default_factory=list)
    git_exposure: Dict = field(default_factory=dict)
    cloud_buckets: List = field(default_factory=list)
    exploits: List = field(default_factory=list)

# ============================================================
# UTILITY FUNCTIONS
# ============================================================
VERSION = "2.0"

def banner():
    if RICH_AVAILABLE:
        title = Text("ReconX", style="bold cyan")
        title.append("  All-in-One Security Scanner", style="bold white")
        subtitle = Text(f"by root_0xM  ·  v{VERSION}  ·  authorized security testing only",
                         style="dim italic")
        body = Align.center(Text.assemble(title, "\n", subtitle))
        console.print(Panel(body, box=rich_box.DOUBLE, border_style="cyan",
                             padding=(1, 4), expand=False))
    else:
        lines = ["ReconX - All-in-One Security Scanner", f"by root_0xM  v{VERSION}"]
        width = max(len(l) for l in lines) + 4
        print("+" + "-" * width + "+")
        for l in lines:
            print("| " + l.center(width - 2) + " |")
        print("+" + "-" * width + "+")

def info(msg, indent=0):
    pad = "  " * indent
    console.print(f"{pad}[bold cyan]›[/] {msg}") if RICH_AVAILABLE else print(f"{pad}[*] {msg}")

def good(msg, indent=0):
    pad = "  " * indent
    console.print(f"{pad}[bold green]✔[/] {msg}") if RICH_AVAILABLE else print(f"{pad}[+] {msg}")

def warn(msg, indent=0):
    pad = "  " * indent
    console.print(f"{pad}[bold yellow]⚠[/] [yellow]{msg}[/]") if RICH_AVAILABLE else print(f"{pad}[!] {msg}")

def bad(msg, indent=0):
    pad = "  " * indent
    console.print(f"{pad}[bold red]✘[/] [red]{msg}[/]") if RICH_AVAILABLE else print(f"{pad}[-] {msg}")

def section(t):
    if RICH_AVAILABLE:
        console.print()
        console.rule(f"[bold white on dark_magenta]  {t}  [/]", style="magenta", characters="─")
    else:
        print(f"\n{'-'*70}\n  {t}\n{'-'*70}")

def make_session(cfg) -> "requests.Session":
    if not REQUESTS_AVAILABLE:
        return None
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retry, pool_connections=cfg["threads"], pool_maxsize=cfg["threads"]))
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_connections=cfg["threads"], pool_maxsize=cfg["threads"]))
    s.headers.update({"User-Agent": cfg["user_agent"]})
    return s

def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def save_json(data, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    good(f"Saved: {path}")

# ============================================================
# 1. PORT SCANNER + SERVICE FINGERPRINTING
# ============================================================
COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,587,993,995,
                1433,1521,2049,2375,2376,3306,3389,5432,5900,5985,5986,
                6379,6443,8000,8080,8443,8888,9000,9090,9200,9300,11211,27017]

# Full TCP port range (1-65535). Used when the user requests an "all ports" scan
# (e.g. --ports all, or -p-  equivalent to nmap's -p-). This is exhaustive but
# much slower than COMMON_PORTS - bump --threads and/or --timeout accordingly.
ALL_PORTS = list(range(1, 65536))


def parse_ports(spec: Optional[str]) -> Optional[List[int]]:
    """Parse a --ports argument into a sorted list of unique port numbers.

    Accepts:
      - None / ""      -> None (caller should fall back to COMMON_PORTS)
      - "all" / "-"     -> full 1-65535 range
      - "80,443,8080"   -> explicit list
      - "1-1024"        -> inclusive range
      - "22,80,1000-2000,8443" -> mixed list/ranges
    """
    if not spec:
        return None
    spec = spec.strip().lower()
    if spec in ("all", "-", "1-65535"):
        return ALL_PORTS
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            start = max(1, start)
            end = min(65535, end)
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports) if ports else None

BANNER_GRABS = {
    21: b"USER anonymous\r\n",
    22: b"",
    25: b"EHLO reconx\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"CAPA\r\n",
    143: b"A1 CAPABILITY\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    3306: b"",
    6379: b"PING\r\n",
    11211: b"version\r\n",
    27017: b"",
}

class PortScanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.results = []

    def _scan(self, host, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.cfg["timeout"])
            r = s.connect_ex((ip, port))
            if r == 0:
                banner = self._grab_banner(ip, port)
                service = self._guess_service(port, banner)
                with self.lock:
                    self.results.append({"port": port, "state": "open",
                                         "banner": banner[:200], "service": service})
                    good(f"{host}:{port} OPEN  - {service}")
            s.close()
        except Exception:
            pass

    def _grab_banner(self, ip, port):
        try:
            s = socket.socket()
            s.settimeout(self.cfg["timeout"])
            s.connect((ip, port))
            payload = BANNER_GRABS.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
            if payload:
                s.send(payload)
            data = s.recv(2048).decode(errors="ignore").strip()
            s.close()
            return data
        except Exception:
            return ""

    def _guess_service(self, port, banner):
        std = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
               143:"imap",443:"https",445:"smb",3306:"mysql",5432:"postgres",
               3389:"rdp",6379:"redis",27017:"mongodb",9200:"elasticsearch",
               11211:"memcached",5900:"vnc"}
        if port in std:
            base = std[port]
        elif banner:
            low = banner.lower()
            if "ssh" in low: base="ssh"
            elif "ftp" in low: base="ftp"
            elif "smtp" in low or "postfix" in low: base="smtp"
            elif "mysql" in low: base="mysql"
            elif "redis" in low: base="redis"
            elif "http" in low: base="http"
            elif "microsoft" in low and "iis" in low: base="http"
            else: base="unknown"
        else:
            base = "unknown"
        return f"{base}"

    def scan(self, host, ports=None):
        section(f"Port Scan: {host}")
        ip = resolve_host(host)
        if not ip:
            bad(f"Cannot resolve {host}")
            return {}
        info(f"Resolved {host} -> {ip}")
        ports = ports or COMMON_PORTS
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg["threads"]) as ex:
            list(ex.map(lambda p: self._scan(host, ip, p), ports))
        self.results.sort(key=lambda x: x["port"])
        return {"ip": ip, "ports": self.results}

# ============================================================
# 2. SERVICE FINGERPRINTING - HTTP HEADERS / TECH
# ============================================================
class ServiceFingerprinter:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def fingerprint(self, host, port_scan):
        section(f"Service Fingerprinting: {host}")
        results = {}
        for p in port_scan.get("ports", []):
            if p["service"] in ("http", "https") or p["port"] in (80,443,8080,8443,8000,8888):
                proto = "https" if p["port"] in (443,8443,6443) else "http"
                url = f"{proto}://{host}:{p['port']}/"
                try:
                    r = self.s.get(url, timeout=self.cfg["timeout"],
                                   verify=self.cfg["verify_ssl"],
                                   allow_redirects=self.cfg["follow_redirects"])
                    server = r.headers.get("Server","")
                    powered = r.headers.get("X-Powered-By","")
                    results[p["port"]] = {"server": server, "x_powered_by": powered,
                                          "status": r.status_code, "title": self._title(r.text)}
                    good(f"{url} -> {server} | {powered} | {r.status_code}")
                except Exception as e:
                    results[p["port"]] = {"error": str(e)}
        return results

    @staticmethod
    def _title(html):
        m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I|re.S)
        return m.group(1).strip()[:120] if m else ""

# ============================================================
# 3. CVE MATCHING (NVD API - CPE-driven)
# ============================================================
def extract_product_version(banner_text, service_hint=""):
    """Best-effort (product, version) extraction from a raw service banner.
    Falls back to the guessed service name with no version if nothing matches."""
    if banner_text:
        # e.g. "Apache/2.4.49", "OpenSSH_7.4", "nginx/1.18.0", "vsftpd 2.3.4"
        m = re.search(r"([A-Za-z][\w\-\.]*)[/_ ]v?(\d+(?:\.\d+){1,3})", banner_text)
        if m:
            return m.group(1), m.group(2)
    return (service_hint or "", "")


class CVEMatcher:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def _headers(self):
        h = {}
        if self.cfg["cve_api_key"]:
            h["apiKey"] = self.cfg["cve_api_key"]
        return h

    def find_cpe(self, product, version=""):
        """Look up the NVD CPE dictionary for the CPE 2.3 name that best matches
        the fingerprinted product (and version, if we have one)."""
        if not REQUESTS_AVAILABLE or not product:
            return None
        try:
            r = self.s.get(self.cfg["cpe_api"], params={"keywordSearch": product, "resultsPerPage": 30},
                            headers=self._headers(), timeout=15)
            if r.status_code != 200:
                return None
            candidates = [p.get("cpe", {}).get("cpeName", "")
                          for p in r.json().get("products", [])]
            candidates = [c for c in candidates if c]
            if not candidates:
                return None
            if version:
                for c in candidates:
                    if f":{version}:" in c or c.endswith(f":{version}"):
                        return c
                major_minor = ".".join(version.split(".")[:2])
                for c in candidates:
                    if f":{major_minor}" in c:
                        return c
            return candidates[0]
        except Exception:
            return None

    def query_by_cpe(self, cpe):
        """Exact-match CVE lookup for a specific CPE - the precise version of the
        service, not just a keyword guess."""
        if not REQUESTS_AVAILABLE or not cpe:
            return []
        try:
            r = self.s.get(self.cfg["cve_api"], params={"cpeName": cpe, "resultsPerPage": 20},
                            headers=self._headers(), timeout=20)
            if r.status_code != 200:
                warn(f"NVD CPE query returned {r.status_code}")
                return []
            return self._parse(r.json())
        except Exception as e:
            warn(f"NVD CPE query failed: {e}")
            return []

    def search(self, keyword):
        """Fallback keyword search, used when no exact CPE can be resolved."""
        if not REQUESTS_AVAILABLE: return []
        try:
            params = {"keywordSearch": keyword, "resultsPerPage": 10}
            r = self.s.get(self.cfg["cve_api"], params=params, headers=self._headers(), timeout=15)
            if r.status_code != 200:
                warn(f"NVD API returned {r.status_code}")
                return []
            return self._parse(r.json())
        except Exception as e:
            warn(f"CVE lookup failed: {e}")
            return []

    @staticmethod
    def _parse(data):
        cves = []
        for v in data.get("vulnerabilities", [])[:20]:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:300]; break
            cvss, severity = "", ""
            metrics = cve.get("metrics", {})
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(k):
                    cd = metrics[k][0].get("cvssData", {})
                    cvss = cd.get("baseScore", "")
                    severity = cd.get("baseSeverity", metrics[k][0].get("baseSeverity", ""))
                    break
            refs = [r.get("url") for r in cve.get("references", [])[:5]]
            cves.append({"id": cve_id, "cvss": cvss, "severity": severity, "desc": desc, "refs": refs})
        return cves

    def match_services(self, port_scan):
        section("CVE Matching (Banner -> Product/Version -> CPE -> NVD)")
        all_cves = []
        seen = set()
        for p in port_scan.get("ports", []):
            product, version = extract_product_version(p.get("banner", ""), p["service"])
            if not product or product == "unknown":
                continue
            key = f"{product}:{version}"
            if key in seen:
                continue
            seen.add(key)
            info(f"Fingerprint: {product} {version}".strip())

            cpe = self.find_cpe(product, version)
            cves = []
            if cpe:
                good(f"  Resolved CPE: {cpe}")
                cves = self.query_by_cpe(cpe)

            if not cves:
                keyword = f"{product} {version}".strip()
                info(f"  No CPE match / no CVEs from CPE - falling back to keyword search: {keyword}")
                cves = self.search(keyword)

            for c in cves:
                good(f"  {c['id']} (CVSS {c['cvss']}{' ' + c['severity'] if c['severity'] else ''})")

            if cves:
                all_cves.append({"service": product, "version": version, "port": p["port"],
                                  "cpe": cpe, "cves": cves})
            time.sleep(1)  # NVD rate-limit friendly (5 req/min without API key)
        return all_cves

# ============================================================
# 4. WEB APPLICATION SECURITY AUDIT
# ============================================================
class WebAuditor:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def audit(self, host, port_scan):
        section(f"Web Application Audit: {host}")
        findings = []
        # find web ports
        web_ports = [p["port"] for p in port_scan.get("ports",[])
                     if p["service"] in ("http","https") or p["port"] in (80,443,8080,8443,8000,8888,9000)]
        for port in web_ports:
            proto = "https" if port in (443,8443) else "http"
            base = f"{proto}://{host}:{port}"
            findings.extend(self._security_headers(base))
            findings.extend(self._check_robots(base))
            findings.extend(self._check_common_files(base))
        return {"findings": findings, "web_ports": web_ports}

    def _security_headers(self, url):
        out = []
        try:
            r = self.s.get(url, timeout=self.cfg["timeout"], verify=self.cfg["verify_ssl"])
            missing = []
            for h in ["Strict-Transport-Security","Content-Security-Policy",
                      "X-Frame-Options","X-Content-Type-Options",
                      "Referrer-Policy","Permissions-Policy"]:
                if h not in r.headers:
                    missing.append(h)
            if missing:
                out.append({"type":"missing_security_headers","url":url,"severity":"medium","detail":missing})
                warn(f"{url} missing headers: {', '.join(missing)}")
            if "Server" in r.headers:
                out.append({"type":"server_header_disclosed","url":url,"severity":"low","detail":r.headers["Server"]})
            if "X-Powered-By" in r.headers:
                out.append({"type":"xpowered_disclosed","url":url,"severity":"low","detail":r.headers["X-Powered-By"]})
        except Exception as e:
            out.append({"type":"error","url":url,"detail":str(e)})
        return out

    def _check_robots(self, url):
        out = []
        try:
            r = self.s.get(urljoin(url,"/robots.txt"), timeout=self.cfg["timeout"], verify=self.cfg["verify_ssl"])
            if r.status_code == 200 and ("Disallow" in r.text or "Allow" in r.text):
                out.append({"type":"robots_txt","url":urljoin(url,"/robots.txt"),"severity":"info","detail":r.text[:500]})
                good(f"robots.txt found at {url}")
        except Exception: pass
        return out

    def _check_common_files(self, url):
        out = []
        files = ["/.env","/.git/config","/.svn/entries","/admin","/admin.php","/wp-admin/",
                 "/phpinfo.php","/backup.zip","/.DS_Store","/server-status","/.well-known/security.txt"]
        def check(path):
            try:
                r = self.s.get(urljoin(url,path), timeout=self.cfg["timeout"], verify=self.cfg["verify_ssl"])
                if r.status_code == 200 and len(r.content) > 0:
                    out.append({"type":"exposed_file","url":urljoin(url,path),"severity":"high","detail":r.status_code})
                    bad(f"Exposed: {urljoin(url,path)} ({r.status_code})")
            except Exception: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(check, files))
        return out

# ============================================================
# 5. DNS ENUMERATION
# ============================================================
class DnsEnumerator:
    def __init__(self, cfg): self.cfg = cfg

    def enumerate(self, host):
        section(f"DNS Enumeration: {host}")
        records = {}
        rtypes = ["A","AAAA","NS","MX","TXT","CNAME","SOA","SRV","CAA"]
        for rt in rtypes:
            try:
                if DNSPY_AVAILABLE:
                    answers = dns.resolver.resolve(host, rt, lifetime=self.cfg["timeout"])
                    records[rt] = [str(a) for a in answers]
                else:
                    # fallback to dig if available
                    out = subprocess.run(["dig","+short",rt,host], capture_output=True, text=True, timeout=self.cfg["timeout"])
                    if out.stdout.strip():
                        records[rt] = out.stdout.strip().splitlines()
                if rt in records:
                    good(f"{rt}: {records[rt]}")
            except Exception:
                pass
        return records

# ============================================================
# 6. SSL/TLS ANALYSIS (Subprocess OpenSSL)
# ============================================================
# Protocol flags tried against the target to build a support matrix.
# Older protocols are intentionally included so their presence can be
# flagged as a weakness - openssl itself will simply fail to connect
# if a protocol has been compiled out or disabled server-side.
TLS_PROTOCOL_FLAGS = [
    ("SSLv3",   "-ssl3"),
    ("TLSv1.0", "-tls1"),
    ("TLSv1.1", "-tls1_1"),
    ("TLSv1.2", "-tls1_2"),
    ("TLSv1.3", "-tls1_3"),
]

WEAK_PROTOCOLS = {"SSLv3", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHER_KEYWORDS = ["NULL", "EXPORT", "DES", "RC4", "MD5", "ADH", "AECDH", "anon", "3DES"]


class SslAnalyzer:
    def __init__(self, cfg): self.cfg = cfg

    def _run(self, cmd, timeout=None):
        try:
            out = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT,
                                  timeout=timeout or (self.cfg["timeout"] + 5))
            return out.stdout.decode(errors="ignore")
        except Exception:
            return ""

    def analyze(self, host, port=443):
        section(f"SSL/TLS Analysis: {host}:{port}")
        data = {
            "certificate": {},
            "protocols": {},
            "cipher": {},
            "security_assessment": {"issues": [], "grade_notes": []},
        }
        try:
            handshake = self._run(
                f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>&1"
            )
            if not handshake:
                data["error"] = "No response from target - connection failed"
                bad("SSL analysis failed: no response from target")
                return data

            # ---- Negotiated protocol & cipher from the default handshake ----
            proto_m = re.search(r"Protocol\s*:\s*(\S+)", handshake)
            cipher_m = re.search(r"Cipher\s*:\s*(\S+)|New,\s*(\S+),\s*Cipher is (\S+)", handshake)
            negotiated_protocol = proto_m.group(1) if proto_m else ""
            if cipher_m:
                negotiated_cipher = cipher_m.group(1) or cipher_m.group(3) or ""
            else:
                negotiated_cipher = ""
            data["cipher"]["negotiated_protocol"] = negotiated_protocol
            data["cipher"]["negotiated_cipher"] = negotiated_cipher
            if negotiated_protocol:
                good(f"Negotiated protocol: {negotiated_protocol}")
            if negotiated_cipher:
                good(f"Negotiated cipher suite: {negotiated_cipher}")

            # key exchange / signature info if openssl printed it (1.1+ verbose)
            kex_m = re.search(r"Server Temp Key:\s*(.+)", handshake)
            if kex_m:
                data["cipher"]["server_temp_key"] = kex_m.group(1).strip()
                good(f"Key exchange: {data['cipher']['server_temp_key']}")

            if any(k in negotiated_cipher.upper() for k in WEAK_CIPHER_KEYWORDS) and negotiated_cipher:
                data["security_assessment"]["issues"].append(
                    {"severity": "high", "issue": f"Weak cipher negotiated: {negotiated_cipher}"})
                bad(f"Weak cipher in use: {negotiated_cipher}")

            # ---- Certificate details ----
            cert_text = self._run(
                f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | "
                f"openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256 "
                f"-pubkey -text 2>/dev/null"
            )
            cert = data["certificate"]
            if cert_text:
                cert["subject"] = self._extract(cert_text, "subject=")
                cert["issuer"] = self._extract(cert_text, "issuer=")
                cert["not_before"] = self._extract(cert_text, "notBefore=")
                cert["not_after"] = self._extract(cert_text, "notAfter=")
                cert["serial"] = self._extract(cert_text, "serial=")
                fp_m = re.search(r"SHA256 Fingerprint=([0-9A-Fa-f:]+)", cert_text)
                cert["sha256_fingerprint"] = fp_m.group(1) if fp_m else ""

                sig_m = re.search(r"Signature Algorithm:\s*(\S+)", cert_text)
                cert["signature_algorithm"] = sig_m.group(1) if sig_m else ""

                keysize_m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", cert_text)
                cert["public_key_bits"] = int(keysize_m.group(1)) if keysize_m else None

                keytype = "RSA" if "rsaEncryption" in cert_text else \
                          "EC" if "id-ecPublicKey" in cert_text else \
                          "DSA" if "dsaEncryption" in cert_text else "unknown"
                cert["public_key_type"] = keytype

                sans = re.findall(r"DNS:([^,\s]+)", cert_text)
                cert["subject_alternative_names"] = sans

                cert["is_self_signed"] = bool(cert["subject"]) and cert["subject"] == cert["issuer"]

                good(f"Subject: {cert.get('subject')}")
                good(f"Issuer: {cert.get('issuer')}")
                good(f"Key: {cert.get('public_key_type')} {cert.get('public_key_bits')} bit | Sig alg: {cert.get('signature_algorithm')}")
                if sans:
                    good(f"SANs: {', '.join(sans[:8])}{' ...' if len(sans) > 8 else ''}")

                # Expiry
                if cert.get("not_after"):
                    date_str = cert["not_after"].replace("GMT", "").strip()
                    try:
                        exp = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
                        days_left = (exp - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                        cert["days_until_expiry"] = days_left
                        if days_left < 0:
                            bad(f"Certificate EXPIRED {abs(days_left)} days ago")
                            data["security_assessment"]["issues"].append(
                                {"severity": "critical", "issue": f"Certificate expired {abs(days_left)} days ago"})
                        elif days_left < 30:
                            warn(f"Certificate expires in {days_left} days")
                            data["security_assessment"]["issues"].append(
                                {"severity": "medium", "issue": f"Certificate expires soon ({days_left} days)"})
                        else:
                            good(f"Certificate valid for {days_left} more days")
                    except Exception:
                        pass

                if cert.get("is_self_signed"):
                    warn("Certificate is self-signed")
                    data["security_assessment"]["issues"].append(
                        {"severity": "medium", "issue": "Certificate is self-signed"})

                if cert.get("public_key_bits") and cert["public_key_type"] == "RSA" and cert["public_key_bits"] < 2048:
                    bad(f"Weak RSA key size: {cert['public_key_bits']} bits")
                    data["security_assessment"]["issues"].append(
                        {"severity": "high", "issue": f"RSA key under 2048 bits ({cert['public_key_bits']})"})

                if cert.get("signature_algorithm") and re.search(r"md5|sha1", cert["signature_algorithm"], re.I):
                    bad(f"Weak signature algorithm: {cert['signature_algorithm']}")
                    data["security_assessment"]["issues"].append(
                        {"severity": "high", "issue": f"Weak signature algorithm: {cert['signature_algorithm']}"})
            else:
                data["error"] = "No certificate retrieved"
                bad("SSL analysis failed: No certificate retrieved")

            # ---- Protocol support matrix ----
            info(f"Probing supported TLS/SSL protocol versions on {host}:{port} ...")
            for name, flag in TLS_PROTOCOL_FLAGS:
                out = self._run(
                    f"echo | timeout {self.cfg['timeout']} openssl s_client {flag} "
                    f"-connect {host}:{port} -servername {host} 2>&1",
                    timeout=self.cfg["timeout"] + 3,
                )
                supported = ("Cipher is" in out or "Cipher    :" in out) and "handshake failure" not in out.lower() \
                            and "no protocols available" not in out.lower() and "unknown option" not in out.lower()
                data["protocols"][name] = supported
                if supported:
                    if name in WEAK_PROTOCOLS:
                        warn(f"{name}: SUPPORTED (outdated / insecure)")
                        data["security_assessment"]["issues"].append(
                            {"severity": "high" if name == "SSLv3" else "medium",
                             "issue": f"Server supports outdated protocol {name}"})
                    else:
                        good(f"{name}: supported")
                else:
                    info(f"{name}: not supported")

            if data["protocols"].get("TLSv1.3"):
                data["security_assessment"]["grade_notes"].append("Supports modern TLS 1.3")
            if not data["protocols"].get("TLSv1.2") and not data["protocols"].get("TLSv1.3"):
                data["security_assessment"]["issues"].append(
                    {"severity": "critical", "issue": "No modern TLS (1.2/1.3) support detected"})

            # ---- Overall grade ----
            sev_rank = {"critical": 3, "high": 2, "medium": 1, "info": 0}
            issues = data["security_assessment"]["issues"]
            worst = max((sev_rank.get(i["severity"], 0) for i in issues), default=-1)
            grade = {-1: "A", 0: "A-", 1: "B", 2: "C", 3: "F"}[worst if worst >= 0 else -1]
            data["security_assessment"]["overall_grade"] = grade
            data["security_assessment"]["issue_count"] = len(issues)
            if issues:
                warn(f"SSL/TLS security grade: {grade} ({len(issues)} issue(s) found)")
            else:
                good(f"SSL/TLS security grade: {grade} (no issues found)")

        except Exception as e:
            data["error"] = str(e)
            bad(f"SSL analysis failed: {e}")
        return data

    @staticmethod
    def _extract(text, key):
        return text.split(key)[1].split("\n")[0].strip() if key in text else ""

# ============================================================
# 7. WHOIS LOOKUP (System subprocess)
# ============================================================
class WhoisLookup:
    def __init__(self, cfg): self.cfg = cfg

    def lookup(self, host):
        section(f"WHOIS Lookup: {host}")
        result = {}
        try:
            # Using system whois is often faster and more reliable than the python module
            out = subprocess.run(["whois", host], capture_output=True, text=True, timeout=15)
            if out.stdout:
                result["raw"] = out.stdout[:5000]
                # Try to extract basic fields via regex for nicer output
                def grep(pattern, text):
                    m = re.search(pattern, text, re.I)
                    return m.group(1).strip() if m else "N/A"
                
                result["domain_name"] = grep(r"Domain Name:\s*(.+)", out.stdout)
                result["registrar"] = grep(r"Registrar:\s*(.+)", out.stdout)
                result["creation_date"] = grep(r"Creation Date:\s*(.+)", out.stdout)
                result["expiration_date"] = grep(r"Registry Expiry Date:\s*(.+)|Expiration Date:\s*(.+)", out.stdout)
                result["name_servers"] = re.findall(r"Name Server:\s*(.+)", out.stdout, re.I)
                
                for k in ("domain_name","registrar","creation_date","expiration_date"):
                    if k in result and result[k] != "N/A": good(f"{k}: {result[k]}")
                good("WHOIS retrieved via system binary")
        except Exception as e:
            result["error"] = str(e)
            bad(f"WHOIS failed: {e}")
        return result

# ============================================================
# 8. SUBDOMAIN ENUMERATION
# ============================================================
SUBDOMAIN_SOURCES = [
    "https://crt.sh/?q=%25.{domain}&output=json",
    "https://api.hackertarget.com/hostsearch/?q={domain}",
]

class SubdomainEnumerator:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def enumerate(self, domain, top_n=None):
        section(f"Subdomain Enumeration: {domain}")
        subs = set()
        for src in SUBDOMAIN_SOURCES:
            url = src.format(domain=domain)
            try:
                r = self.s.get(url, timeout=15)
                if r.status_code == 200:
                    if "crt.sh" in url:
                        for entry in r.json():
                            name = entry.get("name_value","")
                            for n in name.split("\n"):
                                if domain in n: subs.add(n.strip().lstrip("*."))
                    else:
                        for line in r.text.splitlines():
                            parts = line.split(",")
                            if parts and domain in parts[0]:
                                subs.add(parts[0].strip())
            except Exception: pass
        subs = sorted(subs)
        if top_n: subs = subs[:top_n]
        for s in subs: good(f"  {s}")
        return subs

# ============================================================
# 9. DIRECTORY & FILE DISCOVERY
# ============================================================
SMALL_WORDLIST = [
    "admin","login","api","backup","config","dashboard","db","debug","dev",
    "test","old","new","tmp","temp","uploads","files","images","js","css",
    "vendor","node_modules",".git",".env",".svn",".htaccess","wp-admin",
    "wp-content","phpmyadmin","console","status","health","metrics","swagger",
    "graphql","sitemap.xml","robots.txt",".well-known/security.txt","server-status"
]

class DirectoryBruteforcer:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def discover(self, base_url, wordlist=None):
        section(f"Directory Discovery: {base_url}")
        found = []
        words = wordlist or SMALL_WORDLIST
        def check(word):
            url = urljoin(base_url, word)
            try:
                r = self.s.get(url, timeout=self.cfg["timeout"], verify=self.cfg["verify_ssl"],
                               allow_redirects=False)
                if r.status_code in (200,301,302,401,403):
                    found.append({"path": word, "status": r.status_code, "length": len(r.content)})
                    good(f"  {url} [{r.status_code}] ({len(r.content)} bytes)")
            except Exception: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg["threads"]) as ex:
            list(ex.map(check, words))
        return found

# ============================================================
# 10. VIRTUAL HOST DISCOVERY
# ============================================================
class VhostDiscovery:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def discover(self, ip, base_host, wordlist=None):
        section(f"Virtual Host Discovery: {ip} ({base_host})")
        vhosts = []
        candidates = wordlist or ["admin","mail","dev","test","staging","api","vpn",
                                  "portal","dashboard","internal","beta","demo","shop","blog"]
        def check(sub):
            host = f"{sub}.{base_host}"
            try:
                r = self.s.get(f"http://{ip}/", headers={"Host": host}, timeout=self.cfg["timeout"],
                               verify=False, allow_redirects=False)
                # compare response length / title with baseline
                baseline = self.s.get(f"http://{ip}/", timeout=self.cfg["timeout"],
                                       verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.content) != len(baseline.content):
                    vhosts.append({"host": host, "status": r.status_code, "length": len(r.content)})
                    good(f"  VHost: {host} [{r.status_code}] ({len(r.content)} bytes)")
            except Exception: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(check, candidates))
        return vhosts

# ============================================================
# 11. PARAMETER FUZZING
# ============================================================
PARAM_LIST = ["id","q","search","query","page","cmd","exec","file","name","user",
              "url","redirect","next","path","debug","test","item","action",
              "data","type","sort","filter","cat","category"]

class ParameterFuzzer:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def fuzz(self, url):
        section(f"Parameter Fuzzing: {url}")
        reflections = []
        marker = "reconxmarker"
        def check(param):
            try:
                r = self.s.get(url, params={param: marker}, timeout=self.cfg["timeout"],
                               verify=False, allow_redirects=False)
                if marker in r.text:
                    reflections.append({"param": param, "reflected": True, "status": r.status_code})
                    bad(f"  Reflected: {param}")
            except Exception: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(check, PARAM_LIST))
        return reflections

# ============================================================
# 12. API ENDPOINT DISCOVERY
# ============================================================
API_PATHS = ["/api","/api/v1","/api/v2","/api/users","/api/login","/api/auth",
             "/api/admin","/swagger.json","/swagger-ui.html","/api-docs","/openapi.json",
             "/graphql","/v1/users","/v1/login","/health","/status","/metrics"]

class ApiEndpointDiscovery:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def discover(self, base_url):
        section(f"API Endpoint Discovery: {base_url}")
        found = []
        def check(path):
            url = urljoin(base_url, path)
            try:
                r = self.s.get(url, timeout=self.cfg["timeout"], verify=False, allow_redirects=False)
                if r.status_code in (200,201,401,403,405):
                    ctype = r.headers.get("Content-Type","")
                    if "json" in ctype or "xml" in ctype or r.status_code in (200,201):
                        found.append({"path": path, "status": r.status_code, "content_type": ctype})
                        good(f"  {url} [{r.status_code}] {ctype}")
            except Exception: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(check, API_PATHS))
        return found

# ============================================================
# 13. WEB CRAWLER
# ============================================================
class WebCrawler:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg); self.visited=set()

    def crawl(self, url, max_pages=30):
        section(f"Web Crawling: {url}")
        urls = []
        queue = [url]
        while queue and len(self.visited) < max_pages:
            u = queue.pop(0)
            if u in self.visited: continue
            self.visited.add(u)
            try:
                r = self.s.get(u, timeout=self.cfg["timeout"], verify=False)
                urls.append(u)
                if "text/html" not in r.headers.get("Content-Type",""): continue
                for link in re.findall(r'href=["\']([^"\']+)["\']', r.text):
                    abs_url = urljoin(u, link)
                    if abs_url.startswith(url) and abs_url not in self.visited:
                        queue.append(abs_url)
            except Exception: pass
        for u in urls: good(f"  {u}")
        return urls

# ============================================================
# 14. WAYBACK ARCHIVE ENUMERATION
# ============================================================
class WaybackEnumerator:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def enumerate(self, domain):
        section(f"Wayback Archive: {domain}")
        urls = []
        try:
            r = self.s.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=200&collapse=urlkey",
                           timeout=30)
            if r.status_code == 200:
                data = r.json()
                for entry in data[1:]:  # skip header
                    urls.append(entry[2])  # original URL
            good(f"Found {len(urls)} archived URLs")
        except Exception as e:
            warn(f"Wayback failed: {e}")
        return urls[:200]

# ============================================================
# 15. WEBSITE SCREENSHOTS
# ============================================================
class WebsiteScreenshot:
    def __init__(self, cfg): self.cfg = cfg

    def capture(self, url):
        section(f"Screenshot: {url}")
        if not SELENIUM_AVAILABLE:
            warn("Selenium not installed - skipping screenshot")
            return ""
        try:
            opts = webdriver.ChromeOptions()
            opts.add_argument("--headless")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=opts)
            driver.set_page_load_timeout(20)
            driver.get(url)
            time.sleep(2)
            os.makedirs("screenshots", exist_ok=True)
            fname = hashlib.md5(url.encode()).hexdigest() + ".png"
            path = os.path.join("screenshots", fname)
            driver.save_screenshot(path)
            driver.quit()
            good(f"Screenshot saved: {path}")
            return path
        except Exception as e:
            bad(f"Screenshot failed: {e}")
            return ""

# ============================================================
# 16. WAF DETECTION
# ============================================================
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cf_bm"],
    "Akamai": ["akamai", "akamaighost"],
    "AWS WAF": ["awselb", "x-amzn-waf"],
    "F5 BIG-IP": ["bigipserver", "tsip"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Imperva": ["incapsula", "visid_incap"],
    "ModSecurity": ["mod_security", "modsecurity"],
}

class WafDetector:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def detect(self, url):
        section(f"WAF Detection: {url}")
        detected = {}
        try:
            r = self.s.get(url, timeout=self.cfg["timeout"], verify=False)
            headers = " ".join(f"{k}:{v}" for k,v in r.headers.items()).lower()
            cookies = " ".join(f"{c.name}={c.value}" for c in r.cookies).lower()
            combined = headers + " " + cookies + " " + r.text[:5000].lower()
            for waf, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig in combined:
                        detected[waf] = sig
                        good(f"WAF detected: {waf} (signature: {sig})")
                        break
            if not detected:
                info("No WAF detected")
            # try sending malicious payload
            try:
                r2 = self.s.get(url, params={"q":"<script>alert(1)</script>' OR 1=1--"},
                                timeout=self.cfg["timeout"], verify=False)
                if r2.status_code == 403:
                    detected["generic_block"] = "403 on malicious input"
            except Exception: pass
        except Exception as e:
            bad(f"WAF detection failed: {e}")
        return detected

# ============================================================
# 17. TECHNOLOGY FINGERPRINTING
# ============================================================
TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "Drupal": [r"Drupal\.settings", r"drupal\.js"],
    "Joomla": [r"/components/com_", r"joomla"],
    "jQuery": [r"jquery", r"jQuery v"],
    "React": [r"react", r"_next/data", r"__NEXT_DATA__"],
    "Angular": [r"ng-app", r"angular"],
    "Vue.js": [r"vue\.js", r"data-v-"],
    "Bootstrap": [r"bootstrap"],
    "Nginx": [r"nginx"],
    "Apache": [r"apache"],
    "IIS": [r"microsoft-iis", r"asp\.net"],
    "PHP": [r"\.php", r"X-Powered-By: PHP"],
    "ASP.NET": [r"asp\.net", r"__VIEWSTATE"],
    "Tomcat": [r"tomcat", r"jsp"],
    "Express": [r"x-powered-by: express"],
    "Django": [r"csrfmiddlewaretoken", r"django"],
    "Flask": [r"flask"],
    "Cloudflare": [r"cf-ray"],
}

class TechFingerprinter:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def fingerprint(self, url):
        section(f"Tech Fingerprinting: {url}")
        techs = []
        try:
            r = self.s.get(url, timeout=self.cfg["timeout"], verify=False)
            content = (r.text[:10000] + " " +
                       " ".join(f"{k}:{v}" for k,v in r.headers.items())).lower()
            for tech, patterns in TECH_SIGNATURES.items():
                for p in patterns:
                    if re.search(p, content, re.I):
                        techs.append(tech)
                        good(f"  Detected: {tech}")
                        break
        except Exception as e:
            bad(f"Tech fingerprinting failed: {e}")
        return techs

# ============================================================
# 18. SECRET & GIT EXPOSURE SCANNING
# ============================================================
SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret", r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
    ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9]{36}"),
    ("Stripe Key", r"sk_live_[0-9A-Za-z]{24,}"),
    ("Generic API Key", r"api[_-]?key\s*=\s*['\"][A-Za-z0-9]{20,}['\"]"),
    ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("JWT", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("Database URL", r"(postgres|mysql|mongodb)://[^\s'\"]+:[^\s'\"]+@"),
]

class SecretScanner:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def scan(self, url):
        section(f"Secret Scanning: {url}")
        secrets = []
        try:
            r = self.s.get(url, timeout=self.cfg["timeout"], verify=False)
            for name, pat in SECRET_PATTERNS:
                for m in re.finditer(pat, r.text, re.I):
                    secrets.append({"type": name, "match": m.group(0)[:80]+"..." if len(m.group(0))>80 else m.group(0)})
                    bad(f"  Found {name}")
            # check .git
            git_cfg = urljoin(url, ".git/config")
            gr = self.s.get(git_cfg, timeout=self.cfg["timeout"], verify=False)
            if gr.status_code == 200 and "[core]" in gr.text:
                secrets.append({"type":"Git Repository Exposed","url":git_cfg})
                bad(f"  Exposed .git/config at {git_cfg}")
        except Exception as e:
            bad(f"Secret scan failed: {e}")
        return secrets

# ============================================================
# 19. CLOUD BUCKET DISCOVERY
# ============================================================
class CloudBucketDiscovery:
    def __init__(self, cfg): self.cfg = cfg; self.s = make_session(cfg)

    def discover(self, domain):
        section(f"Cloud Bucket Discovery: {domain}")
        found = []
        base = domain.split(".")[0]
        # AWS S3
        for variant in [base, f"{base}-backup", f"{base}-prod", f"{base}-dev", domain]:
            url = f"https://{variant}.s3.amazonaws.com/"
            try:
                r = self.s.get(url, timeout=self.cfg["timeout"])
                if r.status_code in (200,403):
                    found.append({"provider":"AWS S3","bucket":variant,"url":url,"status":r.status_code})
                    good(f"  AWS S3 bucket: {variant} [{r.status_code}]")
            except Exception: pass
        # Google Cloud Storage
        for variant in [base, f"{base}-backup", domain]:
            url = f"https://storage.googleapis.com/{variant}/"
            try:
                r = self.s.get(url, timeout=self.cfg["timeout"])
                if r.status_code in (200,403):
                    found.append({"provider":"GCS","bucket":variant,"url":url,"status":r.status_code})
                    good(f"  GCS bucket: {variant} [{r.status_code}]")
            except Exception: pass
        # Azure Blob
        for variant in [base, domain]:
            url = f"https://{variant}.blob.core.windows.net/"
            try:
                r = self.s.get(url, timeout=self.cfg["timeout"])
                if r.status_code in (200,403):
                    found.append({"provider":"Azure Blob","bucket":variant,"url":url,"status":r.status_code})
                    good(f"  Azure blob: {variant} [{r.status_code}]")
            except Exception: pass
        return found

# ============================================================
# 20. EXPLOIT INTELLIGENCE PIPELINE
# ============================================================
# Generic, non-CVE-specific hints kept as a fallback for services where the
# CVE pipeline found no exact match (e.g. banner gave no usable version).
EXPLOIT_HINTS = {
    "ftp":     ["Anonymous login (USER anonymous / PASS anonymous@)",
                "vsftpd 2.3.4 backdoor (CVE-2011-2523) - Metasploit: exploit/unix/ftp/vsftpd_234_backdoor",
                "ProFTPD 1.3.3c backdoor command execution (CVE-2010-4221)"],
    "ssh":     ["OpenSSH < 7.7 user enumeration (CVE-2018-15473)",
                "LibSSH auth bypass (CVE-2018-10933)",
                "Weak credentials - try hydra -L users.txt -P pass.txt ssh://TARGET"],
    "telnet":  ["Default creds / weak credentials - brute force with hydra",
                "MiTM with ettercap to capture creds"],
    "smtp":    ["Open relay test: RCPT TO:<external@email.com>",
                "User enum via VRFY/EXPN commands",
                "Postfix RCE (CVE-2019-19781 in related Exim)"],
    "http":    ["Directory traversal, LFI/RFI",
                "Default credentials on admin panels (tomcat-manager, jenkins)",
                "Outdated web server RCE (Apache CVE-2021-41773 path traversal, CVE-2021-42013)",
                "HTTP methods: try OPTIONS, PUT for file upload"],
    "https":   ["Same as HTTP + check for Heartbleed (CVE-2014-0160), POODLE, ROBOT",
                "Crack SSL certs with testssl.sh / sslscan"],
    "smb":     ["EternalBlue MS17-010 - Metasploit: exploit/windows/smb/ms17_010_eternalblue",
                "SMBNull session: enum4linux -a TARGET",
                "SambaCry CVE-2017-7494 - RCE via writable share"],
    "mysql":   ["Default root/no password: mysql -h TARGET -u root",
                "MySQL UDF privilege escalation",
                "Authentication bypass CVE-2012-2122"],
    "postgres":["Default postgres/postgres creds",
                "PostgreSQL RCE via COPY TO PROGRAM",
                "Metasploit: auxiliary/scanner/postgres/postgres_login"],
    "redis":   ["Unauthenticated access - write SSH key: redis-cli -h TARGET",
                "Write webshell to /var/www/html/",
                "Crond RCE via /var/spool/cron/"],
    "mongodb": ["Unauthenticated DB - mongo mongodb://TARGET:27017",
                "Metasploit: auxiliary/gather/mongodb_js_injection_collection_enum"],
    "memcached":["Unauthenticated - telnet TARGET 11211; stats; get cached secrets",
                 "DDoS amplification (UDP reflection)"],
    "elasticsearch":["RCE via script_fields CVE-2014-3120, CVE-2015-1427",
                     "Unauthenticated data access: curl http://TARGET:9200/_search"],
    "rdp":     ["BlueKeep CVE-2019-0708 - Metasploit: exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                "Brute force with ncrack -p 3389",
                "RDP MITM CVE-2012-0002"],
    "vnc":     ["Unauthenticated VNC - try vncviewer TARGET",
                "VNC password brute with hydra"],
    "dns":     ["DNS zone transfer: dig axfr @TARGET domain",
                "DNS cache poisoning, DNS rebinding attacks",
                "Subdomain takeover for dangling CNAMEs"],
}


# Curated CVE -> known public Metasploit module path(s), used as a fallback
# suggestion when there's no local Metasploit install to search against.
# This is the same public knowledge already reflected in EXPLOIT_HINTS above,
# just structured so the report can show it per-CVE instead of per-service.
KNOWN_MSF_MODULES = {
    "CVE-2011-2523": ["exploit/unix/ftp/vsftpd_234_backdoor"],
    "CVE-2010-4221": ["exploit/unix/ftp/proftpd_133c_backdoor"],
    "CVE-2018-15473": ["auxiliary/scanner/ssh/ssh_enumusers"],
    "CVE-2018-10933": ["auxiliary/scanner/ssh/libssh_auth_bypass"],
    "CVE-2017-0143": ["exploit/windows/smb/ms17_010_eternalblue", "exploit/windows/smb/ms17_010_psexec"],
    "CVE-2017-0144": ["exploit/windows/smb/ms17_010_eternalblue"],
    "CVE-2017-0145": ["exploit/windows/smb/ms17_010_eternalblue"],
    "CVE-2017-7494": ["exploit/linux/samba/is_known_pipename"],
    "CVE-2012-2122": ["auxiliary/scanner/mysql/mysql_authbypass_hashdump"],
    "CVE-2019-0708": ["exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
    "CVE-2020-0796": ["auxiliary/scanner/smb/smb_ms17_010", "exploit/windows/smb/cve_2020_0796_smbghost"],
    "CVE-2021-41773": ["exploit/multi/http/apache_normalize_path_rce"],
    "CVE-2021-42013": ["exploit/multi/http/apache_normalize_path_rce"],
    "CVE-2021-44228": ["exploit/multi/http/log4shell_header_injection"],
    "CVE-2019-19781": ["exploit/linux/http/citrix_dir_traversal_rce"],
    "CVE-2020-1472": ["auxiliary/admin/dcerpc/cve_2020_1472_zerologon"],
    "CVE-2014-3120": ["exploit/multi/elasticsearch/search_groovy_script"],
    "CVE-2015-1427": ["exploit/multi/elasticsearch/script_mvel_rce"],
    "CVE-2017-5638": ["exploit/multi/http/struts2_content_type_ognl"],
    "CVE-2018-11776": ["exploit/multi/http/struts2_namespace_ognl"],
    "CVE-2021-26855": ["auxiliary/gather/exchange_proxylogon"],
    "CVE-2014-0160": ["auxiliary/scanner/ssl/openssl_heartbleed"],
}


class ExploitIntelligence:
    """Enriches a matched CVE with real-world exploitability signals pulled
    from public feeds: EPSS (likelihood of exploitation), CISA KEV (confirmed
    active exploitation), ExploitDB (public PoC exists), and a local
    Metasploit install (a ready-made module exists). Every source degrades
    gracefully - if a tool/feed isn't available, that signal is just omitted."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.s = make_session(cfg)
        self._kev_cache = None
        self._has_searchsploit = None
        self._msf_modules_dir = None

    # ---- EPSS: probability of exploitation in the next 30 days ----
    def epss(self, cve_id):
        if not REQUESTS_AVAILABLE:
            return {}
        try:
            r = self.s.get(self.cfg["epss_api"], params={"cve": cve_id}, timeout=10)
            if r.status_code == 200:
                rows = r.json().get("data", [])
                if rows:
                    return {"epss_score": float(rows[0].get("epss", 0)),
                            "epss_percentile": float(rows[0].get("percentile", 0))}
        except Exception:
            pass
        return {}

    # ---- CISA Known Exploited Vulnerabilities catalog ----
    def _load_kev(self):
        if self._kev_cache is not None:
            return self._kev_cache
        self._kev_cache = {}
        if REQUESTS_AVAILABLE:
            try:
                r = self.s.get(self.cfg["cisa_kev_url"], timeout=20)
                if r.status_code == 200:
                    for entry in r.json().get("vulnerabilities", []):
                        self._kev_cache[entry.get("cveID", "")] = {
                            "date_added": entry.get("dateAdded", ""),
                            "ransomware_use": entry.get("knownRansomwareCampaignUse", ""),
                            "due_date": entry.get("dueDate", ""),
                        }
            except Exception:
                pass
        return self._kev_cache

    def kev(self, cve_id):
        return self._load_kev().get(cve_id)

    # ---- ExploitDB, via the local searchsploit CLI if it's installed ----
    def exploitdb(self, cve_id):
        if self._has_searchsploit is None:
            self._has_searchsploit = shutil.which("searchsploit") is not None
        if not self._has_searchsploit:
            return []
        try:
            out = subprocess.run(["searchsploit", "--json", cve_id],
                                 capture_output=True, text=True, timeout=15)
            if out.returncode == 0 and out.stdout.strip():
                data = json.loads(out.stdout)
                return [{"title": e.get("Title", ""), "edb_id": e.get("EDB-ID", "")}
                        for e in data.get("RESULTS_EXPLOIT", [])[:5]]
        except Exception:
            pass
        return []

    # ---- Metasploit: confirmed local module, or a suggested known module ----
    def metasploit(self, cve_id):
        modules = []
        if self._msf_modules_dir is None:
            self._msf_modules_dir = ""
            for candidate in ("/usr/share/metasploit-framework/modules",
                               os.path.expanduser("~/.msf4/modules")):
                if os.path.isdir(candidate):
                    self._msf_modules_dir = candidate
                    break
        if self._msf_modules_dir:
            try:
                out = subprocess.run(["grep", "-rl", cve_id, self._msf_modules_dir],
                                     capture_output=True, text=True, timeout=15)
                for path in out.stdout.strip().splitlines()[:5]:
                    rel = path.replace(self._msf_modules_dir + "/", "").replace(".rb", "")
                    modules.append({"module": rel, "confirmed_local": True})
            except Exception:
                pass
        if not modules and cve_id in KNOWN_MSF_MODULES:
            for m in KNOWN_MSF_MODULES[cve_id]:
                modules.append({"module": m, "confirmed_local": False})
        return modules


def _risk_score(cve_entry, epss, kev, edb, msf):
    """Composite 0-100ish risk score: base severity + real-world exploitation signals."""
    score = 0.0
    try:
        score += float(cve_entry.get("cvss") or 0) * 4      # up to ~40
    except (TypeError, ValueError):
        pass
    score += (epss.get("epss_score") or 0) * 40              # up to 40
    if kev: score += 15                                       # confirmed active exploitation
    if edb: score += 10                                       # public PoC available
    if msf:
        score += 15 if any(m.get("confirmed_local") for m in msf) else 8  # ready module vs known suggestion
    return round(score, 1)


class ExploitSuggester:
    @staticmethod
    def suggest(port_scan, cves, cfg):
        section("Exploit Intelligence Pipeline (EPSS / CISA KEV / ExploitDB / Metasploit)")
        intel = ExploitIntelligence(cfg)
        ranked = []

        for entry in cves:
            service, port = entry.get("service", ""), entry.get("port")
            for c in entry.get("cves", []):
                cve_id = c.get("id", "")
                if not cve_id:
                    continue
                info(f"Enriching {cve_id} ({service} :{port}) ...")

                epss = intel.epss(cve_id)
                kev = intel.kev(cve_id)
                edb = intel.exploitdb(cve_id)
                msf = intel.metasploit(cve_id)

                if "epss_score" in epss:
                    good(f"  EPSS: {epss['epss_score']:.2%} exploitation likelihood "
                         f"(percentile {epss['epss_percentile']:.0%})", indent=1)
                if kev:
                    bad(f"  CISA KEV: confirmed actively exploited in the wild "
                        f"(added {kev.get('date_added','?')})", indent=1)
                if edb:
                    warn(f"  ExploitDB: {len(edb)} public PoC(s) found", indent=1)
                if msf:
                    n_confirmed = sum(1 for m in msf if m.get("confirmed_local"))
                    if n_confirmed:
                        bad(f"  Metasploit: {n_confirmed} module(s) confirmed on this system "
                            f"({', '.join(m['module'] for m in msf if m.get('confirmed_local'))})", indent=1)
                    else:
                        warn(f"  Metasploit: {len(msf)} known module(s) for this CVE (not installed locally - "
                             f"{', '.join(m['module'] for m in msf)})", indent=1)
                if not (kev or edb or msf or epss):
                    info("  No public exploit signals found for this CVE", indent=1)

                risk = _risk_score(c, epss, kev, edb, msf)
                ranked.append({
                    "cve": cve_id, "service": service, "port": port,
                    "cvss": c.get("cvss", ""), "severity": c.get("severity", ""),
                    "description": c.get("desc", ""),
                    "epss_score": epss.get("epss_score"), "epss_percentile": epss.get("epss_percentile"),
                    "cisa_kev": bool(kev), "kev_detail": kev,
                    "exploitdb": edb, "metasploit_modules": msf,
                    "references": c.get("refs", []),
                    "risk_score": risk,
                })
            time.sleep(0.3)

        ranked.sort(key=lambda x: x["risk_score"], reverse=True)

        # Generic hints only for ports the CVE pipeline found nothing exact for
        ports_with_cves = {r["port"] for r in ranked if r.get("cve")}
        for p in port_scan.get("ports", []):
            svc = p["service"]
            if svc in EXPLOIT_HINTS and p["port"] not in ports_with_cves:
                for h in EXPLOIT_HINTS[svc]:
                    ranked.append({"port": p["port"], "service": svc, "generic_hint": h, "risk_score": 0})

        top = [r for r in ranked if r.get("cve")][:10]
        if top:
            section(f"Ranked Findings ({len(top)} of {len([r for r in ranked if r.get('cve')])} CVEs shown)")
            if RICH_AVAILABLE:
                t = Table(box=rich_box.ROUNDED, header_style="bold white on red",
                          border_style="grey50", row_styles=["", "on grey11"])
                for col in ("CVE", "Service", "CVSS", "EPSS", "KEV", "ExploitDB", "Metasploit Module(s)", "Risk"):
                    t.add_column(col)
                for r in top:
                    msf = r.get("metasploit_modules") or []
                    if msf:
                        msf_cell = "\n".join(
                            f"{'[bold red]●[/]' if m.get('confirmed_local') else '[yellow]○[/]'} {m['module']}"
                            for m in msf)
                    else:
                        msf_cell = "-"
                    t.add_row(
                        r["cve"], str(r.get("service", "")), str(r.get("cvss", "") or "-"),
                        f"{(r.get('epss_score') or 0):.0%}",
                        "[bold red]YES[/]" if r.get("cisa_kev") else "-",
                        str(len(r.get("exploitdb") or [])) or "-",
                        msf_cell,
                        f"[bold]{r['risk_score']}[/]",
                    )
                console.print(t)
                console.print("[dim]● = confirmed present on this system   ○ = known module, not installed here[/]")
            else:
                for r in top:
                    msf = r.get("metasploit_modules") or []
                    msf_str = ", ".join(f"{m['module']}{'*' if m.get('confirmed_local') else ''}" for m in msf) or "-"
                    print(f"  {r['cve']:18s} risk={r['risk_score']:<6} kev={'Y' if r.get('cisa_kev') else 'N'} "
                          f"edb={len(r.get('exploitdb') or [])} msf=[{msf_str}]")

        return ranked

# ============================================================
# PLUGINS SYSTEM
# ============================================================
PLUGINS = {
    "portscan":       ("Port scanner + service fingerprinting", PortScanner),
    "cve":            ("CPE-based exact CVE matching via NVD", CVEMatcher),
    "webaudit":       ("Web application security audit", WebAuditor),
    "dns":            ("DNS enumeration", DnsEnumerator),
    "ssl":            ("SSL/TLS certificate analysis", SslAnalyzer),
    "whois":          ("WHOIS lookup", WhoisLookup),
    "subdomains":     ("Subdomain enumeration", SubdomainEnumerator),
    "directories":    ("Directory & file discovery", DirectoryBruteforcer),
    "vhosts":         ("Virtual host discovery", VhostDiscovery),
    "paramfuzz":      ("Parameter fuzzing", ParameterFuzzer),
    "apiendpoints":   ("API endpoint discovery", ApiEndpointDiscovery),
    "crawler":        ("Web crawler", WebCrawler),
    "wayback":        ("Wayback archive enumeration", WaybackEnumerator),
    "screenshot":     ("Website screenshots (Selenium)", WebsiteScreenshot),
    "waf":            ("WAF detection", WafDetector),
    "tech":           ("Technology fingerprinting", TechFingerprinter),
    "secrets":        ("Secret & Git exposure scanning", SecretScanner),
    "cloudbuckets":   ("Cloud bucket discovery", CloudBucketDiscovery),
    "exploits":       ("Exploit intel: EPSS/CISA KEV/ExploitDB/Metasploit", ExploitSuggester),
}

def list_plugins():
    section("Loaded Plugins")
    if RICH_AVAILABLE:
        t = Table(box=rich_box.ROUNDED, header_style="bold white on dark_cyan",
                  border_style="grey50", row_styles=["", "on grey11"], pad_edge=False)
        t.add_column("#", style="dim", width=3, justify="right")
        t.add_column("Plugin", style="bold cyan")
        t.add_column("Description", style="white")
        for i, (name, (desc, _)) in enumerate(PLUGINS.items(), 1):
            t.add_row(str(i), name, desc)
        console.print(t)
        console.print(f"[dim]{len(PLUGINS)} plugins loaded — run with -m all to use every module[/]")
    else:
        for name,(desc,_) in PLUGINS.items():
            print(f"  {name:15s} - {desc}")

def show_config(cfg):
    section("Current Configuration")
    if RICH_AVAILABLE:
        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("Key"); t.add_column("Value")
        for k,v in cfg.items(): t.add_row(k, str(v))
        console.print(t)
    else:
        for k,v in cfg.items(): print(f"  {k} = {v}")

# ============================================================
# HTML REPORT RENDERER
# ============================================================
_SECTION_ICONS = {
    "PORT_SCAN": "&#128225;", "CVES": "&#9888;", "WEB_AUDIT": "&#127760;",
    "DNS": "&#128225;", "SSL": "&#128274;", "WHOIS": "&#128203;",
    "SUBDOMAINS": "&#127760;", "DIRECTORIES": "&#128193;", "VHOSTS": "&#127760;",
    "PARAM_FUZZ": "&#128295;", "API_ENDPOINTS": "&#128268;", "CRAWL": "&#128279;",
    "WAYBACK": "&#128340;", "SCREENSHOTS": "&#128247;", "WAF": "&#128737;",
    "TECH": "&#129513;", "SECRETS": "&#128273;", "GIT_EXPOSURE": "&#128193;",
    "CLOUD_BUCKETS": "&#9729;", "EXPLOITS": "&#128163;",
}

# Human-friendly labels for field names that would otherwise show as raw snake_case keys.
_KEY_LABELS = {
    "id": "CVE ID", "cve": "CVE ID", "cvss": "CVSS Score", "cpe": "CPE",
    "epss_score": "EPSS Score", "epss_percentile": "EPSS Percentile",
    "cisa_kev": "CISA KEV Listed", "kev_detail": "KEV Details",
    "exploitdb": "ExploitDB Entries", "metasploit_modules": "Metasploit Modules",
    "generic_hint": "Suggested Technique", "risk_score": "Risk Score",
    "desc": "Description", "description": "Description",
    "refs": "References", "references": "References",
    "ip": "IP Address", "dns": "DNS Records", "ssl": "SSL/TLS Analysis",
    "waf": "WAF Detection", "whois": "WHOIS Lookup",
    "api_endpoints": "API Endpoints", "param_fuzz": "Parameter Fuzzing Results",
    "web_audit": "Web Application Audit", "git_exposure": "Git Exposure",
    "cloud_buckets": "Cloud Storage Buckets", "vhosts": "Virtual Hosts",
    "not_before": "Valid From", "not_after": "Valid Until",
    "sha256_fingerprint": "SHA-256 Fingerprint", "public_key_bits": "Public Key Size (bits)",
    "public_key_type": "Public Key Type", "signature_algorithm": "Signature Algorithm",
    "subject_alternative_names": "Subject Alternative Names (SANs)", "is_self_signed": "Self-Signed",
    "days_until_expiry": "Days Until Expiry", "overall_grade": "Overall Grade",
    "issue_count": "Issue Count", "grade_notes": "Notes",
    "negotiated_protocol": "Negotiated Protocol", "negotiated_cipher": "Negotiated Cipher Suite",
    "server_temp_key": "Key Exchange (Server Temp Key)", "x_powered_by": "X-Powered-By Header",
    "domain_name": "Domain Name", "creation_date": "Creation Date", "expiration_date": "Expiration Date",
    "name_servers": "Name Servers", "edb_id": "ExploitDB ID", "confirmed_local": "Installed Locally",
    "module": "Metasploit Module", "date_added": "Date Added to KEV",
    "ransomware_use": "Known Ransomware Use", "due_date": "Remediation Due Date",
    "fingerprint": "HTTP Fingerprint", "findings": "Findings", "web_ports": "Web Ports",
    "technologies": "Detected Technologies",
}

_ACRONYMS = {"id", "ip", "dns", "ssl", "tls", "url", "cve", "cvss", "epss", "kev",
             "waf", "cpe", "msf", "edb", "api", "http", "https", "ftp", "ssh", "smb",
             "cidr", "cnames", "cname", "ns", "mx", "txt", "soa", "srv", "caa", "sha256"}

def _label(key):
    if key in _KEY_LABELS:
        return _KEY_LABELS[key]
    words = str(key).replace("_", " ").split()
    return " ".join(w.upper() if w.lower() in _ACRONYMS else w.capitalize() for w in words)

def _esc(x):
    return html.escape(str(x))

def _sev_badge(sev):
    sev = (sev or "info").lower()
    colors = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
              "low": "#65a30d", "info": "#0284c7"}
    c = colors.get(sev, "#64748b")
    return f'<span class="badge" style="background:{c}22;color:{c};border:1px solid {c}55">{_esc(sev.upper())}</span>'

def _count_issues(data):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    def walk(obj):
        if isinstance(obj, dict):
            sev = obj.get("severity")
            if isinstance(sev, str) and sev.lower() in counts:
                counts[sev.lower()] += 1
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
    walk(data)
    return counts

def _render_scalar(key, value):
    """Render a single leaf value as readable, styled HTML - never raw JSON."""
    if value is None or value == "":
        return "<span class='muted'>&mdash;</span>"
    if isinstance(value, bool):
        return "<span class='yesno yes'>Yes</span>" if value else "<span class='yesno no'>No</span>"
    lk = (key or "").lower()
    if lk == "epss_score":
        try: return f"{float(value):.2%}"
        except (TypeError, ValueError): pass
    if lk == "epss_percentile":
        try: return f"{float(value):.0%} percentile"
        except (TypeError, ValueError): pass
    if lk in ("severity", "baseseverity") and isinstance(value, str):
        return _sev_badge(value)
    if lk == "risk_score":
        try:
            v = float(value)
            cls = "risk-high" if v >= 70 else "risk-med" if v >= 40 else "risk-low"
            return f"<span class='{cls}'>{v:g}</span>"
        except (TypeError, ValueError): pass
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        s = _esc(value)
        return f"<a href='{s}' target='_blank' rel='noopener'>{s}</a>"
    if isinstance(value, str) and "\n" in value:
        return f"<pre>{_esc(value)}</pre>"
    return _esc(value)

def _render_value(key, value, depth=0):
    """Recursively render any JSON-like value as readable HTML. Lists of dicts
    become tables, dicts become key/value tables, scalar lists become chips or
    link lists, and every nested structure is rendered the same way - nothing
    ever falls through to a raw JSON dump."""
    if value is None or value == "" or value == [] or value == {}:
        return "<span class='muted'>&mdash;</span>"

    if isinstance(value, (bool, int, float, str)):
        return _render_scalar(key, value)

    if isinstance(value, list):
        if all(isinstance(i, dict) for i in value):
            return _render_table(value, depth)
        if all(isinstance(i, (str, int, float, bool)) for i in value):
            lk = (key or "").lower()
            if lk in ("refs", "references", "name_servers") and any(
                    isinstance(i, str) and i.startswith("http") for i in value):
                return "<ul class='plain-list'>" + "".join(
                    f"<li>{_render_scalar(None, i)}</li>" for i in value) + "</ul>"
            return "<div class='chips'>" + "".join(f"<span class='chip'>{_esc(i)}</span>" for i in value) + "</div>"
        # mixed list - render each element recursively
        return "<ul class='plain-list'>" + "".join(
            f"<li>{_render_value(key, i, depth + 1)}</li>" for i in value) + "</ul>"

    if isinstance(value, dict):
        return _render_dict(value, depth)

    return _esc(value)

def _render_table(items, depth):
    keys = []
    for item in items:
        for k in item.keys():
            if k not in keys:
                keys.append(k)
    head = "".join(f"<th>{_esc(_label(k))}</th>" for k in keys)
    rows = []
    for item in items:
        cells = "".join(f"<td>{_render_value(k, item.get(k, ''), depth + 1)}</td>" for k in keys)
        rows.append(f"<tr>{cells}</tr>")
    return (f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')

def _render_dict(d, depth):
    # A dict whose values are all booleans (e.g. the TLS protocol support matrix)
    # reads better as a row of chips than a two-column table.
    if d and all(isinstance(v, bool) for v in d.values()):
        chip_parts = []
        for k, v in d.items():
            cls = "yes" if v else "no"
            status = "Supported" if v else "Not supported"
            chip_parts.append(f"<span class='chip {cls}'>{_esc(k)}: {status}</span>")
        return f"<div class='chips'>{''.join(chip_parts)}</div>"

    rows = []
    for k, val in d.items():
        if k == "issues" and isinstance(val, list) and val:
            items_html = "".join(
                f"<div class='issue-row'>{_sev_badge(i.get('severity'))} <span>{_esc(i.get('issue',''))}</span></div>"
                for i in val)
            rows.append(f"<tr><td class='k'>{_esc(_label(k))}</td><td>{items_html}</td></tr>")
        else:
            rows.append(f"<tr><td class='k'>{_esc(_label(k))}</td><td>{_render_value(k, val, depth + 1)}</td></tr>")
    return f'<table class="kv">{"".join(rows)}</table>'

def _render_html_report(data):
    target = data.get("target", "unknown")
    timestamp = data.get("timestamp", "")
    counts = _count_issues(data)
    total_issues = sum(counts.values())
    open_ports = len(data.get("port_scan", {}).get("ports", []) or [])
    ssl_grade = (data.get("ssl", {}) or {}).get("security_assessment", {}).get("overall_grade", "N/A")

    sections_html = []
    for k, v in data.items():
        if k in ("target", "timestamp") or not v:
            continue
        icon = _SECTION_ICONS.get(k.upper(), "&#128196;")
        title = _label(k)
        sections_html.append(f"""
        <section class="card">
          <div class="card-header">
            <span class="icon">{icon}</span>
            <h2>{title}</h2>
          </div>
          <div class="card-body">
            {_render_value(k, v)}
          </div>
        </section>""")

    stat_cards = f"""
      <div class="stat"><div class="stat-num">{open_ports}</div><div class="stat-label">Open Ports</div></div>
      <div class="stat"><div class="stat-num">{_esc(ssl_grade)}</div><div class="stat-label">SSL/TLS Grade</div></div>
      <div class="stat crit"><div class="stat-num">{counts['critical']}</div><div class="stat-label">Critical</div></div>
      <div class="stat high"><div class="stat-num">{counts['high']}</div><div class="stat-label">High</div></div>
      <div class="stat med"><div class="stat-num">{counts['medium']}</div><div class="stat-label">Medium</div></div>
      <div class="stat"><div class="stat-num">{total_issues}</div><div class="stat-label">Total Findings</div></div>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconX Report - {_esc(target)}</title>
<style>
  :root {{
    --bg: #0b0f19; --panel: #121826; --panel-2: #171f30; --border: #232c3f;
    --text: #e5e9f0; --muted: #8b93a7; --accent: #22d3ee; --accent2: #818cf8;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0; background: radial-gradient(circle at top, #101828 0%, #0b0f19 60%);
    color: var(--text); font-family: 'Segoe UI', Roboto, -apple-system, sans-serif;
  }}
  .topbar {{
    padding: 28px 40px; background: linear-gradient(120deg, #0f172a, #111827 60%, #0b1220);
    border-bottom: 1px solid var(--border);
  }}
  .brand {{ display:flex; align-items:center; gap:14px; }}
  .brand .logo {{
    width: 42px; height: 42px; border-radius: 10px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    display:flex; align-items:center; justify-content:center; font-weight:800; color:#0b0f19;
  }}
  .brand h1 {{ margin:0; font-size: 22px; letter-spacing: .5px; }}
  .brand p {{ margin: 2px 0 0; color: var(--muted); font-size: 13px; }}
  .meta {{ margin-top:16px; color: var(--muted); font-size: 13px; display:flex; gap:24px; flex-wrap:wrap; }}
  .meta b {{ color: var(--text); }}

  .stats {{ display:flex; gap:16px; padding: 24px 40px; flex-wrap:wrap; }}
  .stat {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
    padding: 18px 22px; min-width: 130px; text-align:center;
    box-shadow: 0 4px 18px rgba(0,0,0,.25);
  }}
  .stat-num {{ font-size: 28px; font-weight: 800; color: var(--accent); }}
  .stat.crit .stat-num {{ color:#f87171; }}
  .stat.high .stat-num {{ color:#fb923c; }}
  .stat.med .stat-num {{ color:#facc15; }}
  .stat-label {{ margin-top:6px; font-size:12px; color: var(--muted); text-transform:uppercase; letter-spacing:.5px; }}

  .container {{ padding: 8px 40px 60px; display:grid; gap:20px; }}
  .card {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 16px;
    overflow:hidden; box-shadow: 0 6px 24px rgba(0,0,0,.22);
  }}
  .card-header {{
    display:flex; align-items:center; gap:10px; padding: 16px 22px;
    background: linear-gradient(90deg, var(--panel-2), var(--panel));
    border-bottom: 1px solid var(--border);
  }}
  .card-header h2 {{ margin:0; font-size:16px; letter-spacing:.4px; }}
  .icon {{ font-size:18px; }}
  .card-body {{ padding: 18px 22px; overflow-x:auto; }}

  table {{ border-collapse: collapse; width:100%; font-size: 13px; }}
  table.kv td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align:top; }}
  table.kv td.k {{ color: var(--muted); width: 220px; font-weight:600; white-space:nowrap; }}
  .table-wrap table {{ border: 1px solid var(--border); border-radius:10px; overflow:hidden; }}
  .table-wrap th {{ text-align:left; background: var(--panel-2); color: var(--muted); padding:10px; font-size:12px; text-transform:uppercase; letter-spacing:.4px; white-space:nowrap; }}
  .table-wrap td {{ padding:10px; border-top:1px solid var(--border); vertical-align:top; }}
  .table-wrap tr:hover td {{ background: rgba(34,211,238,0.04); }}
  .table-wrap .table-wrap {{ margin: 2px 0; }}

  pre {{ background:#0b1220; padding:10px 12px; border-radius:8px; overflow-x:auto; font-size:12px; color:#c7d2fe; margin:0; max-height:260px; }}
  code {{ font-size:12px; color:#a5b4fc; }}
  ul.plain-list {{ margin:4px 0; padding-left:20px; }}
  ul.plain-list li {{ margin: 3px 0; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  .badge {{ display:inline-block; padding:3px 9px; border-radius:999px; font-size:11px; font-weight:700; letter-spacing:.4px; }}
  .issue-row {{ display:flex; align-items:center; gap:10px; padding:5px 0; font-size:13px; }}

  .muted {{ color: var(--muted); }}
  .yesno {{ font-weight:700; padding: 2px 8px; border-radius:6px; font-size:12px; }}
  .yesno.yes {{ background:#dc262622; color:#f87171; }}
  .yesno.no {{ background:#65a30d22; color:#86efac; }}

  .chips {{ display:flex; flex-wrap:wrap; gap:6px; }}
  .chip {{ background:#1e293b; border:1px solid var(--border); padding:3px 10px; border-radius:999px; font-size:12px; color:var(--text); }}
  .chip.yes {{ background:#dc262622; border-color:#dc262655; color:#f87171; }}
  .chip.no {{ background:#16532422; border-color:#16532455; color:#86efac; }}

  .risk-high {{ color:#f87171; font-weight:800; }}
  .risk-med {{ color:#facc15; font-weight:800; }}
  .risk-low {{ color:#86efac; font-weight:800; }}

  footer {{ text-align:center; color: var(--muted); font-size:12px; padding: 20px; border-top:1px solid var(--border); }}
</style>
</head>
<body>
  <div class="topbar">
    <div class="brand">
      <div class="logo">R</div>
      <div>
        <h1>ReconX Security Report</h1>
        <p>All-in-One Security Scanner &middot; by root_0xM</p>
      </div>
    </div>
    <div class="meta">
      <div>Target: <b>{_esc(target)}</b></div>
      <div>Generated: <b>{_esc(timestamp)}</b></div>
    </div>
  </div>

  <div class="stats">
    {stat_cards}
  </div>

  <div class="container">
    {''.join(sections_html) if sections_html else '<div class="card"><div class="card-body">No findings recorded for this scan.</div></div>'}
  </div>

  <footer>Generated by ReconX &middot; Educational / authorized-use security scanner &middot; root_0xM</footer>
</body>
</html>"""

# ============================================================
# REPORT GENERATOR
# ============================================================
def generate_report(json_path, fmt="txt"):
    section(f"Report Generation ({fmt}) from {json_path}")
    try:
        with open(json_path) as f:
            data = json.load(f)
    except Exception as e:
        bad(f"Cannot read JSON: {e}")
        return

    out_path = os.path.splitext(json_path)[0] + f".{fmt}"
    if fmt == "txt":
        lines = []
        lines.append("=" * 70)
        lines.append(f"  ReconX Scan Report - {data.get('target','?')}")
        lines.append(f"  Generated: {data.get('timestamp','?')}")
        lines.append("=" * 70)
        def add(name, obj):
            lines.append(f"\n--- {name} ---")
            if isinstance(obj,(dict,list)):
                lines.append(json.dumps(obj, indent=2, default=str))
            else:
                lines.append(str(obj))
        for k,v in data.items():
            if k in ("target","timestamp"): continue
            if v: add(k.upper(), v)
        with open(out_path,"w") as f:
            f.write("\n".join(lines))
    elif fmt == "html":
        html = _render_html_report(data)
        with open(out_path,"w") as f:
            f.write(html)
    elif fmt == "md":
        md = f"# ReconX Report - {data.get('target')}\n\n*Generated: {data.get('timestamp')}*\n\n"
        for k,v in data.items():
            if k in ("target","timestamp") or not v: continue
            md += f"## {k}\n```json\n{json.dumps(v, indent=2, default=str)}\n```\n\n"
        with open(out_path,"w") as f: f.write(md)
    good(f"Report saved: {out_path}")

# ============================================================
# MAIN SCANNER ORCHESTRATOR
# ============================================================
def run_scan(target, modules, cfg, ports=None):
    if not REQUESTS_AVAILABLE:
        bad("requests library not installed. Run: pip install requests")
    result = ScanResult(target=target, timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat())
    # Normalize target
    parsed = urlsplit(target if "://" in target else f"http://{target}")
    host = parsed.hostname or target
    domain = host

    # 1. Port scan
    if "portscan" in modules or "all" in modules:
        ps = PortScanner(cfg)
        result.port_scan = ps.scan(host, ports=ports)
        # 2. Service fingerprinting
        result.port_scan["fingerprint"] = ServiceFingerprinter(cfg).fingerprint(host, result.port_scan)
        # 3. CVE matching
        if "cve" in modules or "all" in modules:
            result.cves = CVEMatcher(cfg).match_services(result.port_scan)
        # 4. Exploit suggestions
        if "exploits" in modules or "all" in modules:
            result.exploits = ExploitSuggester.suggest(result.port_scan, result.cves, cfg)

    # 5. Web audit
    if "webaudit" in modules or "all" in modules:
        result.web_audit = WebAuditor(cfg).audit(host, result.port_scan)

    # 6. DNS
    if "dns" in modules or "all" in modules:
        result.dns = DnsEnumerator(cfg).enumerate(domain)

    # 7. SSL
    if "ssl" in modules or "all" in modules:
        if any(p["port"] in (443,8443) for p in result.port_scan.get("ports",[])):
            result.ssl = SslAnalyzer(cfg).analyze(host, 443)
        else:
            result.ssl = SslAnalyzer(cfg).analyze(host, 443)

    # 8. WHOIS
    if "whois" in modules or "all" in modules:
        result.whois = WhoisLookup(cfg).lookup(domain)

    # 9. Subdomains
    if "subdomains" in modules:
        result.subdomains = SubdomainEnumerator(cfg).enumerate(domain, cfg["subdomains_top"])

    # Determine web base URL
    base_url = None
    for p in result.port_scan.get("ports", []):
        if p["port"] == 443:
            base_url = f"https://{host}"; break
        if p["port"] in (80,8080,8000,8888):
            base_url = f"http://{host}:{p['port']}"; break
    if not base_url:
        base_url = f"http://{host}"

    # 10. Directories
    if "directories" in modules:
        result.directories = DirectoryBruteforcer(cfg).discover(base_url)
    # 11. VHosts
    if "vhosts" in modules:
        ip = result.port_scan.get("ip", host)
        result.vhosts = VhostDiscovery(cfg).discover(ip, domain)
    # 12. Param fuzz
    if "paramfuzz" in modules:
        result.param_fuzz = ParameterFuzzer(cfg).fuzz(base_url)
    # 13. API endpoints
    if "apiendpoints" in modules:
        result.api_endpoints = ApiEndpointDiscovery(cfg).discover(base_url)
    # 14. Crawler
    if "crawler" in modules:
        result.crawl = WebCrawler(cfg).crawl(base_url)
    # 15. Wayback
    if "wayback" in modules:
        result.wayback = WaybackEnumerator(cfg).enumerate(domain)
    # 16. Screenshots
    if "screenshot" in modules:
        path = WebsiteScreenshot(cfg).capture(base_url)
        if path: result.screenshots.append(path)
    # 17. WAF
    if "waf" in modules:
        result.waf = WafDetector(cfg).detect(base_url)
    # 18. Tech fingerprint
    if "tech" in modules:
        result.tech = {"technologies": TechFingerprinter(cfg).fingerprint(base_url)}
    # 19. Secrets
    if "secrets" in modules:
        result.secrets = SecretScanner(cfg).scan(base_url)
    # 20. Cloud buckets
    if "cloudbuckets" in modules:
        result.cloud_buckets = CloudBucketDiscovery(cfg).discover(domain)

    return result

# ============================================================
# CLI
# ============================================================
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="ReconX - All-in-One Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reconx.py -t example.com -m portscan,cve,webaudit
  python reconx.py -t example.com -m all
  python reconx.py -t example.com -m subdomains,directories,paramfuzz
  python reconx.py -t 192.168.1.10 -m portscan -p all --threads 300
  python reconx.py -t 192.168.1.10 -m portscan -p 1-1024
  python reconx.py -t 192.168.1.10 -m portscan -p 22,80,443,8080-8090
  python reconx.py --report reports/example.json --format html
  python reconx.py --plugins
  python reconx.py --config-show
""")
    parser.add_argument("-t","--target", help="Target host/domain")
    parser.add_argument("-m","--modules",
                        default="portscan,cve,webaudit,dns,ssl,whois,exploits",
                        help="Comma-separated modules (or 'all')")
    parser.add_argument("-p","--ports", default="",
                        help="Ports to scan: 'all' (1-65535), a list '22,80,443', "
                             "a range '1-1024', or mixed '22,80,1000-2000'. "
                             "Default: built-in COMMON_PORTS list (~40 well-known ports).")
    parser.add_argument("--threads", type=int, default=DEFAULT_CONFIG["threads"])
    parser.add_argument("--timeout", type=int, default=DEFAULT_CONFIG["timeout"])
    parser.add_argument("--cve-api-key", default="", help="Optional NVD API key")
    parser.add_argument("--report", help="Regenerate report from JSON file")
    parser.add_argument("--format", choices=["txt","html","md","json"], default="json")
    parser.add_argument("--plugins", action="store_true", help="List loaded plugins")
    parser.add_argument("--config-show", action="store_true", help="Show configuration")
    parser.add_argument("--output", default="reports", help="Output directory")
    args = parser.parse_args()

    cfg = DEFAULT_CONFIG.copy()
    cfg["threads"] = args.threads
    cfg["timeout"] = args.timeout
    cfg["cve_api_key"] = args.cve_api_key
    cfg["report_dir"] = args.output

    if args.plugins:
        list_plugins(); return
    if args.config_show:
        show_config(cfg); return
    if args.report:
        if args.format == "json":
            import shutil; shutil.copy(args.report, args.report); good("JSON unchanged")
        else:
            generate_report(args.report, args.format)
        return
    if not args.target:
        parser.print_help()
        return

    # Validate module names
    requested = [m.strip() for m in args.modules.split(",") if m.strip()]
    valid = set(PLUGINS.keys()) | {"all"}
    for m in requested:
        if m not in valid:
            bad(f"Unknown module: {m}")
            info(f"Valid: {', '.join(sorted(valid))}")
            return

    if "all" in requested:
        requested = list(PLUGINS.keys())

    ports = parse_ports(args.ports)

    info(f"Target: {args.target}")
    info(f"Modules: {', '.join(requested)}")
    info(f"Threads: {cfg['threads']} | Timeout: {cfg['timeout']}s")
    if ports is not None:
        info(f"Ports: {len(ports)} port(s) requested"
             + (" (full 1-65535 range - this can take a while)" if len(ports) > 20000 else ""))
        if len(ports) > 5000 and cfg["threads"] < 200:
            warn(f"Scanning {len(ports)} ports with only {cfg['threads']} threads will be slow. "
                 f"Consider --threads 300-500 for a full port scan.")
    else:
        info(f"Ports: default COMMON_PORTS list ({len(COMMON_PORTS)} ports)")

    start = time.time()
    try:
        result = run_scan(args.target, requested, cfg, ports=ports)
    except KeyboardInterrupt:
        bad("Interrupted by user"); return
    except Exception as e:
        bad(f"Scan failed: {e}"); raise

    # Save JSON
    os.makedirs(cfg["report_dir"], exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9_.-]","_", args.target)
    json_path = os.path.join(cfg["report_dir"], f"{safe_target}_{int(time.time())}.json")
    save_json(asdict(result), json_path)

    # Also generate human-readable report
    if args.format != "json":
        generate_report(json_path, args.format)

    elapsed = time.time() - start
    section(f"Scan Complete ({elapsed:.1f}s)")
    good(f"JSON report: {json_path}")
    good(f"Use --report {json_path} --format html  to re-export")

if __name__ == "__main__":
    main()

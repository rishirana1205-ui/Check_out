"""
Vulnerability Scanner Engine
============================
Core scanning module with port scanning, banner grabbing,
vulnerability detection, and configuration checking.

WARNING: Only use on systems you OWN or have EXPLICIT authorization to test.
"""

import socket
import ssl
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VULN_DB_PATH = os.path.join(os.path.dirname(__file__), "vuln_database.json")

PORT_PRESETS = {
    "quick": [21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443,27017],
    "standard": [20,21,22,23,25,53,80,110,111,135,137,139,143,161,389,443,445,465,
        587,636,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017],
    "full": list(range(1, 1025)),
}

SERVICE_PROBES = {
    80: b"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    443: b"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    8080: b"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    21: b"", 22: b"", 25: b"EHLO scanner\r\n", 110: b"", 143: b"",
    3306: b"", 6379: b"INFO server\r\n",
    9200: b"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
}
SSL_PORTS = {443, 8443, 993, 995, 465, 636}

def load_vuln_database():
    try:
        with open(VULN_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"vulnerabilities": {}, "risky_ports": {}, "security_headers": {}}

class PortScanner:
    def __init__(self, target, ports=None, timeout=1.5, max_threads=100):
        self.target = target
        self.ports = ports or PORT_PRESETS["quick"]
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self._lock = threading.Lock()
        self._scanned = 0
        self.total_ports = len(self.ports)

    def _scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            s.close()
            with self._lock:
                self._scanned += 1
            return (port, result == 0)
        except Exception:
            with self._lock:
                self._scanned += 1
            return (port, False)

    @property
    def progress(self):
        return int((self._scanned / max(self.total_ports, 1)) * 100)

    def scan(self, progress_callback=None):
        self._scanned = 0
        self.open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(self._scan_port, p): p for p in self.ports}
            for f in as_completed(futures):
                port, is_open = f.result()
                if is_open:
                    self.open_ports.append(port)
                if progress_callback:
                    progress_callback(self.progress)
        self.open_ports.sort()
        return self.open_ports

class BannerGrabber:
    def __init__(self, target, timeout=3):
        self.target = target
        self.timeout = timeout

    def grab(self, port):
        probe_t = SERVICE_PROBES.get(port, b"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
        probe = probe_t.replace(b"{host}", self.target.encode()) if probe_t else b""
        cert_info = {}
        banner = ""
        try:
            if port in SSL_PORTS:
                banner, cert_info = self._grab_ssl(port, probe)
            else:
                banner = self._grab_tcp(port, probe)
        except Exception:
            pass
        info = self._parse_banner(port, banner)
        if cert_info:
            info["ssl_cert"] = cert_info
        return info

    def _grab_ssl(self, port, probe):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        raw.connect((self.target, port))
        s = ctx.wrap_socket(raw, server_hostname=self.target)
        ci = {}
        try:
            cert = s.getpeercert(binary_form=False)
            if cert:
                ci = {"notAfter": cert.get("notAfter","")}
        except Exception:
            pass
        if probe:
            s.sendall(probe)
        b = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        return b, ci

    def _grab_tcp(self, port, probe):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.target, port))
        if probe:
            s.sendall(probe)
        b = s.recv(4096).decode("utf-8", errors="replace")
        if not b:
            s.sendall(b"\r\n")
            b = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        return b

    def _parse_banner(self, port, raw):
        info = {"port": port, "raw_banner": (raw or "")[:500], "service": "unknown", "version": "", "software": ""}
        if not raw:
            info["service"] = self._guess_service(port)
            return info
        b = raw.strip()
        m = re.search(r'(SSH-[\d.]+-(?:OpenSSH[_\s][\w.]+|dropbear[\w.]*))', b, re.I)
        if m:
            info["service"], info["software"] = "SSH", m.group(1)
            v = re.search(r'OpenSSH[_\s]([\d.p]+)', b, re.I)
            if v: info["version"] = v.group(1)
            return info
        m = re.search(r'Server:\s*(.+)', b, re.I)
        if m:
            info["service"], info["software"] = "HTTP", m.group(1).strip()
            return info
        if re.search(r'(220|530)[\s-]', b):
            info["service"] = "FTP"
            m = re.search(r'(vsftpd\s*[\d.]+|ProFTPD\s*[\d.]+)', b, re.I)
            if m: info["software"] = m.group(1)
            return info
        if re.search(r'ESMTP', b, re.I):
            info["service"] = "SMTP"
            m = re.search(r'(Postfix|Exim\s*[\d.]+)', b, re.I)
            if m: info["software"] = m.group(1)
            return info
        if re.search(r'redis_version', b, re.I):
            info["service"] = "Redis"
            v = re.search(r'redis_version:([\d.]+)', b, re.I)
            if v: info["version"], info["software"] = v.group(1), f"Redis/{v.group(1)}"
            return info
        info["service"] = self._guess_service(port)
        return info

    def _guess_service(self, port):
        m = {20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
             110:"POP3",135:"MS-RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",
             993:"IMAPS",995:"POP3S",1433:"MS-SQL",3306:"MySQL",3389:"RDP",
             5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",
             9200:"Elasticsearch",27017:"MongoDB"}
        return m.get(port, "unknown")

    def grab_all(self, open_ports):
        results = []
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(self.grab, p): p for p in open_ports}
            for f in as_completed(futures):
                results.append(f.result())
        results.sort(key=lambda x: x["port"])
        return results

class VulnDetector:
    def __init__(self):
        self.db = load_vuln_database()

    def check_service(self, svc_info):
        findings = []
        sw = svc_info.get("software", "")
        port = svc_info.get("port", 0)
        raw = svc_info.get("raw_banner", "")
        for pattern, vi in self.db.get("vulnerabilities", {}).items():
            if self._matches(pattern, sw, raw):
                findings.append({"type":"vulnerable_software","port":port,
                    "service":svc_info.get("service","unknown"),"software":sw or pattern,
                    "cve":vi.get("cve","N/A"),"severity":vi.get("severity","UNKNOWN"),
                    "cvss":vi.get("cvss",0),"description":vi.get("description",""),
                    "remediation":vi.get("remediation","")})
        rp = self.db.get("risky_ports", {}).get(str(port))
        if rp:
            findings.append({"type":"risky_port","port":port,
                "service":rp.get("service",svc_info.get("service","unknown")),
                "severity":rp.get("risk","MEDIUM"),"description":rp.get("description",""),
                "remediation":rp.get("remediation","")})
        cert = svc_info.get("ssl_cert", {})
        if cert and cert.get("notAfter"):
            try:
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if exp < datetime.utcnow():
                    findings.append({"type":"ssl_issue","port":port,"severity":"HIGH",
                        "description":f"SSL cert expired on {cert['notAfter']}",
                        "remediation":"Renew SSL/TLS certificate immediately"})
            except ValueError:
                pass
        return findings

    def _matches(self, pattern, software, raw):
        pl = pattern.lower()
        if software and pl in software.lower(): return True
        if raw and pl in raw.lower(): return True
        return False

    def check_http_headers(self, target, port=80, use_ssl=False):
        findings = []
        hdb = self.db.get("security_headers", {})
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw.settimeout(5)
                raw.connect((target, port))
                sock = ctx.wrap_socket(raw, server_hostname=target)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
            resp = sock.recv(8192).decode("utf-8", errors="replace")
            sock.close()
            found = {}
            for line in resp.split("\r\n"):
                if ": " in line:
                    k, _, v = line.partition(": ")
                    found[k.strip().lower()] = v.strip()
            for hname, hinfo in hdb.items():
                if hname.lower() not in found:
                    findings.append({"type":"missing_header","port":port,
                        "severity":hinfo.get("severity","LOW"),"header":hname,
                        "description":f"Missing {hname}: {hinfo.get('description','')}",
                        "remediation":f"Add header: {hname}: {hinfo.get('recommended_value','')}"})
        except Exception:
            pass
        return findings

    def scan_all(self, target, service_infos):
        all_f = []
        for svc in service_infos:
            all_f.extend(self.check_service(svc))
        http_p = [s["port"] for s in service_infos if s.get("service") in ("HTTP","HTTP-Alt")]
        https_p = [s["port"] for s in service_infos if s.get("service") in ("HTTPS","HTTPS-Alt")]
        for p in http_p: all_f.extend(self.check_http_headers(target, p, False))
        for p in https_p: all_f.extend(self.check_http_headers(target, p, True))
        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"UNKNOWN":5}
        all_f.sort(key=lambda x: sev_order.get(x.get("severity","UNKNOWN"),5))
        return all_f

class VulnScanner:
    """Orchestrates the full vulnerability scanning pipeline."""
    def __init__(self, target, port_preset="quick", custom_ports=None, timeout=1.5, max_threads=100):
        self.target = target
        self.resolved_ip = None
        self.timeout = timeout
        self.max_threads = max_threads
        self.status = "idle"
        self.progress = 0
        self.phase = ""
        self.start_time = None
        self.end_time = None
        self.ports = custom_ports if custom_ports else PORT_PRESETS.get(port_preset, PORT_PRESETS["quick"])
        self.open_ports = []
        self.service_infos = []
        self.vulnerabilities = []
        self.scan_results = {}

    def resolve_target(self):
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            return False

    def run(self, progress_callback=None):
        self.start_time = datetime.now()
        self.status = "running"
        self.phase = "Resolving target..."
        self.progress = 0
        if progress_callback: progress_callback(self._get_status())
        if not self.resolve_target():
            self.status = "error"
            self.phase = f"Cannot resolve hostname: {self.target}"
            self.end_time = datetime.now()
            return self._get_status()
        self.phase = "Scanning ports..."
        self.progress = 5
        if progress_callback: progress_callback(self._get_status())
        scanner = PortScanner(self.resolved_ip, self.ports, self.timeout, self.max_threads)
        def port_progress(pct):
            self.progress = 5 + int(pct * 0.45)
            if progress_callback: progress_callback(self._get_status())
        self.open_ports = scanner.scan(progress_callback=port_progress)
        self.phase = "Grabbing service banners..."
        self.progress = 50
        if progress_callback: progress_callback(self._get_status())
        if self.open_ports:
            grabber = BannerGrabber(self.resolved_ip, timeout=self.timeout+1)
            self.service_infos = grabber.grab_all(self.open_ports)
        else:
            self.service_infos = []
        self.phase = "Detecting vulnerabilities..."
        self.progress = 75
        if progress_callback: progress_callback(self._get_status())
        detector = VulnDetector()
        self.vulnerabilities = detector.scan_all(self.resolved_ip, self.service_infos)
        self.phase = "Generating report..."
        self.progress = 95
        if progress_callback: progress_callback(self._get_status())
        self.end_time = datetime.now()
        self.status = "completed"
        self.progress = 100
        self.phase = "Scan complete"
        self.scan_results = self._compile_results()
        if progress_callback: progress_callback(self._get_status())
        return self.scan_results

    def _compile_results(self):
        sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        for v in self.vulnerabilities:
            s = v.get("severity","INFO")
            if s in sev_counts: sev_counts[s] += 1
        risk = self._calc_risk()
        dur = (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0
        return {
            "scan_info": {"target": self.target, "resolved_ip": self.resolved_ip,
                "ports_scanned": len(self.ports),
                "scan_start": self.start_time.isoformat() if self.start_time else None,
                "scan_end": self.end_time.isoformat() if self.end_time else None,
                "duration_seconds": round(dur, 2)},
            "summary": {"open_ports": len(self.open_ports), "total_vulnerabilities": len(self.vulnerabilities),
                "severity_counts": sev_counts, "risk_score": risk, "risk_level": self._risk_level(risk)},
            "open_ports": self.open_ports,
            "services": self.service_infos,
            "vulnerabilities": self.vulnerabilities,
        }

    def _calc_risk(self):
        w = {"CRITICAL":25,"HIGH":15,"MEDIUM":8,"LOW":3,"INFO":1}
        return min(sum(w.get(v.get("severity","INFO"),1) for v in self.vulnerabilities), 100)

    def _risk_level(self, score):
        if score >= 75: return "CRITICAL"
        if score >= 50: return "HIGH"
        if score >= 25: return "MEDIUM"
        if score > 0: return "LOW"
        return "NONE"

    def _get_status(self):
        return {"status": self.status, "progress": self.progress, "phase": self.phase}

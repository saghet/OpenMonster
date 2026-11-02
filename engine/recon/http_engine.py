"""
SECMASTER HTTP & TLS Header Intelligence Engine.
Performs RFC-compliant HTTP/HTTPS inspection, security header audit,
cookie attribute validation (Secure, HttpOnly, SameSite), and cryptographic
X.509 certificate evaluation (TLS version, cipher suite, issuer, expiry).
Does not perform denial-of-service or generate excessive traffic.
"""

from datetime import datetime, timezone
import logging
import os
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from engine.recon.contracts import HttpFingerprintResult, SubdomainResult

logger = logging.getLogger("sec_master.recon.http")

# Title regex pattern
_TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Header patterns that leak software versions
_VERSION_LEAK_PATTERN = re.compile(r"[\d]+\.[\d]+", re.IGNORECASE)


def parse_x509_cert(cert_dict: Dict[str, Any]) -> Tuple[str, str, Optional[int], List[str]]:
    """
    Parses subject, issuer, days until expiry, and SANs from ssl.getpeercert() output.
    """
    subject_parts = []
    for rdn in cert_dict.get("subject", ()):
        for key, value in rdn:
            if key in ("commonName", "organizationName"):
                subject_parts.append(f"{key}={value}")
    subject_str = ", ".join(subject_parts) or "Unknown Subject"

    issuer_parts = []
    for rdn in cert_dict.get("issuer", ()):
        for key, value in rdn:
            if key in ("commonName", "organizationName"):
                issuer_parts.append(f"{key}={value}")
    issuer_str = ", ".join(issuer_parts) or "Unknown Issuer"

    # Expiry calculation
    days_left = None
    not_after = cert_dict.get("notAfter")
    if not_after:
        try:
            # Example: 'May 15 12:00:00 2027 GMT'
            exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(timezone.utc)
            days_left = (exp_date - now).days
        except Exception as e:
            logger.debug(f"Failed to parse TLS certificate notAfter '{not_after}': {e}")

    # Subject Alternative Names (SANs)
    sans = []
    for san_type, san_val in cert_dict.get("subjectAltName", ()):
        if san_type == "DNS":
            sans.append(san_val)

    return subject_str, issuer_str, days_left, sans


class HttpIntelligenceEngine:
    """
    Non-destructive HTTP & TLS Intelligence Engine.
    Evaluates response headers, security flags, cookies, and TLS certificate hygiene.
    """

    def __init__(
        self,
        target: str,
        emitter: Optional[Any] = None,
        timeout: int = 8,
    ):
        self.target = target.strip()
        self.emitter = emitter
        self.timeout = timeout
        self.user_agent = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SECMASTER/1.0"
        )

    def _emit_log(self, message: str, level: str = "INFO"):
        if not self.emitter:
            return
        if hasattr(self.emitter, "log"):
            self.emitter.log(message, level=level)
        elif hasattr(self.emitter, "emit"):
            self.emitter.emit("log", {"message": message, "level": level})

    def _emit_finding(self, finding_data: Dict[str, Any]):
        if not self.emitter:
            return
        if hasattr(self.emitter, "finding"):
            self.emitter.finding(finding_data)
        elif hasattr(self.emitter, "emit"):
            self.emitter.emit("finding", finding_data)

    def inspect_tls(
        self, hostname: str, port: int = 443
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[int]]:
        """
        Connects via TLS socket to evaluate SSL version, cipher suite, and certificate health.
        """
        tls_version = None
        tls_cipher = None
        cert_subject = None
        cert_issuer = None
        days_left = None

        # 1. Try verified TLS connection
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        tls_cipher = cipher_info[0]
                    cert = ssock.getpeercert()
                    if cert:
                        cert_subject, cert_issuer, days_left, _ = parse_x509_cert(cert)
            return tls_version, tls_cipher, cert_subject, cert_issuer, days_left
        except (ssl.SSLCertVerificationError, ssl.SSLError) as e:
            logger.debug(f"Verified TLS connection failed for {hostname}:{port}: {e}")
            # Flag certificate validation error as finding
            self._emit_finding({
                "title": f"TLS Certificate Verification Error on {hostname}",
                "category": "Web Security",
                "attack_type": "tls",
                "vector": f"tls:{port}",
                "severity": "medium",
                "confidence": 100,
                "cve": None,
                "cwe": "CWE-295",
                "owasp": "A02:2021 - Cryptographic Failures",
                "cvss_score": 5.9,
                "description": f"The TLS certificate presented by '{hostname}' failed chain verification: {e}",
                "evidence": {"hostname": hostname, "error": str(e)},
                "remediation": "Install a valid, non-expired TLS certificate issued by a trusted Certificate Authority.",
                "verified": True,
            })

            # 2. Try unverified connection to extract subject/issuer from untrusted/self-signed cert
            try:
                unverified_ctx = ssl._create_unverified_context()
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        tls_version = ssock.version()
                        cipher_info = ssock.cipher()
                        if cipher_info:
                            tls_cipher = cipher_info[0]
                        cert_bin = ssock.getpeercert(binary_form=True)
                        if cert_bin:
                            cert_subject = "Self-Signed or Untrusted CA (Chain Failed)"
                            cert_issuer = "Self-Signed or Untrusted CA"
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"TLS connection could not be established to {hostname}:{port}: {e}")

        return tls_version, tls_cipher, cert_subject, cert_issuer, days_left

    def inspect_endpoint(self, target_url: str) -> Optional[HttpFingerprintResult]:
        """Performs structured HTTP and TLS inspection of a single URL."""
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url
        is_https = parsed.scheme == "https"
        port = parsed.port or (443 if is_https else 80)

        # 1. TLS Inspection if HTTPS
        tls_version, tls_cipher, cert_subject, cert_issuer, days_left = (
            None,
            None,
            None,
            None,
            None,
        )
        if is_https:
            tls_version, tls_cipher, cert_subject, cert_issuer, days_left = (
                self.inspect_tls(hostname, port)
            )

        # 2. HTTP Request
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        try:
            resp = requests.get(
                target_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,  # Allow inspecting targets with self-signed certs without crashing
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"HTTP inspection failed for {target_url}: {e}")
            return None

        # Extract title
        title = None
        if resp.text:
            m = _TITLE_PATTERN.search(resp.text[:50000])  # limit search to first 50KB
            if m:
                title = m.group(1).strip()

        # Lowercase headers dict
        raw_headers = {k.lower(): v for k, v in resp.headers.items()}
        server_header = raw_headers.get("server")
        content_type = raw_headers.get("content-type")

        # Security Headers Map
        security_header_keys = [
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "x-xss-protection",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
        ]
        sec_headers = {k: raw_headers[k] for k in security_header_keys if k in raw_headers}

        # Cookie Analysis
        cookies_list: List[Dict[str, Any]] = []
        for cookie in resp.cookies:
            # Detect samesite attribute
            samesite = "Missing"
            if hasattr(cookie, "get_nonstandard_attr"):
                samesite_attr = cookie.get_nonstandard_attr("samesite")
                if samesite_attr:
                    samesite = str(samesite_attr).capitalize()

            # Check httponly
            httponly = False
            if hasattr(cookie, "has_nonstandard_attr"):
                httponly = cookie.has_nonstandard_attr("httponly")
            elif hasattr(cookie, "_rest") and "httponly" in cookie._rest:
                httponly = True

            c_info = {
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": bool(cookie.secure),
                "httponly": httponly,
                "samesite": samesite,
            }
            cookies_list.append(c_info)

            # Audit cookie hygiene
            if is_https and not cookie.secure:
                self._emit_finding({
                    "title": f"Cookie '{cookie.name}' Missing 'Secure' Attribute",
                    "category": "Web Security",
                    "attack_type": "cookie_security",
                    "vector": f"cookie:{cookie.name}",
                    "severity": "medium",
                    "confidence": 100,
                    "cve": None,
                    "cwe": "CWE-614",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "cvss_score": 5.0,
                    "description": f"The cookie '{cookie.name}' was set over HTTPS without the 'Secure' flag, allowing transmission over unencrypted HTTP.",
                    "evidence": {"cookie_name": cookie.name, "url": target_url},
                    "remediation": "Set the 'Secure' flag on all cookies issued over HTTPS.",
                    "verified": True,
                })

            if not httponly and any(k in cookie.name.lower() for k in ("sess", "auth", "token", "jwt", "id", "login")):
                self._emit_finding({
                    "title": f"Session Cookie '{cookie.name}' Missing 'HttpOnly' Flag",
                    "category": "Web Security",
                    "attack_type": "cookie_security",
                    "vector": f"cookie:{cookie.name}",
                    "severity": "medium",
                    "confidence": 95,
                    "cve": None,
                    "cwe": "CWE-1004",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "cvss_score": 5.3,
                    "description": f"Sensitive session cookie '{cookie.name}' lacks 'HttpOnly', allowing client-side JavaScript access via XSS.",
                    "evidence": {"cookie_name": cookie.name, "url": target_url},
                    "remediation": "Configure 'HttpOnly' flag for all authentication and session identifiers.",
                    "verified": True,
                })

        # Audit Security Headers
        if is_https and "strict-transport-security" not in sec_headers:
            self._emit_finding({
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "category": "Web Security",
                "attack_type": "headers",
                "vector": "header:Strict-Transport-Security",
                "severity": "medium",
                "confidence": 100,
                "cve": None,
                "cwe": "CWE-319",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cvss_score": 5.3,
                "description": f"HTTPS service at {target_url} does not enforce Strict-Transport-Security, exposing users to SSL-stripping MITM attacks.",
                "evidence": {"missing_header": "Strict-Transport-Security", "url": target_url},
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to all HTTPS responses.",
                "verified": True,
            })

        if "content-security-policy" not in sec_headers:
            self._emit_finding({
                "title": "Missing Content-Security-Policy (CSP)",
                "category": "Web Security",
                "attack_type": "headers",
                "vector": "header:Content-Security-Policy",
                "severity": "medium",
                "confidence": 100,
                "cve": None,
                "cwe": "CWE-1021",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cvss_score": 5.3,
                "description": f"No Content-Security-Policy header defined for {target_url}.",
                "evidence": {"missing_header": "Content-Security-Policy", "url": target_url},
                "remediation": "Define a robust Content-Security-Policy restricting unauthorized scripts, objects, and framing.",
                "verified": True,
            })

        if "x-frame-options" not in sec_headers and "content-security-policy" not in sec_headers:
            self._emit_finding({
                "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                "category": "Web Security",
                "attack_type": "headers",
                "vector": "header:X-Frame-Options",
                "severity": "medium",
                "confidence": 100,
                "cve": None,
                "cwe": "CWE-1021",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cvss_score": 4.7,
                "description": f"Neither X-Frame-Options nor CSP frame-ancestors are present on {target_url}.",
                "evidence": {"missing_header": "X-Frame-Options", "url": target_url},
                "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                "verified": True,
            })

        if "x-content-type-options" not in sec_headers:
            self._emit_finding({
                "title": "Missing X-Content-Type-Options: nosniff",
                "category": "Web Security",
                "attack_type": "headers",
                "vector": "header:X-Content-Type-Options",
                "severity": "low",
                "confidence": 100,
                "cve": None,
                "cwe": "CWE-16",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cvss_score": 3.1,
                "description": f"Browser MIME-sniffing protection is disabled on {target_url}.",
                "evidence": {"missing_header": "X-Content-Type-Options", "url": target_url},
                "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
                "verified": True,
            })

        # Information disclosure via Server or X-Powered-By
        if server_header and _VERSION_LEAK_PATTERN.search(server_header):
            self._emit_finding({
                "title": f"Web Server Exact Version Disclosure ('{server_header}')",
                "category": "Web Security",
                "attack_type": "info_disclosure",
                "vector": "header:Server",
                "severity": "low",
                "confidence": 100,
                "cve": None,
                "cwe": "CWE-200",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cvss_score": 3.7,
                "description": f"Server header reveals precise version details: '{server_header}'.",
                "evidence": {"server": server_header, "url": target_url},
                "remediation": "Configure web server tokens (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx) to suppress version numbers.",
                "verified": True,
            })

        # Certificate Expiration Audit
        if days_left is not None:
            if days_left < 0:
                self._emit_finding({
                    "title": f"Expired TLS Certificate on {hostname}",
                    "category": "Web Security",
                    "attack_type": "tls",
                    "vector": f"tls:{port}",
                    "severity": "high",
                    "confidence": 100,
                    "cve": None,
                    "cwe": "CWE-298",
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "cvss_score": 7.5,
                    "description": f"The TLS certificate for {hostname} expired {abs(days_left)} days ago.",
                    "evidence": {"days_left": days_left, "hostname": hostname},
                    "remediation": "Renew and deploy a valid TLS certificate immediately.",
                    "verified": True,
                })
            elif days_left < 30:
                self._emit_finding({
                    "title": f"TLS Certificate Expiring Soon ({days_left} days remaining) on {hostname}",
                    "category": "Web Security",
                    "attack_type": "tls",
                    "vector": f"tls:{port}",
                    "severity": "low",
                    "confidence": 100,
                    "cve": None,
                    "cwe": "CWE-298",
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "cvss_score": 3.1,
                    "description": f"The TLS certificate for {hostname} expires in {days_left} days.",
                    "evidence": {"days_left": days_left, "hostname": hostname},
                    "remediation": "Initiate certificate renewal before service disruption occurs.",
                    "verified": True,
                })

        return HttpFingerprintResult(
            target_url=target_url,
            status_code=resp.status_code,
            server_header=server_header,
            title=title,
            content_type=content_type,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            tls_cert_subject=cert_subject,
            tls_cert_issuer=cert_issuer,
            tls_cert_days_left=days_left,
            security_headers=sec_headers,
            cookies=cookies_list,
            raw_headers=raw_headers,
        )

    def run(
        self, subdomains: Optional[List[SubdomainResult]] = None
    ) -> List[HttpFingerprintResult]:
        """
        Executes HTTP & TLS inspection across base target and verified live subdomains.
        Limits to safe batch size to prevent excessive resource utilization.
        """
        fingerprints: List[HttpFingerprintResult] = []
        endpoints_to_probe: List[str] = []

        # 1. Base Target
        base_url = self.target
        if not base_url.startswith(("http://", "https://")):
            endpoints_to_probe.append(f"https://{base_url}")
        else:
            endpoints_to_probe.append(base_url)

        # 2. Add verified live subdomains (up to 10 endpoints max)
        if subdomains:
            live_subs = [s for s in subdomains if s.is_live]
            # If none are marked live, take up to 5 with highest confidence
            if not live_subs:
                live_subs = sorted(subdomains, key=lambda s: s.confidence, reverse=True)[:5]

            for s in live_subs[:10]:
                sub_url = f"https://{s.subdomain}"
                if sub_url not in endpoints_to_probe:
                    endpoints_to_probe.append(sub_url)

        self._emit_log(
            f"Iniciando HTTP & TLS Intelligence sobre {len(endpoints_to_probe)} endpoint(s)...",
            level="INFO",
        )

        for endpoint in endpoints_to_probe:
            self._emit_log(f"Inspeccionando cabeceras y TLS en '{endpoint}'...", level="DEBUG")
            fp = self.inspect_endpoint(endpoint)
            if fp:
                fingerprints.append(fp)
                # If target was a subdomain, record status_code
                if subdomains:
                    for sub in subdomains:
                        if sub.subdomain in endpoint:
                            sub.http_status = fp.status_code

        self._emit_log(
            f"HTTP & TLS Intelligence completado: {len(fingerprints)} huellas obtenidas.",
            level="INFO",
        )

        return fingerprints

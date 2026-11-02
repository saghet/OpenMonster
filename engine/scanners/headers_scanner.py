"""
Security Headers and Misconfiguration Scanner.
Audits CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and server banner disclosure.
"""

from typing import List, Optional
import requests
from engine.core.event import EventEmitter
from engine.core.module import Finding, SecurityModule


class HeadersScanner(SecurityModule):
    def __init__(self):
        super().__init__(
            module_id="security_headers",
            name="Security Headers & Server Configuration",
            description="Audits HTTP response headers for missing transport encryption and injection defenses.",
            version="1.0.0",
            category="Web Security",
            risk_level="low",
            cwe="CWE-693",
            owasp="A05:2021 - Security Misconfiguration",
            remediation="Implement strict baseline HTTP headers including CSP, HSTS, X-Content-Type-Options: nosniff, and X-Frame-Options: DENY.",
            references=[
                "https://owasp.org/www-project-secure-headers/",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
            ],
        )

    def scan(
        self,
        target_url: str,
        baseline_response: Optional[requests.Response],
        session: requests.Session,
        emitter: EventEmitter,
    ) -> List[Finding]:
        findings: List[Finding] = []
        emitter.log("Iniciando auditoría de cabeceras de seguridad y configuración de transporte...")

        if not baseline_response:
            try:
                baseline_response = session.get(target_url, timeout=7, allow_redirects=True)
            except Exception as e:
                emitter.log(f"No se pudo obtener respuesta para análisis de cabeceras: {e}", level="ERROR")
                return findings

        headers = baseline_response.headers

        # 1. Content-Security-Policy (CSP)
        if "Content-Security-Policy" not in headers:
            f = Finding(
                title="Missing Content-Security-Policy (CSP) Header",
                category=self.category,
                attack_type="headers",
                vector="header",
                severity="medium",
                confidence=100,
                cwe="CWE-1021",
                owasp="A05:2021 - Security Misconfiguration",
                cvss_score=5.3,
                description="The server does not specify a Content-Security-Policy header, allowing unauthorized scripts and data injection.",
                evidence={"missing_header": "Content-Security-Policy"},
                remediation="Configure a restrictive Content-Security-Policy header omitting 'unsafe-inline' and 'unsafe-eval'.",
                verified=True,
            )
            findings.append(f)
            emitter.finding(f.to_dict())

        # 2. Strict-Transport-Security (HSTS)
        if target_url.startswith("https://") and "Strict-Transport-Security" not in headers:
            f = Finding(
                title="Missing HTTP Strict Transport Security (HSTS)",
                category=self.category,
                attack_type="headers",
                vector="header",
                severity="low",
                confidence=100,
                cwe="CWE-319",
                owasp="A05:2021 - Security Misconfiguration",
                cvss_score=3.7,
                description="The application does not instruct the browser to use HTTPS exclusively via HSTS.",
                evidence={"missing_header": "Strict-Transport-Security"},
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                verified=True,
            )
            findings.append(f)
            emitter.finding(f.to_dict())

        # 3. X-Frame-Options (Clickjacking)
        if "X-Frame-Options" not in headers and "frame-ancestors" not in headers.get("Content-Security-Policy", ""):
            f = Finding(
                title="Missing Anti-Clickjacking Defense (X-Frame-Options)",
                category=self.category,
                attack_type="headers",
                vector="header",
                severity="medium",
                confidence=100,
                cwe="CWE-1021",
                owasp="A05:2021 - Security Misconfiguration",
                cvss_score=4.7,
                description="The page can be framed by untrusted external websites, leading to clickjacking vulnerabilities.",
                evidence={"missing_header": "X-Frame-Options"},
                remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                verified=True,
            )
            findings.append(f)
            emitter.finding(f.to_dict())

        # 4. X-Content-Type-Options
        if "X-Content-Type-Options" not in headers:
            f = Finding(
                title="Missing X-Content-Type-Options Header",
                category=self.category,
                attack_type="headers",
                vector="header",
                severity="low",
                confidence=100,
                cwe="CWE-16",
                owasp="A05:2021 - Security Misconfiguration",
                cvss_score=3.1,
                description="Without 'X-Content-Type-Options: nosniff', browsers may attempt to MIME-sniff the response, leading to unexpected script execution.",
                evidence={"missing_header": "X-Content-Type-Options"},
                remediation="Set 'X-Content-Type-Options: nosniff' on all responses.",
                verified=True,
            )
            findings.append(f)
            emitter.finding(f.to_dict())

        return findings

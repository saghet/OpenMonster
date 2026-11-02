"""
CORS Misconfiguration Security Plugin for SECMASTER.
Identifies unsafe Access-Control-Allow-Origin wildcard reflection with credentials.
"""

from typing import List, Optional
import requests
from engine.core.event import EventEmitter
from engine.core.module import Finding, SecurityModule


class PluginScanner(SecurityModule):
    def __init__(self):
        super().__init__(
            module_id="cors-misconfig-scanner",
            name="CORS Misconfiguration Scanner",
            description="Audita encabezados Cross-Origin Resource Sharing (CORS) en busca de orígenes arbitrarios reflejados con credenciales habilitadas.",
            version="1.0.0",
            category="Web Security",
            risk_level="high",
            cwe="CWE-942",
            owasp="A01:2021 - Broken Access Control",
            remediation="Nunca reflejar orígenes no confiables en Access-Control-Allow-Origin si Access-Control-Allow-Credentials es true. Use listas blancas estrictas.",
            references=[
                "https://portswigger.net/web-security/cors",
                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
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
        emitter.emit_log(f"Auditing CORS policy on {target_url}...", level="INFO")

        probe_origin = "https://evil-untrusted-cors-test.com"
        headers = {"Origin": probe_origin}

        try:
            resp = session.get(target_url, headers=headers, timeout=5, allow_redirects=False)
            allow_origin = resp.headers.get("Access-Control-Allow-Origin")
            allow_credentials = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if allow_origin == probe_origin and allow_credentials == "true":
                emitter.emit_log(
                    f"[HIGH] Arbitrary CORS Origin reflection with credentials detected on {target_url}",
                    level="WARNING",
                )
                findings.append(
                    Finding(
                        title="Insecure CORS Policy with Reflected Origin and Credentials",
                        category=self.category,
                        attack_type="cors_misconfiguration",
                        vector=f"header:Origin:{probe_origin}",
                        severity="high",
                        confidence=100,
                        cwe=self.cwe,
                        owasp=self.owasp,
                        cvss_score=7.5,
                        description=(
                            f"The server reflects the untrusted request Origin header ('{probe_origin}') directly in "
                            "'Access-Control-Allow-Origin' while setting 'Access-Control-Allow-Credentials: true'. "
                            "This allows any malicious third-party website visited by an authenticated user to extract sensitive data."
                        ),
                        evidence={
                            "target_url": target_url,
                            "sent_origin": probe_origin,
                            "received_allow_origin": allow_origin,
                            "received_allow_credentials": allow_credentials,
                            "http_status": resp.status_code,
                        },
                        remediation=self.remediation,
                        verified=True,
                    )
                )
            elif allow_origin == "*":
                emitter.emit_log(f"CORS Wildcard (*) detected on {target_url}", level="INFO")
                findings.append(
                    Finding(
                        title="Overly Permissive CORS Policy (Wildcard '*')",
                        category=self.category,
                        attack_type="cors_wildcard",
                        vector="header:Access-Control-Allow-Origin:*",
                        severity="low",
                        confidence=95,
                        cwe=self.cwe,
                        owasp=self.owasp,
                        cvss_score=3.7,
                        description="The server allows any origin to read public resources via wildcard '*' CORS header.",
                        evidence={
                            "target_url": target_url,
                            "received_allow_origin": "*",
                            "http_status": resp.status_code,
                        },
                        remediation="If the resource contains sensitive private data, restrict Access-Control-Allow-Origin to authorized domains.",
                        verified=True,
                    )
                )

        except Exception as e:
            emitter.emit_log(f"CORS probe skipped: {e}", level="DEBUG")

        return findings

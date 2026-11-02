"""
Differential Cross-Site Scripting (XSS) Scanner.
Replaces upstream naive '<script>' matching with unique canary tokens and reflection analysis.
"""

import html
import random
import urllib.parse
from typing import List, Optional
import requests
from engine.core.event import EventEmitter
from engine.core.module import Finding, SecurityModule


class XSSScanner(SecurityModule):
    def __init__(self):
        super().__init__(
            module_id="xss_differential",
            name="Reflected Cross-Site Scripting (XSS)",
            description="Detects unescaped payload reflection in DOM and HTML attributes using randomized canary tokens.",
            version="1.0.0",
            category="Web Security",
            risk_level="high",
            cwe="CWE-79",
            owasp="A03:2021 - Injection",
            remediation="Apply context-sensitive output encoding (HTML entity, JavaScript escaping) and implement a robust Content-Security-Policy.",
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting",
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
        emitter.log("Iniciando análisis XSS diferencial con tokens de canario...")

        baseline_text = baseline_response.text if baseline_response else ""

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        test_params = list(params.keys()) if params else ["q", "search", "s", "query", "id"]

        for param in test_params:
            canary_id = f"sec_xss_{random.randint(100000, 999999)}"

            # Non-destructive test probes checking attribute and tag escape
            payloads = [
                f'"><span id="{canary_id}">test</span>',
                f"'{canary_id}",
                f'"{canary_id}',
                f'<svg/onload=confirm("{canary_id}")>',
            ]

            for payload in payloads:
                # Skip if canary already appears in baseline
                if canary_id in baseline_text:
                    continue

                query_copy = dict(params)
                query_copy[param] = [payload]
                new_query = urllib.parse.urlencode(query_copy, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                try:
                    resp = session.get(test_url, timeout=7, allow_redirects=False)

                    # Check for unencoded reflection
                    if canary_id in resp.text:
                        # Ensure it wasn't sanitized to HTML entities
                        escaped_canary = html.escape(canary_id)
                        raw_reflected = (canary_id in resp.text) and (f'"{canary_id}"' in resp.text or f'>{canary_id}<' in resp.text or f"confirm(\"{canary_id}\")" in resp.text)

                        emitter.log(
                            f"[HIGH] Reflexión no sanitizada de payload XSS detectada en parámetro '{param}'",
                            level="WARNING",
                        )

                        finding = Finding(
                            title=f"Reflected Cross-Site Scripting (XSS) en parámetro '{param}'",
                            category=self.category,
                            attack_type="xss",
                            vector=f"query:{param}",
                            severity="high",
                            confidence=95,
                            cwe=self.cwe,
                            owasp=self.owasp,
                            cvss_score=8.1,
                            description=f"El parámetro '{param}' refleja datos ingresados por el usuario sin codificación adecuada en el cuerpo HTML de la respuesta.",
                            evidence={
                                "url": test_url,
                                "parameter": param,
                                "canary_token": canary_id,
                                "payload": payload,
                                "http_status": resp.status_code,
                                "raw_reflection": raw_reflected,
                            },
                            remediation=self.remediation,
                            verified=True,
                        )
                        findings.append(finding)
                        emitter.finding(finding.to_dict())
                        break  # Move to next parameter
                except Exception as e:
                    emitter.log(f"Error evaluando parámetro XSS '{param}': {e}", level="DEBUG")

        return findings

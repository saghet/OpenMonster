"""
Differential Server-Side Template Injection (SSTI) Scanner.
Replaces upstream secMONSTER naive '49' regex with dynamic random math verification.
"""

import random
import urllib.parse
from typing import List, Optional
import requests
from engine.core.event import EventEmitter
from engine.core.module import Finding, SecurityModule


class SSTIScanner(SecurityModule):
    def __init__(self):
        super().__init__(
            module_id="ssti_differential",
            name="Server-Side Template Injection (SSTI)",
            description="Evaluates template injection using dynamic randomized computed expressions.",
            version="1.0.0",
            category="Web Security",
            risk_level="critical",
            cwe="CWE-1336",
            owasp="A03:2021 - Injection",
            remediation="Never concatenate user input directly into template engines. Use contextual sandboxing and logic-less templates.",
            references=[
                "https://owasp.org/www-community/attacks/Server-Side_Template_Injection",
                "https://portswigger.net/web-security/server-side-template-injection",
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
        emitter.log("Iniciando análisis SSTI diferencial con cálculo dinámico...")

        baseline_text = baseline_response.text if baseline_response else ""

        # Generate unique random factors (e.g. 2381 * 4912)
        n1 = random.randint(1200, 9900)
        n2 = random.randint(1100, 8900)
        expected_product = str(n1 * n2)

        # Skip if the target page happens to contain this random number in baseline
        if expected_product in baseline_text:
            n1 += 13
            expected_product = str(n1 * n2)

        templates = [
            f"{{{{{n1}*{n2}}}}}",           # Jinja2 / Twig
            f"${{{n1}*{n2}}}",             # Freemarker / Spring Expression
            f"<%= {n1}*{n2} %>",           # ERB / EJS
            f"#{{{n1}*{n2}}}",             # Ruby
        ]

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        # If no query params exist, test a default test param
        test_params = list(params.keys()) if params else ["test", "template", "view"]

        for param in test_params:
            for payload in templates:
                query_copy = dict(params)
                query_copy[param] = [payload]
                new_query = urllib.parse.urlencode(query_copy, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                try:
                    resp = session.get(test_url, timeout=7, allow_redirects=False)

                    # True verification: the exact computed product is returned and was absent in baseline
                    if expected_product in resp.text and expected_product not in baseline_text:
                        emitter.log(
                            f"[CRITICAL] Expresión matemática computada detectada ({n1}*{n2} = {expected_product}) en parámetro '{param}'",
                            level="WARNING",
                        )

                        finding = Finding(
                            title=f"Server-Side Template Injection (SSTI) en parámetro '{param}'",
                            category=self.category,
                            attack_type="ssti",
                            vector=f"query:{param}",
                            severity="critical",
                            confidence=100,
                            cwe=self.cwe,
                            owasp=self.owasp,
                            cvss_score=9.8,
                            description=f"El parámetro '{param}' evalúa expresiones dinámicas en el motor de plantillas del servidor, ejecutando código arbitrario ({n1}*{n2} resultó en '{expected_product}').",
                            evidence={
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "computed_product": expected_product,
                                "http_status": resp.status_code,
                                "differential_verified": True,
                            },
                            remediation=self.remediation,
                            verified=True,
                        )
                        findings.append(finding)
                        emitter.finding(finding.to_dict())
                        return findings  # Return immediately on confirmed critical vulnerability
                except Exception as e:
                    emitter.log(f"Error evaluando payload SSTI '{payload}': {e}", level="DEBUG")

        return findings

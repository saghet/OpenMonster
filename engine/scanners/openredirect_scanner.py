"""
Open Redirect Vulnerability Scanner.
Checks 3xx redirects and Location header destinations against injected domains.
"""

import urllib.parse
from typing import List, Optional
import requests
from engine.core.event import EventEmitter
from engine.core.module import Finding, SecurityModule

REDIRECT_PARAMS = [
    "next", "url", "target", "rurl", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "return_to", "return"
]


class OpenRedirectScanner(SecurityModule):
    def __init__(self):
        super().__init__(
            module_id="open_redirect",
            name="Open Redirect",
            description="Evaluates untrusted destination redirection in authentication and navigation parameters.",
            version="1.0.0",
            category="Web Security",
            risk_level="medium",
            cwe="CWE-601",
            owasp="A01:2021 - Broken Access Control",
            remediation="Validate redirection targets against a strict allowlist of relative paths or trusted company domains.",
            references=[
                "https://cwe.mitre.org/data/definitions/601.html",
                "https://portswigger.net/web-security/open-redirect",
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
        emitter.log("Iniciando análisis de Open Redirect en parámetros de navegación...")

        test_destinations = [
            "https://example.com/sec_master_verify",
            "//example.com/sec_master_verify",
        ]

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        # Test both existing parameters and common redirect parameter names
        target_param_names = set(params.keys()).union(set(REDIRECT_PARAMS[:6]))

        for param in target_param_names:
            for test_target in test_destinations:
                query_copy = dict(params)
                query_copy[param] = [test_target]
                new_query = urllib.parse.urlencode(query_copy, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                try:
                    resp = session.get(test_url, timeout=7, allow_redirects=False)

                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("Location", "")
                        if "example.com/sec_master_verify" in location:
                            emitter.log(
                                f"[MEDIUM] Open Redirect verificado en parámetro '{param}' -> {location}",
                                level="WARNING",
                            )
                            finding = Finding(
                                title=f"Open Redirect en parámetro '{param}'",
                                category=self.category,
                                attack_type="openredirect",
                                vector=f"query:{param}",
                                severity="medium",
                                confidence=100,
                                cwe=self.cwe,
                                owasp=self.owasp,
                                cvss_score=6.1,
                                description=f"El parámetro '{param}' permite a un atacante redirigir a los usuarios hacia dominios arbitrarios no confiables mediante la cabecera 'Location'.",
                                evidence={
                                    "url": test_url,
                                    "parameter": param,
                                    "injected_destination": test_target,
                                    "header_location": location,
                                    "http_status": resp.status_code,
                                },
                                remediation=self.remediation,
                                verified=True,
                            )
                            findings.append(finding)
                            emitter.finding(finding.to_dict())
                            break
                except Exception as e:
                    emitter.log(f"Error evaluando Open Redirect en '{param}': {e}", level="DEBUG")

        return findings

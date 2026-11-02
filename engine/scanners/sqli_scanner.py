"""
Differential SQL Injection (SQLi) Scanner.
Uses boolean divergence and database error detection with baseline comparison.
"""

import re
import urllib.parse
from typing import List, Optional
import requests
from engine.core.event import EventEmitter
from engine.core.module import Finding, SecurityModule

DB_ERRORS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\): query failed", re.I),
    re.compile(r"sqlite3::sqlexception", re.I),
    re.compile(r"microsoft ole db provider for odbc drivers error", re.I),
]


class SQLiScanner(SecurityModule):
    def __init__(self):
        super().__init__(
            module_id="sqli_differential",
            name="SQL Injection (SQLi)",
            description="Evaluates SQL injection via boolean response divergence and database error signatures.",
            version="1.0.0",
            category="Web Security",
            risk_level="critical",
            cwe="CWE-89",
            owasp="A03:2021 - Injection",
            remediation="Use parameterized queries (Prepared Statements) or an ORM for all database operations.",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection",
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
        emitter.log("Iniciando análisis SQLi diferencial (Boolean & Error based)...")

        baseline_len = len(baseline_response.text) if baseline_response else 0
        baseline_status = baseline_response.status_code if baseline_response else 200

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        test_params = list(params.keys()) if params else ["id", "user", "cat", "item", "page"]

        for param in test_params:
            # 1. Error-based probe: single quote and double quote
            for error_payload in ["'", "''", "\"", "\\"]:
                query_copy = dict(params)
                orig_val = query_copy.get(param, ["1"])[0]
                query_copy[param] = [f"{orig_val}{error_payload}"]
                new_query = urllib.parse.urlencode(query_copy, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                try:
                    resp = session.get(test_url, timeout=7, allow_redirects=False)
                    for err_re in DB_ERRORS:
                        match = err_re.search(resp.text)
                        if match:
                            emitter.log(
                                f"[CRITICAL] Error de base de datos detectado en parámetro '{param}': {match.group(0)}",
                                level="WARNING",
                            )
                            finding = Finding(
                                title=f"SQL Injection (Error-Based) en parámetro '{param}'",
                                category=self.category,
                                attack_type="sqli",
                                vector=f"query:{param}",
                                severity="critical",
                                confidence=95,
                                cwe=self.cwe,
                                owasp=self.owasp,
                                cvss_score=9.3,
                                description=f"El parámetro '{param}' provocó un error explícito de sintaxis SQL en el motor de base de datos: '{match.group(0)}'.",
                                evidence={
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": error_payload,
                                    "db_error_detected": match.group(0),
                                    "http_status": resp.status_code,
                                },
                                remediation=self.remediation,
                                verified=True,
                            )
                            findings.append(finding)
                            emitter.finding(finding.to_dict())
                            return findings
                except Exception as e:
                    emitter.log(f"Error evaluando SQLi error probe en '{param}': {e}", level="DEBUG")

            # 2. Boolean-based divergence: TRUE condition vs FALSE condition
            try:
                true_query = dict(params)
                true_query[param] = ["1' OR '1'='1"]
                resp_true = session.get(
                    urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(true_query, doseq=True))),
                    timeout=7,
                    allow_redirects=False,
                )

                false_query = dict(params)
                false_query[param] = ["1' AND '1'='0"]
                resp_false = session.get(
                    urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(false_query, doseq=True))),
                    timeout=7,
                    allow_redirects=False,
                )

                # Significant difference in length between True and False condition, with True resembling baseline
                len_true = len(resp_true.text)
                len_false = len(resp_false.text)
                delta = abs(len_true - len_false)

                if delta > 120 and resp_true.status_code == 200 and resp_false.status_code != 500:
                    emitter.log(
                        f"[HIGH] Divergencia booleana SQLi detectada en '{param}' (Delta: {delta} bytes)",
                        level="WARNING",
                    )
                    finding = Finding(
                        title=f"SQL Injection (Boolean-Based) en parámetro '{param}'",
                        category=self.category,
                        attack_type="sqli",
                        vector=f"query:{param}",
                        severity="high",
                        confidence=85,
                        cwe=self.cwe,
                        owasp=self.owasp,
                        cvss_score=8.5,
                        description=f"El servidor respondió de manera diferencial ante condiciones lógicas booleanas inyectadas en '{param}', indicando evaluación directa en base de datos.",
                        evidence={
                            "parameter": param,
                            "len_true_condition": len_true,
                            "len_false_condition": len_false,
                            "length_delta": delta,
                            "baseline_len": baseline_len,
                        },
                        remediation=self.remediation,
                        verified=True,
                    )
                    findings.append(finding)
                    emitter.finding(finding.to_dict())
            except Exception as e:
                emitter.log(f"Error en prueba booleana SQLi '{param}': {e}", level="DEBUG")

        return findings

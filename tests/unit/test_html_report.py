import unittest
from engine.reporting.html_report import HTMLReportGenerator


class TestHTMLReportGenerator(unittest.TestCase):
    def test_executive_report_generation(self):
        vulns = [
            {
                "id": "v-1",
                "title": "SQL Injection in User Search",
                "severity": "critical",
                "confidence": 100,
                "cwe": "CWE-89",
                "cvss_score": 9.8,
                "description": "Unsanitized user input concatenated in SQL query.",
                "evidence_json": '{"parameter": "id", "delta": "+15ms"}',
                "remediation": "Use parameterized prepared statements.",
            }
        ]
        html = HTMLReportGenerator.generate(
            title="Executive Summary Audit",
            target_name="Production Database Gateway",
            target_url="https://db.internal.corp",
            auditor_name="Senior Pentester",
            report_type="executive",
            vulnerabilities=vulns,
        )
        self.assertIn("SECMASTER Audit Report", html)
        self.assertIn("Production Database Gateway", html)
        self.assertIn("CRITICAL", html)
        self.assertIn("CWE-89", html)
        self.assertIn("GPL-3.0 Licensed Platform", html)

    def test_technical_report_includes_evidence(self):
        vulns = [
            {
                "id": "v-2",
                "title": "Reflected XSS",
                "severity": "high",
                "confidence": 95,
                "cwe": "CWE-79",
                "cvss_score": 7.5,
                "description": "Reflected token in search.",
                "evidence_json": '{"token": "xyz123", "reflected": true}',
                "remediation": "HTML entity encode output.",
            }
        ]
        html = HTMLReportGenerator.generate(
            title="Technical Audit",
            target_name="Web Portal",
            target_url="https://portal.internal.corp",
            auditor_name="SecOps Team",
            report_type="technical",
            vulnerabilities=vulns,
        )
        self.assertIn("Evidencia Técnica Reproducible", html)
        self.assertIn("xyz123", html)
        self.assertIn("HTML entity encode output", html)


if __name__ == "__main__":
    unittest.main()

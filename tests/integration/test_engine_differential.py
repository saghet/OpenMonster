"""
Integration tests for SECMASTER Differential Scanners.
Runs an ephemeral local HTTP server with controlled vulnerable and benign endpoints
to verify that vulnerabilities are discovered deterministically while false positives are suppressed.
"""

import http.server
import json
import threading
import time
import unittest
import urllib.parse
from engine.core.event import EventEmitter
from engine.scanners.ssti_scanner import SSTIScanner
from engine.scanners.xss_scanner import XSSScanner
from engine.scanners.headers_scanner import HeadersScanner
import requests


class MockVulnerableServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # 1. Benign endpoint containing the number 49 (which caused false positive in secMONSTER)
        if parsed.path == "/benign-49":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            # Contains "49" in price and CSS
            body = "<html><body><h1>Item Price: $49.00</h1><div style='width: 49px'>Test</div></body></html>"
            self.wfile.write(body.encode())
            return

        # 2. SSTI vulnerable endpoint: evaluates {{A*B}}
        if parsed.path == "/vulnerable-ssti":
            q = params.get("template", [""])[0]
            evaluated_output = q
            if "{{" in q and "}}" in q:
                inner = q.replace("{{", "").replace("}}", "")
                if "*" in inner:
                    parts = inner.split("*")
                    try:
                        p1, p2 = int(parts[0]), int(parts[1])
                        evaluated_output = str(p1 * p2)
                    except ValueError:
                        pass

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            body = f"<html><body>Template Render: {evaluated_output}</body></html>"
            self.wfile.write(body.encode())
            return

        # 3. Reflected XSS vulnerable endpoint
        if parsed.path == "/vulnerable-xss":
            q = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            # Reflects unescaped
            body = f"<html><body>Search Results for: {q}</body></html>"
            self.wfile.write(body.encode())
            return

        # Default fallback
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>SECMASTER Baseline</body></html>")

    def log_message(self, format, *args):
        pass  # Suppress HTTP server console noise during tests


class TestDifferentialEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockVulnerableServer)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.session = requests.Session()
        self.emitter = EventEmitter(scan_id="test-scan", asset_id="test-asset")

    def test_ssti_suppresses_false_positive_on_page_with_49(self):
        """Verify that a normal page containing '49' is NOT falsely reported as SSTI."""
        scanner = SSTIScanner()
        target = f"{self.base_url}/benign-49?item=1"
        baseline = self.session.get(target)

        findings = scanner.scan(target, baseline, self.session, self.emitter)
        self.assertEqual(len(findings), 0, "SSTI Scanner must not flag a page just because it contains '49'")

    def test_ssti_detects_real_vulnerability(self):
        """Verify that dynamic math expression evaluation is discovered."""
        scanner = SSTIScanner()
        target = f"{self.base_url}/vulnerable-ssti?template=hello"
        baseline = self.session.get(target)

        findings = scanner.scan(target, baseline, self.session, self.emitter)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].attack_type, "ssti")
        self.assertTrue(findings[0].verified)

    def test_xss_detects_unencoded_reflection(self):
        """Verify that unescaped parameter reflection is detected."""
        scanner = XSSScanner()
        target = f"{self.base_url}/vulnerable-xss?q=test"
        baseline = self.session.get(target)

        findings = scanner.scan(target, baseline, self.session, self.emitter)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].attack_type, "xss")
        self.assertTrue(findings[0].verified)

    def test_headers_audits_missing_security_headers(self):
        """Verify that endpoints missing CSP / X-Frame-Options are reported."""
        scanner = HeadersScanner()
        target = f"{self.base_url}/vulnerable-xss"
        baseline = self.session.get(target)

        findings = scanner.scan(target, baseline, self.session, self.emitter)
        self.assertGreaterEqual(len(findings), 2)
        titles = [f.title for f in findings]
        self.assertTrue(any("Content-Security-Policy" in t for t in titles))
        self.assertTrue(any("X-Frame-Options" in t for t in titles))


if __name__ == "__main__":
    unittest.main()

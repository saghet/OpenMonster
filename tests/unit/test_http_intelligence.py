"""
Unit tests for the SECMASTER HTTP & TLS Header Intelligence Engine.
Tests header extraction, X.509 certificate parsing, cookie security attributes,
and automated finding generation using deterministic mocks.
"""

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from engine.recon.contracts import HttpFingerprintResult, SubdomainResult
from engine.recon.http_engine import HttpIntelligenceEngine, parse_x509_cert


class TestHttpIntelligenceEngine(unittest.TestCase):

    def setUp(self):
        self.mock_emitter = MagicMock()
        self.engine = HttpIntelligenceEngine("https://example.com", emitter=self.mock_emitter)

    def test_parse_x509_cert(self):
        mock_cert = {
            "subject": ((("commonName", "example.com"),), (("organizationName", "Acme Corp"),)),
            "issuer": ((("commonName", "Let's Encrypt Authority X3"),),),
            "notAfter": "Jan 01 00:00:00 2030 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }

        subject, issuer, days_left, sans = parse_x509_cert(mock_cert)
        self.assertIn("commonName=example.com", subject)
        self.assertIn("organizationName=Acme Corp", subject)
        self.assertIn("Let's Encrypt", issuer)
        self.assertGreater(days_left, 100)
        self.assertEqual(sans, ["example.com", "www.example.com"])

    @patch.object(HttpIntelligenceEngine, "inspect_tls")
    @patch("requests.get")
    def test_inspect_endpoint_headers_and_findings(self, mock_get, mock_tls):
        mock_tls.return_value = (
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384",
            "CN=example.com",
            "CN=Let's Encrypt",
            120,
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><head><title>Super Portal</title></head><body>OK</body></html>"
        mock_resp.headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "Content-Type": "text/html; charset=UTF-8",
            "X-Frame-Options": "DENY",
        }
        mock_resp.cookies = []
        mock_get.return_value = mock_resp

        fp = self.engine.inspect_endpoint("https://example.com")
        self.assertIsNotNone(fp)
        self.assertEqual(fp.status_code, 200)
        self.assertEqual(fp.title, "Super Portal")
        self.assertEqual(fp.server_header, "Apache/2.4.41 (Ubuntu)")
        self.assertEqual(fp.tls_version, "TLSv1.3")
        self.assertEqual(fp.tls_cert_days_left, 120)
        self.assertIn("x-frame-options", fp.security_headers)

        # Check emitted findings (Missing HSTS, Missing CSP, Missing nosniff, Server version disclosure)
        emitted_findings = [call.args[0] for call in self.mock_emitter.finding.call_args_list]
        titles = [f["title"] for f in emitted_findings]
        self.assertTrue(any("Missing HTTP Strict Transport Security" in t for t in titles))
        self.assertTrue(any("Missing Content-Security-Policy" in t for t in titles))
        self.assertTrue(any("Web Server Exact Version Disclosure" in t for t in titles))

    @patch.object(HttpIntelligenceEngine, "inspect_tls")
    @patch("requests.get")
    def test_cookie_security_audit(self, mock_get, mock_tls):
        mock_tls.return_value = ("TLSv1.3", "TLS_AES_256_GCM_SHA384", None, None, None)

        mock_cookie1 = MagicMock()
        mock_cookie1.name = "session_id"
        mock_cookie1.domain = "example.com"
        mock_cookie1.path = "/"
        mock_cookie1.secure = False  # Insecure on HTTPS!
        mock_cookie1.has_nonstandard_attr.return_value = False  # Missing HttpOnly!
        mock_cookie1.get_nonstandard_attr.return_value = None

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html></html>"
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.cookies = [mock_cookie1]
        mock_get.return_value = mock_resp

        fp = self.engine.inspect_endpoint("https://example.com")
        self.assertIsNotNone(fp)
        self.assertEqual(len(fp.cookies), 1)
        self.assertFalse(fp.cookies[0]["secure"])
        self.assertFalse(fp.cookies[0]["httponly"])

        emitted_findings = [call.args[0] for call in self.mock_emitter.finding.call_args_list]
        titles = [f["title"] for f in emitted_findings]
        self.assertTrue(any("Missing 'Secure' Attribute" in t for t in titles))
        self.assertTrue(any("Missing 'HttpOnly' Flag" in t for t in titles))

    @patch.object(HttpIntelligenceEngine, "inspect_endpoint")
    def test_run_subdomain_propagation(self, mock_inspect):
        mock_fp = HttpFingerprintResult(
            target_url="https://api.example.com",
            status_code=200,
            server_header="nginx",
            title="API Gateway",
        )
        mock_inspect.return_value = mock_fp

        sub = SubdomainResult(
            subdomain="api.example.com",
            ip_addresses=["192.0.2.1"],
            source="crt.sh",
            confidence=90,
            is_live=True,
        )

        fps = self.engine.run(subdomains=[sub])
        self.assertEqual(len(fps), 2)  # base + subdomain
        self.assertEqual(sub.http_status, 200)


if __name__ == "__main__":
    unittest.main()

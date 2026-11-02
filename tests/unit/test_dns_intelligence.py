"""
Unit tests for the SECMASTER DNS Intelligence Engine.
Tests RFC record parsing, DNSSEC evaluation, reverse PTR queries,
and Subdomain Takeover heuristic risk identification using deterministic mocks.
"""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from engine.recon.contracts import DnsRecordResult, SubdomainResult
from engine.recon.dns_engine import DnsIntelligenceEngine, TAKEOVER_SIGNATURES


class TestDnsIntelligenceEngine(unittest.TestCase):

    def setUp(self):
        self.engine = DnsIntelligenceEngine("example.com")

    @patch("subprocess.run")
    def test_query_record_a_via_dig(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "example.com.\t300\tIN\tA\t93.184.216.34\n"
        mock_run.return_value = mock_proc

        records = self.engine.query_record("example.com", "A")
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r.domain, "example.com")
        self.assertEqual(r.record_type, "A")
        self.assertEqual(r.record_value, "93.184.216.34")
        self.assertEqual(r.ttl, 300)
        self.assertFalse(r.is_takeover_risk)

    @patch("subprocess.run")
    def test_query_record_mx_and_ns(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = (
            "example.com.\t3600\tIN\tMX\t10 mail.example.com.\n"
        )
        mock_run.return_value = mock_proc

        records = self.engine.query_record("example.com", "MX")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].record_type, "MX")
        self.assertIn("mail.example.com", records[0].record_value)

    @patch("subprocess.run")
    def test_query_dnssec_enabled(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = (
            ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
            "example.com.\t300\tIN\tRRSIG\tSOA 8 2 300 20261102 ...\n"
        )
        mock_run.return_value = mock_proc

        dnssec = self.engine.query_dnssec("example.com")
        self.assertEqual(dnssec.record_type, "DNSSEC")
        self.assertIn("Enabled", dnssec.record_value)

    @patch("subprocess.run")
    def test_query_dnssec_disabled(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        mock_run.return_value = mock_proc

        dnssec = self.engine.query_dnssec("example.com")
        self.assertEqual(dnssec.record_type, "DNSSEC")
        self.assertIn("Unsigned", dnssec.record_value)

    @patch("subprocess.run")
    def test_query_ptr(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "dns.google.\n"
        mock_run.return_value = mock_proc

        ptr = self.engine.query_ptr("8.8.8.8")
        self.assertIsNotNone(ptr)
        self.assertEqual(ptr.record_type, "PTR")
        self.assertEqual(ptr.record_value, "dns.google")

    def test_takeover_detection_positive(self):
        # GitHub Pages dangling CNAME
        is_risk, reason = self.engine._evaluate_takeover("CNAME", "myproject.github.io.")
        self.assertTrue(is_risk)
        self.assertIn("GitHub Pages", reason)
        self.assertIn("VALIDATION REQUIRED", reason)

        # Amazon S3 dangling CNAME
        is_risk_s3, reason_s3 = self.engine._evaluate_takeover("CNAME", "mybucket.s3.amazonaws.com")
        self.assertTrue(is_risk_s3)
        self.assertIn("Amazon S3", reason_s3)

    def test_takeover_detection_negative(self):
        # Internal safe CNAME
        is_risk, reason = self.engine._evaluate_takeover("CNAME", "internal-cdn.example.com")
        self.assertFalse(is_risk)
        self.assertIsNone(reason)

        # A record should never trigger takeover
        is_risk_a, reason_a = self.engine._evaluate_takeover("A", "93.184.216.34")
        self.assertFalse(is_risk_a)

    @patch.object(DnsIntelligenceEngine, "query_record")
    @patch.object(DnsIntelligenceEngine, "query_dnssec")
    @patch.object(DnsIntelligenceEngine, "query_ptr")
    def test_full_dns_engine_run_with_subdomains(self, mock_ptr, mock_dnssec, mock_query):
        mock_dnssec.return_value = DnsRecordResult(
            domain="example.com",
            record_type="DNSSEC",
            record_value="Enabled",
        )
        mock_ptr.return_value = DnsRecordResult(
            domain="93.184.216.34",
            record_type="PTR",
            record_value="example.com",
        )

        def mock_query_side_effect(domain, rtype):
            if domain == "example.com" and rtype == "A":
                return [
                    DnsRecordResult(
                        domain="example.com",
                        record_type="A",
                        record_value="93.184.216.34",
                        ttl=300,
                    )
                ]
            elif domain == "docs.example.com" and rtype == "CNAME":
                return [
                    DnsRecordResult(
                        domain="docs.example.com",
                        record_type="CNAME",
                        record_value="org.github.io",
                        ttl=300,
                        is_takeover_risk=True,
                        takeover_reason="[VALIDATION REQUIRED] GitHub Pages takeover risk",
                    )
                ]
            return []

        mock_query.side_effect = mock_query_side_effect

        sub = SubdomainResult(
            subdomain="docs.example.com",
            ip_addresses=[],
            source="crt.sh",
            confidence=85,
            is_live=False,
        )

        results = self.engine.run(subdomains=[sub])

        # Subdomain must have been validated as live due to active CNAME resolution
        self.assertTrue(sub.is_live)

        # Must contain DNSSEC, A, CNAME, PTR
        types = [r.record_type for r in results]
        self.assertIn("A", types)
        self.assertIn("DNSSEC", types)
        self.assertIn("CNAME", types)
        self.assertIn("PTR", types)

        cname_rec = next(r for r in results if r.record_type == "CNAME")
        self.assertTrue(cname_rec.is_takeover_risk)


if __name__ == "__main__":
    unittest.main()

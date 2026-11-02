"""
Unit tests for the SECMASTER Passive Reconnaissance Engine.
Tests CT log parsing, OSINT aggregation, domain normalization, tagging heuristics,
and provenance tracking using mocks without external network dependencies.
"""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from engine.recon.contracts import SubdomainResult
from engine.recon.passive import (
    AmassAdapter,
    CrtShSource,
    HackerTargetSource,
    PassiveReconEngine,
    SubfinderAdapter,
    normalize_domain,
    tag_subdomain,
)


class TestPassiveReconEngine(unittest.TestCase):

    def test_normalize_domain(self):
        self.assertEqual(normalize_domain("*.api.example.com"), "api.example.com")
        self.assertEqual(normalize_domain("  SUB.EXAMPLE.COM. "), "sub.example.com")
        self.assertEqual(normalize_domain("example.com"), "example.com")
        self.assertIsNone(normalize_domain(""))
        self.assertIsNone(normalize_domain("invalid domain name with spaces"))
        self.assertIsNone(normalize_domain("http://example.com"))

    def test_tag_subdomain(self):
        tags1 = tag_subdomain("staging-api.example.com")
        self.assertIn("environment:staging", tags1)
        self.assertIn("surface:api", tags1)

        tags2 = tag_subdomain("legacy-v1-backup.example.com")
        self.assertIn("risk:potentially_forgotten", tags2)

        tags3 = tag_subdomain("vpn-admin.example.com")
        self.assertIn("surface:administrative", tags3)
        self.assertIn("surface:vpn_remote_access", tags3)

    @patch("requests.get")
    def test_crtsh_source_query(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "name_value": "*.dev.example.com\nlegacy-admin.example.com",
                "common_name": "example.com",
            },
            {
                "name_value": "out-of-scope.otherdomain.com",
                "common_name": "otherdomain.com",
            },
        ]
        mock_get.return_value = mock_resp

        source = CrtShSource(timeout=5)
        results = source.query("example.com")

        subdomains = [r.subdomain for r in results]
        self.assertIn("dev.example.com", subdomains)
        self.assertIn("legacy-admin.example.com", subdomains)
        self.assertIn("example.com", subdomains)
        self.assertNotIn("out-of-scope.otherdomain.com", subdomains)

        # Check provenance and tags
        dev_result = next(r for r in results if r.subdomain == "dev.example.com")
        self.assertEqual(dev_result.source, "crt.sh")
        self.assertIn("environment:development", dev_result.tags)
        self.assertFalse(dev_result.is_live)

    @patch("requests.get")
    def test_hackertarget_source_query(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            "api.example.com,192.0.2.1\n"
            "vpn.example.com,198.51.100.2\n"
            "invalid,No DNS\n"
        )
        mock_get.return_value = mock_resp

        source = HackerTargetSource(timeout=5)
        results = source.query("example.com")

        self.assertEqual(len(results), 2)
        api_result = next(r for r in results if r.subdomain == "api.example.com")
        self.assertEqual(api_result.ip_addresses, ["192.0.2.1"])
        self.assertEqual(api_result.source, "hackertarget")
        self.assertIn("surface:api", api_result.tags)

    @patch("subprocess.run")
    def test_subfinder_adapter(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "app.example.com\nportal.example.com\n"
        mock_run.return_value = mock_proc

        with patch.object(SubfinderAdapter, "is_available", return_value=True):
            adapter = SubfinderAdapter(timeout=10)
            results = adapter.query("example.com")

            subs = [r.subdomain for r in results]
            self.assertIn("app.example.com", subs)
            self.assertIn("portal.example.com", subs)
            self.assertEqual(results[0].source, "subfinder")

    @patch.object(CrtShSource, "query")
    @patch.object(HackerTargetSource, "query")
    def test_passive_recon_engine_aggregation_and_deduplication(
        self, mock_ht_query, mock_crt_query
    ):
        mock_crt_query.return_value = [
            SubdomainResult(
                subdomain="portal.example.com",
                ip_addresses=[],
                source="crt.sh",
                confidence=85,
                tags=["surface:portal"],
            ),
            SubdomainResult(
                subdomain="dev.example.com",
                ip_addresses=[],
                source="crt.sh",
                confidence=85,
                tags=["environment:development"],
            ),
        ]
        mock_ht_query.return_value = [
            SubdomainResult(
                subdomain="portal.example.com",
                ip_addresses=["192.0.2.10"],
                source="hackertarget",
                confidence=80,
                tags=["surface:portal"],
            ),
            SubdomainResult(
                subdomain="api.example.com",
                ip_addresses=["192.0.2.20"],
                source="hackertarget",
                confidence=80,
                tags=["surface:api"],
            ),
        ]

        engine = PassiveReconEngine("example.com")
        # Ensure only mocked sources are evaluated
        engine.sources = [CrtShSource(), HackerTargetSource()]
        engine.sources[0].query = mock_crt_query
        engine.sources[1].query = mock_ht_query

        results = engine.run()

        # Should be 3 unique subdomains
        self.assertEqual(len(results), 3)

        portal = next(r for r in results if r.subdomain == "portal.example.com")
        # Provenance must combine both sources
        self.assertIn("crt.sh", portal.source)
        self.assertIn("hackertarget", portal.source)
        # IP address should be aggregated
        self.assertEqual(portal.ip_addresses, ["192.0.2.10"])
        # Confidence should be boosted due to multiple sources
        self.assertGreater(portal.confidence, 85)
        # Passive discovery does not confirm live status
        self.assertFalse(portal.is_live)


if __name__ == "__main__":
    unittest.main()

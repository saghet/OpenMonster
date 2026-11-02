import unittest
from unittest.mock import patch

from engine.recon.contracts import (
    DnsRecordResult,
    HttpFingerprintResult,
    ReconResult,
    SubdomainResult,
    TechResult,
)
from engine.recon.orchestrator import ReconOrchestrator


class TestReconContractsAndOrchestrator(unittest.TestCase):
    def test_contracts_serialization(self):
        sub = SubdomainResult(
            subdomain="api.example.com",
            ip_addresses=["93.184.216.34"],
            source="crt.sh",
            confidence=95,
            is_live=True,
            http_status=200,
        )
        d = sub.to_dict()
        self.assertEqual(d["subdomain"], "api.example.com")
        self.assertEqual(d["ip_addresses"], ["93.184.216.34"])
        self.assertTrue(d["is_live"])

        dns = DnsRecordResult(
            domain="example.com",
            record_type="MX",
            record_value="mail.example.com",
            ttl=3600,
            is_takeover_risk=False,
        )
        d_dns = dns.to_dict()
        self.assertEqual(d_dns["record_type"], "MX")
        self.assertEqual(d_dns["record_value"], "mail.example.com")

        tech = TechResult(
            target_url="https://example.com",
            name="Cloudflare",
            category="CDN",
            confidence="Confirmed",
            matched_indicators=["Server: cloudflare"],
        )
        d_tech = tech.to_dict()
        self.assertEqual(d_tech["name"], "Cloudflare")
        self.assertEqual(d_tech["confidence"], "Confirmed")

        fp = HttpFingerprintResult(
            target_url="https://example.com",
            status_code=200,
            server_header="cloudflare",
            title="Example Domain",
            tls_version="TLSv1.3",
        )
        d_fp = fp.to_dict()
        self.assertEqual(d_fp["tls_version"], "TLSv1.3")
        self.assertEqual(d_fp["status_code"], 200)

    def test_scope_validation_blocking(self):
        # Target not in allowlist
        orch = ReconOrchestrator(
            target="https://unauthorized-domain.com",
            asset_id="ast-1",
            recon_scan_id="rscan-1",
            allowed_targets=["allowed-company.com"],
        )
        res = orch.run()
        self.assertTrue(len(res.errors) > 0)
        self.assertIn("authorized whitelist", res.errors[0])

    @patch("engine.recon.dns_engine.DnsIntelligenceEngine.run")
    @patch("engine.recon.passive.PassiveReconEngine.run")
    def test_orchestrator_skeleton_execution(self, mock_passive_run, mock_dns_run):
        mock_passive_run.return_value = [
            SubdomainResult(
                subdomain="dev.example.com",
                ip_addresses=[],
                source="crt.sh",
                confidence=85,
                tags=["environment:development"],
            )
        ]
        mock_dns_run.return_value = [
            DnsRecordResult(
                domain="example.com",
                record_type="A",
                record_value="93.184.216.34",
            )
        ]
        orch = ReconOrchestrator(
            target="https://example.com",
            asset_id="ast-1",
            recon_scan_id="rscan-1",
            allowed_targets=["example.com"],
        )
        res = orch.run()
        self.assertEqual(res.target_domain, "example.com")
        self.assertEqual(len(res.errors), 0)
        self.assertEqual(len(res.subdomains), 1)
        self.assertEqual(res.subdomains[0].subdomain, "dev.example.com")
        self.assertEqual(len(res.dns_records), 1)


if __name__ == "__main__":
    unittest.main()

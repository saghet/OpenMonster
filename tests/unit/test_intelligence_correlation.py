"""
Unit tests for the SECMASTER Intelligence Correlation Engine.
Tests attack surface topological graph building, shared IP and technology clustering,
dangling takeover categorization, and historical diffing between audit sessions.
"""

import json
import unittest

from engine.recon.contracts import (
    AttackSurfaceGraph,
    CorrelatedAssetNode,
    DnsRecordResult,
    HttpFingerprintResult,
    ReconDiffResult,
    ReconResult,
    SubdomainResult,
    TechResult,
)
from engine.recon.correlation import IntelligenceCorrelationEngine


class TestIntelligenceCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.recon = ReconResult(
            target_domain="example.com",
            asset_id="asset-123",
            scan_id="scan-456",
            subdomains=[
                SubdomainResult(
                    subdomain="api.example.com",
                    ip_addresses=["192.0.2.1"],
                    source="crt.sh",
                    confidence=95,
                    is_live=True,
                    tags=["surface:api"],
                ),
                SubdomainResult(
                    subdomain="docs.example.com",
                    ip_addresses=[],
                    source="hackertarget",
                    confidence=80,
                    is_live=False,
                    tags=["surface:portal"],
                ),
            ],
            dns_records=[
                DnsRecordResult(
                    domain="example.com",
                    record_type="A",
                    record_value="192.0.2.1",
                ),
                DnsRecordResult(
                    domain="docs.example.com",
                    record_type="CNAME",
                    record_value="myorg.github.io",
                    is_takeover_risk=True,
                    takeover_reason="[VALIDATION REQUIRED] Potential dangling GitHub Pages CNAME",
                ),
            ],
            http_fingerprints=[
                HttpFingerprintResult(
                    target_url="https://example.com",
                    status_code=200,
                    server_header="nginx/1.24.0",
                    title="Enterprise Portal",
                    tls_version="TLSv1.3",
                    tls_cert_issuer="CN=Let's Encrypt",
                )
            ],
            technologies=[
                TechResult(
                    target_url="https://example.com",
                    name="Nginx",
                    category="Web Server",
                    version="1.24.0",
                    confidence="Confirmed",
                ),
                TechResult(
                    target_url="https://api.example.com",
                    name="FastAPI",
                    category="Web Framework",
                    confidence="Probable",
                ),
            ],
        )
        self.engine = IntelligenceCorrelationEngine(self.recon)

    def test_build_surface_topology_graph(self):
        graph = self.engine.build_surface_topology()

        self.assertEqual(graph.root_domain, "example.com")
        self.assertEqual(len(graph.nodes), 3)  # root, api, docs

        # Shared IP Clustering (example.com and api.example.com both resolve to 192.0.2.1)
        self.assertIn("192.0.2.1", graph.ip_clusters)
        shared_hosts = graph.ip_clusters["192.0.2.1"]
        self.assertIn("example.com", shared_hosts)
        self.assertIn("api.example.com", shared_hosts)

        # Technology Clustering
        self.assertIn("Nginx", graph.technology_clusters)
        self.assertIn("example.com", graph.technology_clusters["Nginx"])
        self.assertIn("FastAPI", graph.technology_clusters)
        self.assertIn("api.example.com", graph.technology_clusters["FastAPI"])

        # Takeover candidate identification
        self.assertEqual(len(graph.takeover_candidates), 1)
        candidate = graph.takeover_candidates[0]
        self.assertEqual(candidate["domain"], "docs.example.com")
        self.assertEqual(candidate["cname_pointer"], "myorg.github.io")

        # Unresolved subdomain identification
        self.assertNotIn("docs.example.com", graph.unresolved_subdomains)  # Has CNAME

    def test_compare_with_previous_historical_diff(self):
        previous_session = {
            "subdomains": [
                {
                    "subdomain": "example.com",
                    "ip_addresses": ["198.51.100.1"],  # Old IP
                },
                {
                    "subdomain": "legacy-old.example.com",  # Decommissioned subdomain
                    "ip_addresses": ["198.51.100.5"],
                },
            ],
            "technologies": [
                {
                    "target_url": "https://example.com",
                    "name": "Apache",  # Old technology replaced by Nginx
                    "version": "2.4.41",
                }
            ],
        }

        diff = self.engine.compare_with_previous(previous_session)

        # Newly exposed subdomains in current scan
        self.assertIn("api.example.com", diff.new_subdomains)
        self.assertIn("docs.example.com", diff.new_subdomains)

        # Removed/decommissioned subdomains
        self.assertIn("legacy-old.example.com", diff.removed_subdomains)

        # Changed IP for example.com
        self.assertIn("example.com", diff.changed_ips)
        self.assertEqual(diff.changed_ips["example.com"]["before"], ["198.51.100.1"])
        self.assertEqual(diff.changed_ips["example.com"]["after"], ["192.0.2.1"])

        # Technology drift (Nginx added, Apache removed)
        added_techs = [t["technology"] for t in diff.new_technologies]
        removed_techs = [t["technology"] for t in diff.removed_technologies]
        self.assertIn("Nginx", added_techs)
        self.assertIn("Apache", removed_techs)

    def test_export_summary(self):
        json_output = self.engine.export_summary(format_type="json")
        parsed = json.loads(json_output)
        self.assertEqual(parsed["root_domain"], "example.com")
        self.assertEqual(len(parsed["nodes"]), 3)

        md_output = self.engine.export_summary(format_type="markdown")
        self.assertIn("# Attack Surface Intelligence: example.com", md_output)
        self.assertIn("192.0.2.1", md_output)


if __name__ == "__main__":
    unittest.main()

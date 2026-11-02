"""
SECMASTER Intelligence Correlation Engine.
Constructs verified topological asset graphs, maps multi-domain IP/Hosting clusters,
aggregates technology stacks, and calculates historical diffs without conjectural leaps.
"""

from collections import defaultdict
import json
import logging
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from engine.recon.contracts import (
    AttackSurfaceGraph,
    CorrelatedAssetNode,
    ReconDiffResult,
    ReconResult,
)

logger = logging.getLogger("sec_master.recon.correlation")


class IntelligenceCorrelationEngine:
    """
    Correlates disparate OSINT, DNS, TLS, and HTTP intelligence into a unified attack surface model.
    Enforces evidence-based linkage (never links nodes without cryptographic, DNS, or network proof).
    """

    def __init__(self, recon_result: ReconResult, emitter: Optional[Any] = None):
        self.result = recon_result
        self.emitter = emitter

    def _emit_log(self, message: str, level: str = "INFO"):
        if not self.emitter:
            return
        if hasattr(self.emitter, "log"):
            self.emitter.log(message, level=level)
        elif hasattr(self.emitter, "emit"):
            self.emitter.emit("log", {"message": message, "level": level})

    def build_surface_topology(self) -> AttackSurfaceGraph:
        """
        Builds a correlated topological graph of the entire discovered surface:
        - Root Domain -> Subdomains -> Resolved IPs -> Technologies -> Risk Flags
        - Clustered by shared IP addresses and common technology stacks.
        """
        root_domain = self.result.target_domain
        nodes_dict: Dict[str, CorrelatedAssetNode] = {}

        # 1. Initialize root node
        nodes_dict[root_domain] = CorrelatedAssetNode(
            domain=root_domain,
            is_root=True,
        )

        # 2. Add nodes for each discovered subdomain
        for sub in self.result.subdomains:
            norm_sub = sub.subdomain.lower().rstrip(".")
            if norm_sub not in nodes_dict:
                nodes_dict[norm_sub] = CorrelatedAssetNode(
                    domain=norm_sub,
                    is_root=(norm_sub == root_domain),
                    ips=list(sub.ip_addresses),
                    tags=list(sub.tags),
                )
            else:
                # Merge tags and IPs
                node = nodes_dict[norm_sub]
                node.ips = sorted(list(set(node.ips).union(sub.ip_addresses)))
                node.tags = sorted(list(set(node.tags).union(sub.tags)))

        # 3. Correlate DNS Records
        for dns in self.result.dns_records:
            dom = dns.domain.lower().rstrip(".")
            if dom not in nodes_dict:
                nodes_dict[dom] = CorrelatedAssetNode(
                    domain=dom,
                    is_root=(dom == root_domain),
                )
            node = nodes_dict[dom]
            node.dns_records.append({
                "type": dns.record_type,
                "value": dns.record_value,
                "ttl": dns.ttl,
            })
            if dns.record_type in ("A", "AAAA"):
                if dns.record_value not in node.ips:
                    node.ips.append(dns.record_value)
            if dns.is_takeover_risk and dns.takeover_reason:
                node.takeover_risks.append(dns.takeover_reason)

        # 4. Correlate HTTP Fingerprints & TLS Metadata
        for fp in self.result.http_fingerprints:
            parsed = urlparse(fp.target_url)
            host = (parsed.hostname or fp.target_url).lower().rstrip(".")
            if host in nodes_dict:
                node = nodes_dict[host]
                node.http_status = fp.status_code
                node.title = fp.title
                node.server_header = fp.server_header
                if fp.tls_version or fp.tls_cert_issuer:
                    node.tls_info = {
                        "version": fp.tls_version,
                        "cipher": fp.tls_cipher,
                        "subject": fp.tls_cert_subject,
                        "issuer": fp.tls_cert_issuer,
                        "days_left": fp.tls_cert_days_left,
                    }

        # 5. Correlate Technologies
        for tech in self.result.technologies:
            parsed = urlparse(tech.target_url)
            host = (parsed.hostname or tech.target_url).lower().rstrip(".")
            if host in nodes_dict:
                node = nodes_dict[host]
                tech_entry = {
                    "name": tech.name,
                    "category": tech.category,
                    "version": tech.version,
                    "confidence": tech.confidence,
                }
                if tech_entry not in node.technologies:
                    node.technologies.append(tech_entry)

        # 6. Build Clusters and Categorize Risks
        ip_clusters = defaultdict(list)
        tech_clusters = defaultdict(list)
        takeover_candidates = []
        unresolved_subdomains = []

        for dom, node in sorted(nodes_dict.items()):
            # IP Clustering
            for ip in node.ips:
                if dom not in ip_clusters[ip]:
                    ip_clusters[ip].append(dom)

            # Technology Clustering
            for t in node.technologies:
                t_name = t["name"]
                if dom not in tech_clusters[t_name]:
                    tech_clusters[t_name].append(dom)

            # Takeover candidates
            if node.takeover_risks:
                takeover_candidates.append({
                    "domain": dom,
                    "reasons": node.takeover_risks,
                    "cname_pointer": next(
                        (r["value"] for r in node.dns_records if r["type"] == "CNAME"), None
                    ),
                })

            # Check if subdomain remains unresolved (no IPs and no CNAME)
            if not node.is_root and not node.ips and not any(r["type"] == "CNAME" for r in node.dns_records):
                unresolved_subdomains.append(dom)

        graph = AttackSurfaceGraph(
            root_domain=root_domain,
            nodes=list(nodes_dict.values()),
            ip_clusters=dict(ip_clusters),
            technology_clusters=dict(tech_clusters),
            takeover_candidates=takeover_candidates,
            unresolved_subdomains=unresolved_subdomains,
        )

        self._emit_log(
            f"Correlación completada: {len(graph.nodes)} nodos topológicos, "
            f"{len(graph.ip_clusters)} clusters de IP y {len(graph.technology_clusters)} stacks tecnológicos.",
            level="INFO",
        )

        return graph

    def compare_with_previous(
        self, previous_recon_dict: Dict[str, Any]
    ) -> ReconDiffResult:
        """
        Performs rigorous differential audit against a previous reconnaissance session:
        - Identifies newly exposed or decommissioned subdomains.
        - Identifies DNS IP infrastructure alterations.
        - Identifies technology stack modifications.
        """
        diff = ReconDiffResult()

        topology = self.build_surface_topology()
        curr_domains_dict: Dict[str, CorrelatedAssetNode] = {
            n.domain: n for n in topology.nodes
        }

        prev_domains_dict: Dict[str, Dict[str, Any]] = {}
        for s in previous_recon_dict.get("subdomains", []):
            sub_name = s.get("subdomain", "").lower().rstrip(".")
            if sub_name:
                prev_domains_dict[sub_name] = s

        prev_names = set(prev_domains_dict.keys())
        curr_names = set(curr_domains_dict.keys())

        # Subdomain differences
        diff.new_subdomains = sorted(list(curr_names - prev_names))
        diff.removed_subdomains = sorted(list(prev_names - curr_names))

        # IP address migration detection for persistent domains/subdomains
        common_names = curr_names.intersection(prev_names)
        for name in common_names:
            prev_ips = sorted(prev_domains_dict[name].get("ip_addresses", []))
            curr_ips = sorted(curr_domains_dict[name].ips)
            if prev_ips != curr_ips:
                diff.changed_ips[name] = {
                    "before": prev_ips,
                    "after": curr_ips,
                }

        # Technology stack drift detection
        prev_techs = {
            (t.get("target_url", ""), t.get("name", "")): t.get("version")
            for t in previous_recon_dict.get("technologies", [])
        }
        curr_techs = {
            (t.target_url, t.name): t.version for t in self.result.technologies
        }

        for (url, name), ver in curr_techs.items():
            if (url, name) not in prev_techs:
                diff.new_technologies.append({
                    "target_url": url,
                    "technology": name,
                    "version": ver or "Unknown",
                })

        for (url, name), ver in prev_techs.items():
            if (url, name) not in curr_techs:
                diff.removed_technologies.append({
                    "target_url": url,
                    "technology": name,
                    "version": ver or "Unknown",
                })

        return diff

    def export_summary(self, format_type: str = "json") -> str:
        """Serializes correlated graph for desktop rendering or file export."""
        topology = self.build_surface_topology()
        if format_type.lower() == "json":
            return json.dumps(topology.to_dict(), indent=2)

        # Markdown format export
        lines = [
            f"# Attack Surface Intelligence: {topology.root_domain}",
            f"- **Total Nodes:** {len(topology.nodes)}",
            f"- **IP Clusters:** {len(topology.ip_clusters)}",
            f"- **Technology Stacks:** {len(topology.technology_clusters)}",
            f"- **Takeover Candidates:** {len(topology.takeover_candidates)}",
            "",
            "## Discovered Nodes",
        ]
        for n in topology.nodes:
            lines.append(f"### {n.domain} {'(ROOT)' if n.is_root else ''}")
            if n.ips:
                lines.append(f"- **IPs:** {', '.join(n.ips)}")
            if n.technologies:
                tech_names = [f"{t['name']} ({t.get('version') or 'N/A'})" for t in n.technologies]
                lines.append(f"- **Technologies:** {', '.join(tech_names)}")
            if n.takeover_risks:
                lines.append(f"- **Takeover Risks:** {'; '.join(n.takeover_risks)}")
            lines.append("")

        return "\n".join(lines)

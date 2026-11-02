"""
SECMASTER DNS Intelligence Engine.
Performs RFC-compliant multi-record DNS resolution (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, DNSSEC),
identifies nameservers, detects misconfigurations, and flags potential subdomain takeovers for validation.
Uses native Linux dig utility with Python socket fallback. Never claims or interacts destructively with third parties.
"""

import logging
import os
import re
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.recon.contracts import DnsRecordResult, SubdomainResult

logger = logging.getLogger("sec_master.recon.dns")

# Known third-party cloud/hosting providers susceptible to dangling CNAME subdomain takeover
TAKEOVER_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "GitHub Pages": {
        "cname": ["github.io"],
        "nxdomain_risk": True,
    },
    "Amazon S3 / AWS": {
        "cname": ["s3.amazonaws.com", "s3-website", "s3.dualstack", "amazonaws.com"],
        "nxdomain_risk": True,
    },
    "Heroku": {
        "cname": ["herokuapp.com", "herokudns.com"],
        "nxdomain_risk": True,
    },
    "CloudFront CDN": {
        "cname": ["cloudfront.net"],
        "nxdomain_risk": True,
    },
    "Microsoft Azure": {
        "cname": [
            "azurewebsites.net",
            "cloudapp.net",
            "trafficmanager.net",
            "blob.core.windows.net",
        ],
        "nxdomain_risk": True,
    },
    "WordPress": {
        "cname": ["wordpress.com"],
        "nxdomain_risk": True,
    },
    "Shopify": {
        "cname": ["myshopify.com"],
        "nxdomain_risk": True,
    },
    "Bitbucket": {
        "cname": ["bitbucket.io"],
        "nxdomain_risk": True,
    },
    "Zendesk": {
        "cname": ["zendesk.com"],
        "nxdomain_risk": True,
    },
    "Fastly": {
        "cname": ["fastly.net"],
        "nxdomain_risk": True,
    },
    "Ghost": {
        "cname": ["ghost.io"],
        "nxdomain_risk": True,
    },
    "Surge": {
        "cname": ["surge.sh"],
        "nxdomain_risk": True,
    },
    "ReadTheDocs": {
        "cname": ["readthedocs.io"],
        "nxdomain_risk": True,
    },
}

SUPPORTED_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


class DnsIntelligenceEngine:
    """
    Modular DNS Intelligence Engine.
    Resolves records, checks DNSSEC, queries reverse PTR, and identifies takeover vectors.
    """

    def __init__(
        self,
        target_domain: str,
        emitter: Optional[Any] = None,
        timeout: int = 5,
        nameserver: Optional[str] = None,
    ):
        self.target_domain = target_domain.strip().lower()
        self.emitter = emitter
        self.timeout = timeout
        self.nameserver = nameserver
        self.dig_available = shutil.which("dig") is not None

    def _emit_log(self, message: str, level: str = "INFO"):
        if not self.emitter:
            return
        if hasattr(self.emitter, "log"):
            self.emitter.log(message, level=level)
        elif hasattr(self.emitter, "emit"):
            self.emitter.emit("log", {"message": message, "level": level})

    def _clean_domain(self, domain: str) -> str:
        return domain.strip().rstrip(".")

    def query_record(self, domain: str, record_type: str) -> List[DnsRecordResult]:
        """Resolves specified record type for a domain using dig or socket."""
        records: List[DnsRecordResult] = []
        clean_target = self._clean_domain(domain)

        if self.dig_available:
            cmd = ["dig", "+noall", "+answer", "+comments", record_type, clean_target, f"+time={self.timeout}"]
            if self.nameserver:
                cmd.append(f"@{self.nameserver}")

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 2,
                    check=False,
                )
                if proc.returncode == 0:
                    lines = proc.stdout.splitlines()
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith(";"):
                            continue
                        # Standard dig answer format: domain ttl class type rdata...
                        parts = line.split(None, 4)
                        if len(parts) >= 5:
                            rec_domain = self._clean_domain(parts[0])
                            try:
                                ttl = int(parts[1])
                            except ValueError:
                                ttl = None
                            rec_class = parts[2].upper()
                            rec_type = parts[3].upper()
                            rec_val = parts[4].strip().strip('"')

                            if rec_type == record_type.upper() and rec_class == "IN":
                                is_risk, risk_reason = self._evaluate_takeover(
                                    rec_type, rec_val
                                )
                                records.append(
                                    DnsRecordResult(
                                        domain=rec_domain,
                                        record_type=rec_type,
                                        record_value=self._clean_domain(rec_val) if rec_type in ("CNAME", "NS") else rec_val,
                                        ttl=ttl,
                                        is_takeover_risk=is_risk,
                                        takeover_reason=risk_reason,
                                    )
                                )
            except Exception as e:
                logger.warning(f"Error querying {record_type} for {domain} via dig: {e}")

        # Fallback to Python socket for A / AAAA if dig not available or returned nothing
        if not records and record_type in ("A", "AAAA"):
            try:
                family = socket.AF_INET if record_type == "A" else socket.AF_INET6
                addr_info = socket.getaddrinfo(clean_target, None, family)
                seen_ips = set()
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        records.append(
                            DnsRecordResult(
                                domain=clean_target,
                                record_type=record_type,
                                record_value=ip,
                                ttl=300,
                                is_takeover_risk=False,
                                takeover_reason=None,
                            )
                        )
            except (socket.gaierror, socket.timeout):
                pass
            except Exception as e:
                logger.debug(f"Socket resolution failed for {domain} ({record_type}): {e}")

        return records

    def query_dnssec(self, domain: str) -> DnsRecordResult:
        """Queries DNSSEC status (ad flag in header and RRSIG presence)."""
        clean_target = self._clean_domain(domain)
        if not self.dig_available:
            return DnsRecordResult(
                domain=clean_target,
                record_type="DNSSEC",
                record_value="Unknown (dig not available)",
                ttl=None,
            )

        cmd = ["dig", "+dnssec", "+comments", "SOA", clean_target, f"+time={self.timeout}"]
        if self.nameserver:
            cmd.append(f"@{self.nameserver}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 2,
                check=False,
            )
            out = proc.stdout
            has_ad_flag = "flags:" in out and " ad;" in out or " ad " in out
            has_rrsig = "RRSIG" in out

            if has_ad_flag or has_rrsig:
                status = "Enabled (DNSSEC Validated & RRSIG Present)"
            else:
                status = "Unsigned / Inactive (No DNSSEC validation detected)"

            return DnsRecordResult(
                domain=clean_target,
                record_type="DNSSEC",
                record_value=status,
                ttl=None,
                is_takeover_risk=False,
            )
        except Exception as e:
            return DnsRecordResult(
                domain=clean_target,
                record_type="DNSSEC",
                record_value=f"Error checking DNSSEC: {e}",
                ttl=None,
            )

    def query_ptr(self, ip_address: str) -> Optional[DnsRecordResult]:
        """Performs reverse DNS PTR lookup on an IP address."""
        clean_ip = ip_address.strip()
        if not clean_ip:
            return None

        # 1. Try dig -x
        if self.dig_available:
            cmd = ["dig", "-x", clean_ip, "+short", f"+time={self.timeout}"]
            if self.nameserver:
                cmd.append(f"@{self.nameserver}")
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 2,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    ptr_name = self._clean_domain(proc.stdout.splitlines()[0])
                    return DnsRecordResult(
                        domain=clean_ip,
                        record_type="PTR",
                        record_value=ptr_name,
                        ttl=None,
                    )
            except Exception:
                pass

        # 2. Try socket fallback
        try:
            hostname, _, _ = socket.gethostbyaddr(clean_ip)
            if hostname:
                return DnsRecordResult(
                    domain=clean_ip,
                    record_type="PTR",
                    record_value=self._clean_domain(hostname),
                    ttl=None,
                )
        except Exception:
            pass

        return None

    def _evaluate_takeover(
        self, record_type: str, record_value: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Analyzes CNAME records against dangling cloud service signatures.
        Classifies exclusively as a finding requiring manual validation.
        Never attempts to claim or register any external resource.
        """
        if record_type != "CNAME":
            return False, None

        val_lower = record_value.lower().rstrip(".")
        for provider, config in TAKEOVER_SIGNATURES.items():
            for cname_pattern in config["cname"]:
                if val_lower.endswith(cname_pattern):
                    # Flag as high-priority audit candidate requiring human verification
                    reason = (
                        f"[VALIDATION REQUIRED] Dangling CNAME pointer '{val_lower}' "
                        f"matches {provider} signature. Subdomain takeover risk if the service "
                        f"resource has been decommissioned or is unclaimed."
                    )
                    return True, reason

        return False, None

    def run(
        self, subdomains: Optional[List[SubdomainResult]] = None
    ) -> List[DnsRecordResult]:
        """
        Executes full DNS intelligence suite:
        1. Resolves all supported records for the target domain.
        2. Inspects DNSSEC security status.
        3. Resolves and marks live status for subdomains discovered pasively.
        4. Gathers reverse PTR records for all discovered IP addresses.
        5. Identifies potential subdomain takeover risks.
        """
        all_records: List[DnsRecordResult] = []
        unique_ips: Set[str] = set()

        self._emit_log(
            f"Iniciando DNS Intelligence sobre '{self.target_domain}' (Dig {'disponible' if self.dig_available else 'no disponible, usando fallback'})...",
            level="INFO",
        )

        # 1. Core Record Resolution for target domain
        for rtype in SUPPORTED_RECORD_TYPES:
            recs = self.query_record(self.target_domain, rtype)
            for r in recs:
                all_records.append(r)
                if r.record_type in ("A", "AAAA"):
                    unique_ips.add(r.record_value)

        # 2. DNSSEC Validation
        dnssec_rec = self.query_dnssec(self.target_domain)
        all_records.append(dnssec_rec)

        # 3. Batch Resolution for Discovered Subdomains (Active Verification)
        if subdomains:
            self._emit_log(
                f"Resolviendo activamente {len(subdomains)} subdominios para verificar estado activo e IPs...",
                level="INFO",
            )
            for sub in subdomains:
                sub_domain = sub.subdomain
                # Query A and CNAME for each subdomain
                a_recs = self.query_record(sub_domain, "A")
                cname_recs = self.query_record(sub_domain, "CNAME")

                resolved_ips = []
                for ar in a_recs:
                    all_records.append(ar)
                    resolved_ips.append(ar.record_value)
                    unique_ips.add(ar.record_value)

                for cr in cname_recs:
                    all_records.append(cr)

                if resolved_ips:
                    sub.is_live = True
                    # Merge unique IPs
                    current_ips = set(sub.ip_addresses)
                    current_ips.update(resolved_ips)
                    sub.ip_addresses = sorted(list(current_ips))
                elif cname_recs:
                    # Has CNAME record
                    sub.is_live = True

        # 4. Reverse PTR Lookups on all unique IPs
        if unique_ips:
            self._emit_log(
                f"Realizando resoluciones PTR inversas sobre {len(unique_ips)} IPs descubiertas...",
                level="DEBUG",
            )
            for ip in sorted(unique_ips):
                ptr_rec = self.query_ptr(ip)
                if ptr_rec:
                    all_records.append(ptr_rec)

        takeover_count = sum(1 for r in all_records if r.is_takeover_risk)
        self._emit_log(
            f"DNS Intelligence completado: {len(all_records)} registros DNS obtenidos. "
            f"Riesgos de takeover preliminares detectados: {takeover_count}.",
            level="INFO",
        )

        return all_records

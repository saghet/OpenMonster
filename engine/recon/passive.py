"""
SECMASTER Passive Reconnaissance Engine.
Performs non-intrusive surface discovery using Certificate Transparency (crt.sh),
public OSINT sources (HackerTarget), and tool adapters (Subfinder, Amass).
Maintains strict provenance tracking, deduplication, and tags potentially forgotten assets.
"""

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Set
import requests

from engine.recon.contracts import SubdomainResult

logger = logging.getLogger("sec_master.recon.passive")

# Valid domain name regex (RFC 1123 compliant label structure)
_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Heuristic tags for potentially forgotten, legacy, or high-interest environments
_ENVIRONMENT_TAGS = {
    "dev": "environment:development",
    "devel": "environment:development",
    "development": "environment:development",
    "stage": "environment:staging",
    "staging": "environment:staging",
    "test": "environment:testing",
    "testing": "environment:testing",
    "qa": "environment:qa",
    "uat": "environment:uat",
    "demo": "environment:demo",
    "sandbox": "environment:sandbox",
    "beta": "environment:beta",
    "legacy": "risk:potentially_forgotten",
    "old": "risk:potentially_forgotten",
    "v1": "risk:potentially_forgotten",
    "backup": "risk:potentially_forgotten",
    "bak": "risk:potentially_forgotten",
    "temp": "risk:potentially_forgotten",
    "admin": "surface:administrative",
    "internal": "surface:internal",
    "corp": "surface:internal",
    "vpn": "surface:vpn_remote_access",
    "portal": "surface:portal",
    "api": "surface:api",
}


def normalize_domain(name: str) -> Optional[str]:
    """Cleans wildcards, whitespaces, and returns normalized lowercase domain or None."""
    if not name:
        return None
    cleaned = name.strip().lower()
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    cleaned = cleaned.rstrip(".")
    if _DOMAIN_REGEX.match(cleaned):
        return cleaned
    return None


def tag_subdomain(subdomain: str) -> List[str]:
    """Analyzes subdomain parts to detect environment, legacy risk, or sensitive surfaces."""
    tags = set()
    parts = subdomain.lower().split(".")
    sub_parts = []
    for p in parts[:-2]:  # Check labels before domain.tld
        sub_parts.extend(re.split(r"[-_]", p))

    for part in sub_parts:
        if part in _ENVIRONMENT_TAGS:
            tags.add(_ENVIRONMENT_TAGS[part])

    return sorted(list(tags))


class BasePassiveSource:
    """Interface for passive reconnaissance sources."""

    def __init__(self, name: str, timeout: int = 10):
        self.name = name
        self.timeout = timeout

    def query(self, domain: str) -> List[SubdomainResult]:
        raise NotImplementedError


class CrtShSource(BasePassiveSource):
    """Certificate Transparency (CT) log aggregator via crt.sh JSON endpoint."""

    def __init__(self, timeout: int = 15):
        super().__init__("crt.sh", timeout=timeout)

    def query(self, domain: str) -> List[SubdomainResult]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {
            "User-Agent": "SECMASTER-OpenMonster-OSINT/1.0 (+https://github.com/saghet/OpenMonster)",
            "Accept": "application/json",
        }
        results = []
        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code != 200:
                logger.warning(f"crt.sh returned HTTP {resp.status_code} for {domain}")
                return []

            data = resp.json()
            if not isinstance(data, list):
                return []

            seen: Set[str] = set()
            for entry in data:
                # name_value can contain multiple domains separated by newline
                names = entry.get("name_value", "").split("\n")
                common_name = entry.get("common_name", "")
                if common_name:
                    names.append(common_name)

                for raw_name in names:
                    norm = normalize_domain(raw_name)
                    if not norm:
                        continue
                    # Must belong to target domain hierarchy
                    if norm == domain or norm.endswith("." + domain):
                        if norm not in seen:
                            seen.add(norm)
                            tags = tag_subdomain(norm)
                            results.append(
                                SubdomainResult(
                                    subdomain=norm,
                                    ip_addresses=[],
                                    source="crt.sh",
                                    confidence=85,
                                    is_live=False,
                                    tags=tags,
                                )
                            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error querying crt.sh for {domain}: {e}")
        except Exception as e:
            logger.warning(f"Unexpected parsing error from crt.sh for {domain}: {e}")

        return results


class HackerTargetSource(BasePassiveSource):
    """Public host search aggregator via HackerTarget."""

    def __init__(self, timeout: int = 10):
        super().__init__("hackertarget", timeout=timeout)

    def query(self, domain: str) -> List[SubdomainResult]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        headers = {
            "User-Agent": "SECMASTER-OpenMonster-OSINT/1.0",
        }
        results = []
        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code != 200:
                return []

            content = resp.text.strip()
            if not content or "error" in content.lower() or "no dns record" in content.lower():
                return []

            for line in content.splitlines():
                line = line.strip()
                if not line or "," not in line:
                    continue
                parts = line.split(",", 1)
                host_str = parts[0].strip()
                ip_str = parts[1].strip()

                norm = normalize_domain(host_str)
                if not norm:
                    continue
                if norm == domain or norm.endswith("." + domain):
                    ips = [ip_str] if ip_str and not ip_str.startswith("No") else []
                    tags = tag_subdomain(norm)
                    results.append(
                        SubdomainResult(
                            subdomain=norm,
                            ip_addresses=ips,
                            source="hackertarget",
                            confidence=80,
                            is_live=False,
                            tags=tags,
                        )
                    )
        except Exception as e:
            logger.warning(f"HackerTarget query failed for {domain}: {e}")

        return results


class SubfinderAdapter(BasePassiveSource):
    """Tool adapter that runs ProjectDiscovery Subfinder if present in PATH."""

    def __init__(self, timeout: int = 30):
        super().__init__("subfinder", timeout=timeout)

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("subfinder") is not None

    def query(self, domain: str) -> List[SubdomainResult]:
        if not self.is_available():
            return []

        results = []
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    norm = normalize_domain(line.strip())
                    if norm and (norm == domain or norm.endswith("." + domain)):
                        results.append(
                            SubdomainResult(
                                subdomain=norm,
                                ip_addresses=[],
                                source="subfinder",
                                confidence=90,
                                is_live=False,
                                tags=tag_subdomain(norm),
                            )
                        )
        except Exception as e:
            logger.warning(f"Subfinder execution error: {e}")

        return results


class AmassAdapter(BasePassiveSource):
    """Tool adapter for OWASP Amass in passive mode if present in PATH."""

    def __init__(self, timeout: int = 30):
        super().__init__("amass", timeout=timeout)

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("amass") is not None

    def query(self, domain: str) -> List[SubdomainResult]:
        if not self.is_available():
            return []

        results = []
        cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    norm = normalize_domain(line.strip())
                    if norm and (norm == domain or norm.endswith("." + domain)):
                        results.append(
                            SubdomainResult(
                                subdomain=norm,
                                ip_addresses=[],
                                source="amass",
                                confidence=90,
                                is_live=False,
                                tags=tag_subdomain(norm),
                            )
                        )
        except Exception as e:
            logger.warning(f"Amass execution error: {e}")

        return results


class PassiveReconEngine:
    """
    Coordinates multi-source passive surface discovery.
    Deduplicates results while strictly recording provenance and calculating multi-factor confidence.
    """

    def __init__(self, target_domain: str, emitter: Optional[Any] = None):
        self.target_domain = target_domain.strip().lower()
        self.emitter = emitter
        self.sources: List[BasePassiveSource] = [
            CrtShSource(),
            HackerTargetSource(),
        ]
        # Dynamically attach tool adapters if available in system
        if SubfinderAdapter.is_available():
            self.sources.append(SubfinderAdapter())
        if AmassAdapter.is_available():
            self.sources.append(AmassAdapter())

    def _emit_log(self, message: str, level: str = "INFO"):
        if not self.emitter:
            return
        if hasattr(self.emitter, "log"):
            self.emitter.log(message, level=level)
        elif hasattr(self.emitter, "emit"):
            self.emitter.emit("log", {"message": message, "level": level})

    def run(self) -> List[SubdomainResult]:
        """Executes all passive sources, deduplicates, and aggregates intelligence."""
        if not self.target_domain:
            return []

        self._emit_log(
            f"Iniciando Passive Recon sobre '{self.target_domain}' utilizando {len(self.sources)} fuentes pasivas.",
            level="INFO",
        )

        aggregated: Dict[str, Dict[str, Any]] = {}

        for source in self.sources:
            try:
                self._emit_log(f"Consultando fuente pasiva: {source.name}...", level="DEBUG")

                items = source.query(self.target_domain)

                for item in items:
                    sub = item.subdomain
                    if sub not in aggregated:
                        aggregated[sub] = {
                            "subdomain": sub,
                            "ip_addresses": set(item.ip_addresses),
                            "sources": {item.source},
                            "base_confidence": item.confidence,
                            "tags": set(item.tags),
                        }
                    else:
                        aggregated[sub]["sources"].add(item.source)
                        aggregated[sub]["ip_addresses"].update(item.ip_addresses)
                        aggregated[sub]["tags"].update(item.tags)
                        # Confidence boost when confirmed by multiple independent OSINT sources
                        aggregated[sub]["base_confidence"] = min(
                            99, aggregated[sub]["base_confidence"] + 10
                        )

            except Exception as e:
                logger.error(f"Error querying source {source.name}: {e}")
                self._emit_log(f"Fallo en fuente {source.name}: {e}", level="WARNING")

        # Build finalized SubdomainResult list
        final_results: List[SubdomainResult] = []
        for sub, data in sorted(aggregated.items()):
            provenance = ", ".join(sorted(data["sources"]))
            result = SubdomainResult(
                subdomain=sub,
                ip_addresses=sorted(list(data["ip_addresses"])),
                source=provenance,
                confidence=data["base_confidence"],
                is_live=False,  # Passive recon only; live verification is done by DNS & HTTP engines
                tags=sorted(list(data["tags"])),
            )
            final_results.append(result)

        self._emit_log(
            f"Passive Recon finalizado: {len(final_results)} subdominios descubiertos con trazabilidad de origen.",
            level="INFO",
        )

        return final_results

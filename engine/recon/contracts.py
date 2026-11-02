"""
Data Contracts and Schema Definitions for Reconnaissance & Intelligence Engine.
Ensures strict type-safety, structured evidence, and verified source traceability.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SubdomainResult:
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    source: str = "crt.sh"
    confidence: int = 80
    is_live: bool = False
    http_status: Optional[int] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DnsRecordResult:
    domain: str
    record_type: str  # A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, DNSSEC
    record_value: str
    ttl: Optional[int] = None
    is_takeover_risk: bool = False
    takeover_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TechResult:
    target_url: str
    name: str
    category: str  # Web Server, Framework, CMS, CDN, WAF, Language, Analytics, JavaScript Library
    version: Optional[str] = None
    confidence: str = "Confirmed"  # Confirmed, Probable, Suspected
    matched_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HttpFingerprintResult:
    target_url: str
    status_code: int
    server_header: Optional[str] = None
    title: Optional[str] = None
    content_type: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_cert_subject: Optional[str] = None
    tls_cert_issuer: Optional[str] = None
    tls_cert_days_left: Optional[int] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReconResult:
    target_domain: str
    asset_id: str
    scan_id: str
    subdomains: List[SubdomainResult] = field(default_factory=list)
    dns_records: List[DnsRecordResult] = field(default_factory=list)
    technologies: List[TechResult] = field(default_factory=list)
    http_fingerprints: List[HttpFingerprintResult] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "asset_id": self.asset_id,
            "scan_id": self.scan_id,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "dns_records": [d.to_dict() for d in self.dns_records],
            "technologies": [t.to_dict() for t in self.technologies],
            "http_fingerprints": [f.to_dict() for f in self.http_fingerprints],
            "execution_time_seconds": self.execution_time_seconds,
            "errors": self.errors,
        }

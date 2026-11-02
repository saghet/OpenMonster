"""
Base Module Definition for SECMASTER Security Scanners.
Enforces structured metadata, references, CWE/OWASP mapping, and remediation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import requests
from engine.core.event import EventEmitter


@dataclass
class Finding:
    title: str
    category: str
    attack_type: str
    vector: str
    severity: str  # critical, high, medium, low, info
    confidence: int  # 0 to 100
    cve: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "attack_type": self.attack_type,
            "vector": self.vector,
            "severity": self.severity,
            "confidence": self.confidence,
            "cve": self.cve,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "verified": self.verified,
        }


class SecurityModule(ABC):
    def __init__(
        self,
        module_id: str,
        name: str,
        description: str,
        version: str,
        category: str,
        risk_level: str,
        cwe: str,
        owasp: str,
        remediation: str,
        references: List[str],
    ):
        self.module_id = module_id
        self.name = name
        self.description = description
        self.version = version
        self.category = category
        self.risk_level = risk_level
        self.cwe = cwe
        self.owasp = owasp
        self.remediation = remediation
        self.references = references

    @abstractmethod
    def scan(
        self,
        target_url: str,
        baseline_response: Optional[requests.Response],
        session: requests.Session,
        emitter: EventEmitter,
    ) -> List[Finding]:
        """Execute non-destructive security evaluation and return list of verified findings."""
        pass

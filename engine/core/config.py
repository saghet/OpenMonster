"""
Core Configuration and Safety Boundaries for SECMASTER-OpenMonster.
Ensures minimal user privileges, rate limiting, and timeout enforcement.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class EngineConfig:
    # Concurrency and Rate Limiting
    MAX_WORKERS: int = 10
    DEFAULT_RATE_LIMIT: int = 20  # requests per second
    REQUEST_TIMEOUT: int = 8      # seconds per individual request
    TOTAL_SCAN_TIMEOUT: int = 600 # 10 minutes maximum per scan session

    # Safety Restrictions
    PASSIVE_MODE_DEFAULT: bool = True
    ALLOW_DESTRUCTIVE_PAYLOADS: bool = False
    VERIFY_SSL_CERTS: bool = False  # Allows testing dev environments with self-signed certs

    # Blacklisted Target Ranges (Prevent inadvertent internal compromise unless explicit override)
    RESTRICTED_METADATA_IPS: List[str] = field(default_factory=lambda: [
        "169.254.169.254", # AWS / Azure instance metadata service
        "metadata.google.internal", # GCP metadata
    ])

    # User-Agent header (Explicitly identifying the authorized assessment platform)
    USER_AGENT: str = "SECMASTER-OpenMonster/1.0 (+https://github.com/OpenMonster/sec-master; Authorized Audit)"


config = EngineConfig()

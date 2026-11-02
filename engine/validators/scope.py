"""
Scope Enforcement and Target Whitelisting Validator.
Guarantees that no scanner executes outside authorized domains and IPs.
"""

import ipaddress
import urllib.parse
from typing import List, Optional


class ScopeViolationError(Exception):
    """Raised when an operation attempts to test a target outside the authorized scope."""
    pass


class ScopeValidator:
    def __init__(self, allowed_targets: List[str], passive_only: bool = True):
        self.allowed_targets = [self._normalize_target(t) for t in allowed_targets]
        self.passive_only = passive_only
        self.restricted_ips = ["169.254.169.254"]

    def _normalize_target(self, target: str) -> str:
        t = target.strip().lower()
        if t.startswith("http://") or t.startswith("https://"):
            parsed = urllib.parse.urlparse(t)
            return parsed.netloc.split(":")[0]
        return t.split(":")[0]

    def is_target_authorized(self, target_url: str) -> bool:
        """Verifies if the given URL or host is included in the authorized whitelist."""
        try:
            parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
            host = parsed.netloc.split(":")[0].lower()

            if not host:
                return False

            # Block cloud metadata access unless explicitly authorized
            if host in self.restricted_ips:
                return False

            # Check exact match or subdomain match
            for allowed in self.allowed_targets:
                if host == allowed or host.endswith(f".{allowed}"):
                    return True

                # Check CIDR match if allowed is an IP network
                try:
                    net = ipaddress.ip_network(allowed, strict=False)
                    target_ip = ipaddress.ip_address(host)
                    if target_ip in net:
                        return True
                except ValueError:
                    pass

            return False
        except Exception:
            return False

    def validate_or_raise(self, target_url: str, is_active_scan: bool = True) -> None:
        """Strict check before initiating any scan task."""
        if not self.is_target_authorized(target_url):
            raise ScopeViolationError(
                f"Scope Validation Failed: '{target_url}' is not in the authorized whitelist."
            )

        if is_active_scan and self.passive_only:
            raise ScopeViolationError(
                f"Scope Authorization Error: Target is in Passive-Only mode. Active fuzzing is not authorized."
            )

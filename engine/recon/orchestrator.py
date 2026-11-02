#!/usr/bin/env python3
"""
SECMASTER Reconnaissance & Intelligence Orchestrator.
Coordinates Passive Discovery, DNS Intelligence, HTTP Fingerprinting, and Technology Correlation.
Emits streaming JSON Lines events for desktop IPC and SQLite persistence.
"""

import argparse
import json
import os
import pathlib
import signal
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Ensure project root is in sys.path
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from engine.core.event import EventEmitter
from engine.recon.contracts import (
    DnsRecordResult,
    HttpFingerprintResult,
    ReconResult,
    SubdomainResult,
    TechResult,
)
from engine.validators.scope import ScopeValidator, ScopeViolationError

running = True


def handle_signal(sig, frame):
    global running
    sys.stderr.write(f"\n[!] Signal {sig} received: Gracefully terminating Reconnaissance Engine...\n")
    running = False


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


class ReconOrchestrator:
    """Coordinates execution of the 5 modular intelligence engines."""

    def __init__(
        self,
        target: str,
        asset_id: str,
        recon_scan_id: str,
        mode: str = "all",
        allowed_targets: Optional[List[str]] = None,
        passive_only: bool = False,
        rate_limit: int = 10,
    ):
        self.target = target
        self.asset_id = asset_id
        self.recon_scan_id = recon_scan_id
        self.mode = mode
        self.allowed_targets = allowed_targets or [target]
        self.passive_only = passive_only
        self.rate_limit = rate_limit
        self.emitter = EventEmitter(scan_id=recon_scan_id, asset_id=asset_id)

        # Normalize target domain
        parsed = urlparse(target if "://" in target else f"https://{target}")
        self.target_domain = parsed.hostname or target.split(":")[0].strip("/")

    def emit_event(self, event_type: str, data: Dict[str, Any]):
        """Emit formatted JSON Lines event to stdout."""
        event = {
            "type": event_type,
            "scan_id": self.recon_scan_id,
            "asset_id": self.asset_id,
            "timestamp": time.time(),
            "data": data,
        }
        print(json.dumps(event), flush=True)

    def run(self) -> ReconResult:
        global running
        start_time = time.time()
        result = ReconResult(
            target_domain=self.target_domain,
            asset_id=self.asset_id,
            scan_id=self.recon_scan_id,
        )

        self.emit_event("log", {"message": f"Iniciando Reconnaissance & Intelligence Engine sobre '{self.target_domain}' (Modo: {self.mode})..."})
        self.emit_event("progress", {"percent": 5.0, "message": "Validando autorización y límites de alcance..."})

        # 1. Scope Verification
        validator = ScopeValidator(allowed_targets=self.allowed_targets, passive_only=self.passive_only)
        try:
            validator.validate_or_raise(self.target, is_active_scan=not self.passive_only)
        except ScopeViolationError as e:
            self.emit_event("error", {"message": f"Scope Violation: {e}"})
            result.errors.append(str(e))
            return result

        # 2. Engine A: Passive Reconnaissance (crt.sh, CT Logs, OSINT)
        if running and self.mode in ("all", "passive"):
            self.emit_event("progress", {"percent": 15.0, "message": "Ejecutando Passive Recon (Certificate Transparency & OSINT)..."})
            try:
                from engine.recon.passive import PassiveReconEngine
                passive_engine = PassiveReconEngine(self.target_domain, self.emitter)
                subs = passive_engine.run()
                for s in subs:
                    result.subdomains.append(s)
                    self.emit_event("recon_subdomain", s.to_dict())
            except ImportError:
                self.emit_event("log", {"message": "PassiveReconEngine no inicializado en Fase B (esqueleto activo).", "level": "DEBUG"})
            except Exception as e:
                self.emit_event("log", {"message": f"Error en Passive Recon: {e}", "level": "WARNING"})
                result.errors.append(f"PassiveRecon: {e}")

        # 3. Engine B: DNS Intelligence (A, AAAA, CNAME, MX, NS, TXT, Takeover Check)
        if running and self.mode in ("all", "dns"):
            self.emit_event("progress", {"percent": 40.0, "message": "Ejecutando DNS Intelligence (Resolución multi-registro & Takeover check)..."})
            try:
                from engine.recon.dns_engine import DnsIntelligenceEngine
                dns_engine = DnsIntelligenceEngine(self.target_domain, self.emitter)
                records = dns_engine.run(subdomains=result.subdomains)
                for r in records:
                    result.dns_records.append(r)
                    self.emit_event("recon_dns", r.to_dict())
            except ImportError:
                self.emit_event("log", {"message": "DnsIntelligenceEngine no inicializado en Fase B (esqueleto activo).", "level": "DEBUG"})
            except Exception as e:
                self.emit_event("log", {"message": f"Error en DNS Intelligence: {e}", "level": "WARNING"})
                result.errors.append(f"DnsIntelligence: {e}")

        # 4. Engine C: HTTP & TLS Intelligence
        if running and self.mode in ("all", "http"):
            self.emit_event("progress", {"percent": 65.0, "message": "Ejecutando HTTP & TLS Intelligence (Cabeceras, X.509 & Cookies)..."})
            try:
                from engine.recon.http_engine import HttpIntelligenceEngine
                http_engine = HttpIntelligenceEngine(self.target, self.emitter)
                fps = http_engine.run()
                for fp in fps:
                    result.http_fingerprints.append(fp)
                    self.emit_event("recon_http", fp.to_dict())
            except ImportError:
                self.emit_event("log", {"message": "HttpIntelligenceEngine no inicializado en Fase B (esqueleto activo).", "level": "DEBUG"})
            except Exception as e:
                self.emit_event("log", {"message": f"Error en HTTP Intelligence: {e}", "level": "WARNING"})
                result.errors.append(f"HttpIntelligence: {e}")

        # 5. Engine D & E: Technology Fingerprinting & Correlation
        if running and self.mode in ("all", "tech"):
            self.emit_event("progress", {"percent": 85.0, "message": "Ejecutando Technology Fingerprinting & Correlation..."})
            try:
                from engine.recon.fingerprint import TechFingerprintEngine
                tech_engine = TechFingerprintEngine(self.target, self.emitter)
                techs = tech_engine.run(result.http_fingerprints)
                for t in techs:
                    result.technologies.append(t)
                    self.emit_event("recon_tech", t.to_dict())
            except ImportError:
                self.emit_event("log", {"message": "TechFingerprintEngine no inicializado en Fase B (esqueleto activo).", "level": "DEBUG"})
            except Exception as e:
                self.emit_event("log", {"message": f"Error en Technology Fingerprinting: {e}", "level": "WARNING"})
                result.errors.append(f"TechFingerprinting: {e}")

        result.execution_time_seconds = time.time() - start_time
        self.emit_event("progress", {"percent": 100.0, "message": "Auditoría de reconocimiento completada."})
        self.emit_event(
            "completed",
            {
                "subdomains_count": len(result.subdomains),
                "dns_records_count": len(result.dns_records),
                "technologies_count": len(result.technologies),
                "http_fingerprints_count": len(result.http_fingerprints),
                "execution_time_seconds": round(result.execution_time_seconds, 2),
                "errors_count": len(result.errors),
            },
        )
        return result


def main():
    parser = argparse.ArgumentParser(description="SECMASTER Reconnaissance & Intelligence Engine")
    parser.add_argument("--target", required=True, help="Target URL or domain to audit")
    parser.add_argument("--asset-id", required=True, help="Database asset UUID")
    parser.add_argument("--recon-scan-id", required=True, help="Recon scan session UUID")
    parser.add_argument("--mode", default="all", choices=["all", "passive", "dns", "http", "tech"], help="Reconnaissance mode")
    parser.add_argument("--allowed-targets", default="", help="Comma-separated allowlist of authorized targets")
    parser.add_argument("--passive-only", action="store_true", help="Force strictly passive OSINT mode")
    parser.add_argument("--rate-limit", type=int, default=10, help="Max requests per second")

    args = parser.parse_args()
    allowed = [t.strip() for t in args.allowed_targets.split(",") if t.strip()]

    orchestrator = ReconOrchestrator(
        target=args.target,
        asset_id=args.asset_id,
        recon_scan_id=args.recon_scan_id,
        mode=args.mode,
        allowed_targets=allowed,
        passive_only=args.passive_only,
        rate_limit=args.rate_limit,
    )
    orchestrator.run()


if __name__ == "__main__":
    main()

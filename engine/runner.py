#!/usr/bin/env python3
"""
SECMASTER-OpenMonster Security Engine Runner.
Orchestrates verified modular scanners, scope verification, and JSON Lines event streaming.
"""

import argparse
import os
import pathlib
import signal
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import requests
from engine.core.event import EventEmitter
from engine.validators.scope import ScopeValidator, ScopeViolationError
from engine.scanners.headers_scanner import HeadersScanner
from engine.scanners.ssti_scanner import SSTIScanner
from engine.scanners.xss_scanner import XSSScanner
from engine.scanners.sqli_scanner import SQLiScanner
from engine.scanners.openredirect_scanner import OpenRedirectScanner

# Graceful termination handling
running = True


def handle_signal(sig, frame):
    global running
    sys.stderr.write(f"\n[!] Signal {sig} received: Gracefully terminating scan operations...\n")
    running = False


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


def main():
    parser = argparse.ArgumentParser(description="SECMASTER Execution Engine")
    parser.add_argument("--target", required=True, help="Target URL to assess")
    parser.add_argument("--scan-id", required=True, help="Scan session UUID")
    parser.add_argument("--asset-id", required=True, help="Asset database ID")
    parser.add_argument("--vectors", default="all", help="Comma-separated test vectors (xss,sqli,ssti,openredirect,headers)")
    parser.add_argument("--rate-limit", type=int, default=20, help="Maximum requests per second")
    parser.add_argument("--allowed-targets", default="", help="Comma-separated whitelist of authorized domains/IPs")
    parser.add_argument("--passive-only", action="store_true", help="Enforce passive mode only")

    args = parser.parse_args()

    emitter = EventEmitter(scan_id=args.scan_id, asset_id=args.asset_id)
    emitter.log(f"Iniciando motor de auditoría para objetivo: {args.target}")

    # 1. Scope Whitelisting Enforcement
    allowed_list = [t.strip() for t in args.allowed_targets.split(",") if t.strip()]
    if not allowed_list:
        # Default to target's own host if no explicit list given
        allowed_list = [args.target]

    validator = ScopeValidator(allowed_targets=allowed_list, passive_only=args.passive_only)

    try:
        is_active = not args.passive_only
        validator.validate_or_raise(args.target, is_active_scan=is_active)
        emitter.log("Validación de alcance completada con éxito. Autorización confirmada.")
    except ScopeViolationError as e:
        emitter.error(str(e))
        sys.exit(1)

    # 2. HTTP Session setup
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SECMASTER-OpenMonster/1.0 (+https://github.com/OpenMonster/sec-master; Authorized Audit)",
        "Accept": "*/*",
    })

    # 3. Establish Baseline
    emitter.progress(5.0, "Estableciendo respuesta base (baseline)...")
    baseline_response = None
    try:
        baseline_response = session.get(args.target, timeout=8, allow_redirects=True, verify=False)
        emitter.log(f"Respuesta base obtenida: HTTP {baseline_response.status_code} ({len(baseline_response.text)} bytes)")
    except Exception as e:
        emitter.log(f"Advertencia: No se pudo conectar directamente con el objetivo ({e}). Continuando con pruebas...", level="WARNING")

    # 4. Scanner Selection
    selected_vector_ids = [v.strip().lower() for v in args.vectors.split(",") if v.strip()]
    if "all" in selected_vector_ids or not selected_vector_ids:
        selected_vector_ids = ["headers", "xss", "sqli", "ssti", "openredirect"]

    all_scanners = [
        ("headers", HeadersScanner()),
        ("ssti", SSTIScanner()),
        ("xss", XSSScanner()),
        ("sqli", SQLiScanner()),
        ("openredirect", OpenRedirectScanner()),
    ]

    active_scanners = [s for s in all_scanners if s[0] in selected_vector_ids or "all" in selected_vector_ids]

    total_scanners = len(active_scanners)
    total_findings_count = 0

    # 5. Run active scanners sequentially with progress tracking
    for idx, (name, scanner) in enumerate(active_scanners):
        if not running:
            emitter.log("Escaneo interrumpido por señal de detención.", level="WARNING")
            break

        progress_pct = 10.0 + ((idx / total_scanners) * 85.0)
        emitter.progress(progress_pct, f"Ejecutando módulo: {scanner.name}")

        try:
            results = scanner.scan(args.target, baseline_response, session, emitter)
            total_findings_count += len(results)
        except Exception as e:
            emitter.log(f"Error en módulo '{scanner.name}': {e}", level="ERROR")

    # 6. Completed
    emitter.progress(100.0, "Auditoría finalizada.")
    emitter.completed({
        "total_scanners_executed": len(active_scanners),
        "total_findings": total_findings_count,
        "target": args.target,
        "completed_at": time.time(),
    })


if __name__ == "__main__":
    main()

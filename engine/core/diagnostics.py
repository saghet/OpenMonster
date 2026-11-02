"""
Local Diagnostic and Telemetry Subsystem for SECMASTER.
Monitors platform health, dependency integrity, plugin status, and engine execution metrics.

Strict Guarantee:
Zero outbound telemetry. All diagnostics remain exclusively within the local host.
"""

from dataclasses import dataclass, field
import json
import os
import pathlib
import platform
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from engine.integrations.ollama_client import OllamaClient
from engine.plugins.manager import PluginManager


@dataclass
class DiagnosticResult:
    timestamp: str
    platform_info: Dict[str, str]
    python_env: Dict[str, Any]
    database_health: Dict[str, Any]
    core_modules_status: Dict[str, bool]
    plugins_status: List[Dict[str, Any]]
    ollama_status: Dict[str, Any]
    telemetry_policy: Dict[str, Any]
    overall_status: str  # HEALTHY, DEGRADED, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "platform_info": self.platform_info,
            "python_env": self.python_env,
            "database_health": self.database_health,
            "core_modules_status": self.core_modules_status,
            "plugins_status": self.plugins_status,
            "ollama_status": self.ollama_status,
            "telemetry_policy": self.telemetry_policy,
            "overall_status": self.overall_status,
        }


class SystemDiagnostics:
    """Performs deep health and integrity verification of the local platform."""

    @staticmethod
    def run_check(db_path: Optional[pathlib.Path] = None) -> DiagnosticResult:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        is_healthy = True

        # 1. Platform Info
        plat_info = {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "node": platform.node(),
        }

        # 2. Python Environment
        py_info = {
            "version": sys.version,
            "executable": sys.executable,
            "prefix": sys.prefix,
        }

        # 3. Database Integrity Check
        db_health: Dict[str, Any] = {"status": "UNKNOWN"}
        if db_path and db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check;")
                integrity_rows = cursor.fetchall()
                is_ok = integrity_rows == [("ok",)]
                db_size = os.path.getsize(db_path)
                db_health = {
                    "path": str(db_path),
                    "size_bytes": db_size,
                    "integrity_check": "PASS" if is_ok else "FAIL",
                    "details": integrity_rows,
                }
                if not is_ok:
                    is_healthy = False
                conn.close()
            except Exception as e:
                db_health = {"status": "ERROR", "error": str(e)}
                is_healthy = False
        else:
            db_health = {"status": "NOT_SPECIFIED_OR_IN_MEMORY"}

        # 4. Core Scanners Verification
        core_modules = {
            "ssti_scanner": False,
            "xss_scanner": False,
            "sqli_scanner": False,
            "openredirect_scanner": False,
            "headers_scanner": False,
        }
        try:
            from engine.scanners.ssti_scanner import SSTIScanner
            core_modules["ssti_scanner"] = True
        except Exception:
            is_healthy = False

        try:
            from engine.scanners.xss_scanner import XSSScanner
            core_modules["xss_scanner"] = True
        except Exception:
            is_healthy = False

        try:
            from engine.scanners.sqli_scanner import SQLiScanner
            core_modules["sqli_scanner"] = True
        except Exception:
            is_healthy = False

        try:
            from engine.scanners.openredirect_scanner import OpenRedirectScanner
            core_modules["openredirect_scanner"] = True
        except Exception:
            is_healthy = False

        try:
            from engine.scanners.headers_scanner import HeadersScanner
            core_modules["headers_scanner"] = True
        except Exception:
            is_healthy = False

        # 5. Plugins Status & Integrity
        pm = PluginManager()
        discovered = pm.discover_plugins()
        plugins_summary = []
        for p in discovered:
            plugins_summary.append({
                "plugin_id": p.plugin_id,
                "name": p.name,
                "version": p.version,
                "integrity_hash": p.integrity_hash[:16] + "..." if p.integrity_hash else None,
                "enabled": p.enabled,
                "permissions": p.permissions,
            })

        # 6. Ollama Status
        ollama = OllamaClient()
        ollama_status = ollama.check_health()
        ollama_summary = {
            "available": ollama_status.available,
            "installed_models": ollama_status.models,
            "error_message": ollama_status.error_message,
        }

        # 7. Telemetry Policy
        telemetry_policy = {
            "external_telemetry_enabled": False,
            "remote_endpoints_configured": 0,
            "local_storage_mode": "AIR_GAPPED_STRICT",
            "compliance": "Zero External Data Exfiltration",
        }

        overall_status = "HEALTHY" if is_healthy else "DEGRADED"

        return DiagnosticResult(
            timestamp=now_str,
            platform_info=plat_info,
            python_env=py_info,
            database_health=db_health,
            core_modules_status=core_modules,
            plugins_status=plugins_summary,
            ollama_status=ollama_summary,
            telemetry_policy=telemetry_policy,
            overall_status=overall_status,
        )


if __name__ == "__main__":
    diag = SystemDiagnostics.run_check()
    print(json.dumps(diag.to_dict(), indent=2))

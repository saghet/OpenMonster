#!/usr/bin/env python3
"""
SECMASTER Unified Engine CLI.
Provides headless and IPC endpoints for plugins, local Ollama assistance, and diagnostics.
"""

import argparse
import json
import pathlib
import sys

# Ensure project root is in sys.path
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from engine.core.diagnostics import SystemDiagnostics
from engine.integrations.ollama_client import OllamaClient
from engine.plugins.manager import PluginManager


def handle_plugins(args):
    pm = PluginManager()
    if args.subcommand == "list":
        plugins = pm.discover_plugins()
        print(json.dumps([p.to_dict() for p in plugins], indent=2))
    elif args.subcommand == "toggle":
        # Toggle enabled in manifest
        plugin_dir = pm.plugins_dir / args.plugin_id
        manifest_file = plugin_dir / "manifest.json"
        if not manifest_file.exists():
            print(json.dumps({"success": False, "error": f"Plugin {args.plugin_id} not found."}))
            sys.exit(1)
        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        new_state = args.enable.lower() in ("true", "1", "yes")
        data["enabled"] = new_state
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(json.dumps({"success": True, "plugin_id": args.plugin_id, "enabled": new_state}))


def handle_ollama(args):
    client = OllamaClient()
    if args.subcommand == "status":
        status = client.check_health()
        print(json.dumps({
            "available": status.available,
            "models": status.models,
            "error_message": status.error_message,
        }, indent=2))
    elif args.subcommand == "explain":
        try:
            evidence = json.loads(args.evidence) if args.evidence else {}
        except Exception:
            evidence = args.evidence

        res = client.explain_vulnerability(
            title=args.title,
            category=args.category,
            severity=args.severity,
            cwe=args.cwe,
            description=args.description,
            evidence=evidence,
            model=args.model,
        )
        print(json.dumps(res, indent=2))
    elif args.subcommand == "prioritize":
        try:
            findings = json.loads(args.findings)
        except Exception as e:
            print(json.dumps({"success": False, "error": f"Invalid findings JSON: {e}"}))
            sys.exit(1)
        res = client.prioritize_remediations(findings, model=args.model)
        print(json.dumps(res, indent=2))


def handle_diagnose(args):
    db_path = pathlib.Path(args.db_path) if args.db_path else None
    result = SystemDiagnostics.run_check(db_path=db_path)
    print(json.dumps(result.to_dict(), indent=2))


def main():
    parser = argparse.ArgumentParser(description="SECMASTER Engine Operations CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Plugins
    plugins_p = subparsers.add_parser("plugins", help="Manage plugins")
    plugins_sub = plugins_p.add_subparsers(dest="subcommand", required=True)
    plugins_sub.add_parser("list", help="List all discovered plugins")
    toggle_p = plugins_sub.add_parser("toggle", help="Toggle plugin enabled status")
    toggle_p.add_argument("plugin_id", help="Plugin identifier")
    toggle_p.add_argument("enable", help="'true' or 'false'")

    # Ollama
    ollama_p = subparsers.add_parser("ollama", help="Local AI assistance")
    ollama_sub = ollama_p.add_subparsers(dest="subcommand", required=True)
    ollama_sub.add_parser("status", help="Check local Ollama health and list models")
    explain_p = ollama_sub.add_parser("explain", help="Explain vulnerability and generate fix")
    explain_p.add_argument("--title", required=True)
    explain_p.add_argument("--category", required=True)
    explain_p.add_argument("--severity", required=True)
    explain_p.add_argument("--cwe", default="")
    explain_p.add_argument("--description", default="")
    explain_p.add_argument("--evidence", default="{}")
    explain_p.add_argument("--model", default=None)

    prio_p = ollama_sub.add_parser("prioritize", help="Prioritize findings")
    prio_p.add_argument("--findings", required=True, help="JSON string of findings array")
    prio_p.add_argument("--model", default=None)

    # Diagnostics
    diag_p = subparsers.add_parser("diagnose", help="Run local system health diagnostics")
    diag_p.add_argument("--db-path", default=None, help="Path to SQLite database file")

    args = parser.parse_args()

    if args.command == "plugins":
        handle_plugins(args)
    elif args.command == "ollama":
        handle_ollama(args)
    elif args.command == "diagnose":
        handle_diagnose(args)


if __name__ == "__main__":
    main()

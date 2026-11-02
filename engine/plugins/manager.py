"""
Plugin Architecture and Manifest Management for SECMASTER.
Provides discovery, schema validation, integrity hashing, permission sandboxing,
and dynamic loading of security testing plugins.
"""

import hashlib
import json
import logging
import os
import pathlib
import sys
from dataclasses import dataclass, field
from importlib.util import module_from_spec, spec_from_file_location
from typing import Any, Dict, List, Optional, Tuple

from engine.core.module import Finding, SecurityModule

logger = logging.getLogger("sec_master.plugins")

# Allowlisted capability permissions that plugins may request
ALLOWED_PERMISSIONS = {
    "network:http_probe",
    "network:tls_probe",
    "analysis:static_ast",
    "report:enrichment",
    "dns:lookup",
}

# Strictly forbidden permissions that violate platform security boundaries
PROHIBITED_PERMISSIONS = {
    "system:root",
    "system:raw_shell",
    "system:kernel_module",
    "network:bypass_scope",
    "network:dos_flood",
}


@dataclass
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    author: str
    license: str
    category: str
    description: str
    entrypoint: str
    permissions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    integrity_hash: Optional[str] = None
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "license": self.license,
            "category": self.category,
            "description": self.description,
            "entrypoint": self.entrypoint,
            "permissions": self.permissions,
            "dependencies": self.dependencies,
            "risk_level": self.risk_level,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "integrity_hash": self.integrity_hash,
            "enabled": self.enabled,
        }


class PluginValidationError(Exception):
    """Raised when a plugin manifest or integrity check fails validation."""
    pass


class PluginManager:
    """Discovers, validates, and loads SECMASTER plugins securely."""

    def __init__(self, plugins_dir: Optional[pathlib.Path] = None):
        if plugins_dir is None:
            # Default to engine/plugins/ or workspace plugins directory
            base_dir = pathlib.Path(__file__).resolve().parent
            self.plugins_dir = base_dir / "installed"
        else:
            self.plugins_dir = plugins_dir

        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self._loaded_plugins: Dict[str, Tuple[PluginManifest, Any]] = {}

    def calculate_file_hash(self, file_path: pathlib.Path) -> str:
        """Compute SHA-256 checksum of an entrypoint file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def validate_manifest(self, manifest_data: Dict[str, Any], plugin_path: pathlib.Path) -> PluginManifest:
        """Validate manifest fields, license compliance, and permission boundaries."""
        required_keys = ["plugin_id", "name", "version", "author", "license", "category", "entrypoint"]
        for key in required_keys:
            if key not in manifest_data or not manifest_data[key]:
                raise PluginValidationError(f"Missing mandatory manifest attribute: '{key}'")

        # Validate permissions against platform constraints
        permissions = manifest_data.get("permissions", [])
        for perm in permissions:
            if perm in PROHIBITED_PERMISSIONS:
                raise PluginValidationError(
                    f"Security Boundary Violation: Plugin requests prohibited permission '{perm}'"
                )
            if perm not in ALLOWED_PERMISSIONS:
                raise PluginValidationError(
                    f"Unknown or unapproved permission '{perm}'. Allowed: {sorted(ALLOWED_PERMISSIONS)}"
                )

        # Check entrypoint existence
        entrypoint_file = plugin_path / manifest_data["entrypoint"]
        if not entrypoint_file.exists() or not entrypoint_file.is_file():
            raise PluginValidationError(f"Entrypoint file not found: {manifest_data['entrypoint']}")

        # Compute or check integrity hash
        integrity_hash = self.calculate_file_hash(entrypoint_file)
        expected_hash = manifest_data.get("integrity_hash")
        if expected_hash and expected_hash.lower() != integrity_hash.lower():
            raise PluginValidationError(
                f"Cryptographic Integrity Mismatch! Expected: {expected_hash}, computed: {integrity_hash}"
            )

        return PluginManifest(
            plugin_id=manifest_data["plugin_id"],
            name=manifest_data["name"],
            version=manifest_data["version"],
            author=manifest_data["author"],
            license=manifest_data["license"],
            category=manifest_data["category"],
            description=manifest_data.get("description", ""),
            entrypoint=manifest_data["entrypoint"],
            permissions=permissions,
            dependencies=manifest_data.get("dependencies", []),
            risk_level=manifest_data.get("risk_level", "medium"),
            cwe=manifest_data.get("cwe"),
            owasp=manifest_data.get("owasp"),
            integrity_hash=integrity_hash,
            enabled=manifest_data.get("enabled", True),
        )

    def discover_plugins(self) -> List[PluginManifest]:
        """Scan plugins directory for valid plugins with manifest.json."""
        manifests = []
        if not self.plugins_dir.exists():
            return manifests

        for item in self.plugins_dir.iterdir():
            if item.is_dir():
                manifest_file = item / "manifest.json"
                if manifest_file.exists():
                    try:
                        with open(manifest_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        manifest = self.validate_manifest(data, item)
                        manifests.append(manifest)
                    except Exception as e:
                        logger.warning("Failed to load plugin at %s: %s", item, e)

        return manifests

    def load_plugin_instance(self, plugin_dir: pathlib.Path, manifest: PluginManifest) -> Optional[SecurityModule]:
        """Dynamically load and instantiate the plugin's SecurityModule."""
        if not manifest.enabled:
            return None

        entrypoint_path = plugin_dir / manifest.entrypoint
        module_name = f"sec_master_plugin_{manifest.plugin_id.replace('-', '_')}"

        try:
            spec = spec_from_file_location(module_name, str(entrypoint_path))
            if not spec or not spec.loader:
                raise ImportError(f"Cannot create loader for {entrypoint_path}")

            mod = module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)

            # Look for SecurityModule class
            plugin_cls = getattr(mod, "PluginScanner", None)
            if plugin_cls is None:
                # Search for subclass of SecurityModule
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if isinstance(attr, type) and issubclass(attr, SecurityModule) and attr is not SecurityModule:
                        plugin_cls = attr
                        break

            if plugin_cls is None:
                raise ValueError(f"Plugin {manifest.plugin_id} does not export a SecurityModule or PluginScanner class.")

            instance = plugin_cls()
            self._loaded_plugins[manifest.plugin_id] = (manifest, instance)
            return instance

        except Exception as e:
            logger.error("Failed to load plugin %s: %s", manifest.plugin_id, e)
            raise

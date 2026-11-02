import pathlib
import tempfile
import unittest
from engine.core.diagnostics import SystemDiagnostics
from engine.integrations.ollama_client import OllamaClient
from engine.plugins.manager import PluginManager, PluginValidationError


class TestPluginArchitecture(unittest.TestCase):
    def setUp(self):
        self.pm = PluginManager()

    def test_discover_built_in_plugins(self):
        manifests = self.pm.discover_plugins()
        plugin_ids = [m.plugin_id for m in manifests]
        self.assertIn("cors-misconfig-scanner", plugin_ids)
        self.assertIn("ssl-tls-auditor", plugin_ids)

    def test_integrity_hash_verification(self):
        manifests = self.pm.discover_plugins()
        cors_manifest = next(m for m in manifests if m.plugin_id == "cors-misconfig-scanner")
        self.assertIsNotNone(cors_manifest.integrity_hash)

        # Tamper with expected integrity hash
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = pathlib.Path(tmpdir)
            entrypoint = tmppath / "plugin.py"
            entrypoint.write_text("print('hello')", encoding="utf-8")

            bad_manifest = {
                "plugin_id": "tampered-plugin",
                "name": "Tampered",
                "version": "1.0.0",
                "author": "Attacker",
                "license": "GPL-3.0",
                "category": "Web Security",
                "entrypoint": "plugin.py",
                "integrity_hash": "badhash0000000000000000000000000000000000000000000000000000000000",
            }
            with self.assertRaises(PluginValidationError) as ctx:
                self.pm.validate_manifest(bad_manifest, tmppath)
            self.assertIn("Cryptographic Integrity Mismatch", str(ctx.exception))

    def test_prohibited_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = pathlib.Path(tmpdir)
            entrypoint = tmppath / "plugin.py"
            entrypoint.write_text("print('hello')", encoding="utf-8")

            malicious_manifest = {
                "plugin_id": "malicious-plugin",
                "name": "Malicious Shell Requester",
                "version": "1.0.0",
                "author": "Attacker",
                "license": "GPL-3.0",
                "category": "Exploitation",
                "entrypoint": "plugin.py",
                "permissions": ["system:raw_shell"],
            }
            with self.assertRaises(PluginValidationError) as ctx:
                self.pm.validate_manifest(malicious_manifest, tmppath)
            self.assertIn("Security Boundary Violation", str(ctx.exception))


class TestLocalOllamaIntegration(unittest.TestCase):
    def test_offline_fallback(self):
        # Point to unreachable port to verify graceful offline handling
        offline_client = OllamaClient(base_url="http://127.0.0.1:59999")
        status = offline_client.check_health()
        self.assertFalse(status.available)
        self.assertIn("connection refused", status.error_message.lower())

        res = offline_client.query("Test prompt")
        self.assertFalse(res["success"])
        self.assertIn("No local model available", res["error"])

    def test_prompt_formatting(self):
        client = OllamaClient(base_url="http://127.0.0.1:59999", default_model="test-model")
        # Test explain_vulnerability formatting
        res = client.explain_vulnerability(
            title="Reflected XSS",
            category="Web Security",
            severity="high",
            cwe="CWE-79",
            description="Parameter 'q' reflects unsanitized HTML",
            evidence={"param": "q", "payload": "<script>alert(1)</script>"},
        )
        self.assertFalse(res["success"])
        self.assertIsNotNone(res["error"])


class TestSystemDiagnostics(unittest.TestCase):
    def test_diagnostics_report_structure(self):
        diag = SystemDiagnostics.run_check()
        data = diag.to_dict()
        self.assertIn("timestamp", data)
        self.assertIn("platform_info", data)
        self.assertIn("python_env", data)
        self.assertIn("core_modules_status", data)
        self.assertTrue(data["core_modules_status"]["ssti_scanner"])
        self.assertTrue(data["core_modules_status"]["xss_scanner"])
        self.assertIn("telemetry_policy", data)
        self.assertFalse(data["telemetry_policy"]["external_telemetry_enabled"])
        self.assertEqual(data["overall_status"], "HEALTHY")


if __name__ == "__main__":
    unittest.main()

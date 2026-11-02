import unittest
from engine.validators.scope import ScopeValidator, ScopeViolationError


class TestScopeValidator(unittest.TestCase):
    def test_scope_authorization_whitelisting(self):
        validator = ScopeValidator(
            allowed_targets=["staging.corp.local", "192.168.1.0/24"],
            passive_only=False
        )

        # Valid targets
        self.assertTrue(validator.is_target_authorized("https://staging.corp.local/api/users"))
        self.assertTrue(validator.is_target_authorized("http://sub.staging.corp.local:8080/test"))
        self.assertTrue(validator.is_target_authorized("http://192.168.1.55/login"))

        # Out of scope targets
        self.assertFalse(validator.is_target_authorized("https://unauthorized-bank.com"))
        self.assertFalse(validator.is_target_authorized("http://10.0.0.1"))

        # Cloud metadata service protection
        self.assertFalse(validator.is_target_authorized("http://169.254.169.254/latest/meta-data"))

    def test_passive_only_blocks_active_scans(self):
        validator = ScopeValidator(
            allowed_targets=["staging.corp.local"],
            passive_only=True
        )

        # Passive mode is permitted without raising
        validator.validate_or_raise("https://staging.corp.local", is_active_scan=False)

        # Active fuzzing raises ScopeViolationError
        with self.assertRaises(ScopeViolationError) as cm:
            validator.validate_or_raise("https://staging.corp.local", is_active_scan=True)
        self.assertIn("Passive-Only mode", str(cm.exception))


if __name__ == '__main__':
    unittest.main()

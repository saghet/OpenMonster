"""
Unit tests for the SECMASTER Technology Fingerprinting Engine.
Tests multi-factor technology detection across Headers, Cookies, Meta tags, Scripts,
and HTML patterns with confidence grading (Confirmed, Probable, Suspected).
"""

import unittest
from unittest.mock import MagicMock, patch

from engine.recon.contracts import HttpFingerprintResult, TechResult
from engine.recon.fingerprint import TechFingerprintEngine


class TestTechFingerprintEngine(unittest.TestCase):

    def setUp(self):
        self.engine = TechFingerprintEngine("https://example.com")

    def test_signatures_loaded(self):
        self.assertGreater(len(self.engine.signatures), 10)
        names = [s["name"] for s in self.engine.signatures]
        self.assertIn("Nginx", names)
        self.assertIn("WordPress", names)
        self.assertIn("Next.js", names)
        self.assertIn("PHP", names)
        self.assertIn("Cloudflare", names)

    def test_wordpress_multi_factor_confirmed(self):
        # Meta generator + script src -> Confirmed with version
        html = (
            '<html><head><meta name="generator" content="WordPress 6.4.3">'
            '<script src="/wp-content/themes/custom/main.js"></script></head><body>'
            '<div class="wp-block-group">Hello</div></body></html>'
        )
        techs = self.engine.analyze_fingerprint(
            target_url="https://example.com",
            raw_headers={},
            cookies=[],
            html_content=html,
        )

        wp = next((t for t in techs if t.name == "WordPress"), None)
        self.assertIsNotNone(wp)
        self.assertEqual(wp.category, "CMS")
        self.assertEqual(wp.version, "6.4.3")
        self.assertEqual(wp.confidence, "Confirmed")
        self.assertTrue(len(wp.matched_indicators) >= 2)

    def test_php_headers_and_cookie_confirmed(self):
        # X-Powered-By header + PHPSESSID cookie -> Confirmed
        raw_headers = {
            "x-powered-by": "PHP/8.2.14",
            "server": "nginx/1.24.0",
        }
        cookies = [{"name": "PHPSESSID", "value": "abc123xyz"}]

        techs = self.engine.analyze_fingerprint(
            target_url="https://example.com",
            raw_headers=raw_headers,
            cookies=cookies,
            html_content="",
        )

        php = next((t for t in techs if t.name == "PHP"), None)
        self.assertIsNotNone(php)
        self.assertEqual(php.version, "8.2.14")
        self.assertEqual(php.confidence, "Confirmed")

        nginx = next((t for t in techs if t.name == "Nginx"), None)
        self.assertIsNotNone(nginx)
        self.assertEqual(nginx.version, "1.24.0")
        self.assertEqual(nginx.confidence, "Probable")

    def test_nextjs_and_react_detection(self):
        html = (
            '<html><head><script src="/_next/static/chunks/main-app.js"></script></head>'
            '<body><div id="__NEXT_DATA__">{}</div>'
            '<div data-reactroot="">React App</div></body></html>'
        )
        techs = self.engine.analyze_fingerprint(
            target_url="https://example.com",
            raw_headers={"x-powered-by": "Next.js"},
            cookies=[],
            html_content=html,
        )

        nextjs = next((t for t in techs if t.name == "Next.js"), None)
        self.assertIsNotNone(nextjs)
        self.assertEqual(nextjs.confidence, "Confirmed")

        react = next((t for t in techs if t.name == "React"), None)
        self.assertIsNotNone(react)
        self.assertEqual(react.confidence, "Probable")

    def test_cloudflare_cdn_confirmed(self):
        raw_headers = {
            "server": "cloudflare",
            "cf-ray": "8df912837123",
            "cf-cache-status": "HIT",
        }
        cookies = [{"name": "__cf_bm", "value": "token"}]

        techs = self.engine.analyze_fingerprint(
            target_url="https://example.com",
            raw_headers=raw_headers,
            cookies=cookies,
            html_content="",
        )

        cf = next((t for t in techs if t.name == "Cloudflare"), None)
        self.assertIsNotNone(cf)
        self.assertEqual(cf.confidence, "Confirmed")

    @patch("requests.get")
    def test_run_orchestration_with_fingerprints(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.text = '<html><head><meta name="generator" content="Drupal 10"></head></html>'
        mock_get.return_value = mock_resp

        fp = HttpFingerprintResult(
            target_url="https://drupal.example.com",
            status_code=200,
            server_header="Apache/2.4.41",
            raw_headers={"x-generator": "Drupal 10"},
            cookies=[],
        )

        techs = self.engine.run([fp])
        self.assertTrue(len(techs) >= 1)
        drupal = next((t for t in techs if t.name == "Drupal"), None)
        self.assertIsNotNone(drupal)
        self.assertEqual(drupal.version, "10")
        self.assertEqual(drupal.confidence, "Confirmed")


if __name__ == "__main__":
    unittest.main()

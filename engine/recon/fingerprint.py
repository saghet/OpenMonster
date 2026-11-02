"""
SECMASTER Technology Fingerprinting Engine.
Identifies Web Servers, Frameworks, Programming Languages, CMS, JavaScript Libraries,
CDNs, and WAFs using multi-factor indicators (Headers, Cookies, Meta tags, Scripts, HTML DOM).
Adheres to Wappalyzer-compatible signature schemas with strict confidence grading.
"""

import json
import logging
import os
import pathlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from engine.recon.contracts import HttpFingerprintResult, TechResult

logger = logging.getLogger("sec_master.recon.fingerprint")

# Default signatures path
_DEFAULT_SIGS_PATH = (
    pathlib.Path(__file__).resolve().parent / "signatures" / "technologies.json"
)

# Regex to extract <meta name="..." content="..."> and <script src="...">
_META_REGEX = re.compile(
    r'<meta\s+[^>]*?(?:name|property)=["\']([^"\']+)["\'][^>]*?content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_META_REGEX_REVERSE = re.compile(
    r'<meta\s+[^>]*?content=["\']([^"\']*)["\'][^>]*?(?:name|property)=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_SCRIPT_SRC_REGEX = re.compile(r'<script\s+[^>]*?src=["\']([^"\']+)["\']', re.IGNORECASE)


class TechFingerprintEngine:
    """
    Multi-factor Technology Identification Engine.
    Detects technology stacks and categorizes confidence into Confirmed, Probable, or Suspected.
    """

    def __init__(
        self,
        target: str,
        emitter: Optional[Any] = None,
        signatures_path: Optional[str] = None,
        timeout: int = 5,
    ):
        self.target = target.strip()
        self.emitter = emitter
        self.timeout = timeout
        self.signatures_path = (
            pathlib.Path(signatures_path) if signatures_path else _DEFAULT_SIGS_PATH
        )
        self.signatures: List[Dict[str, Any]] = self._load_signatures()

    def _emit_log(self, message: str, level: str = "INFO"):
        if not self.emitter:
            return
        if hasattr(self.emitter, "log"):
            self.emitter.log(message, level=level)
        elif hasattr(self.emitter, "emit"):
            self.emitter.emit("log", {"message": message, "level": level})

    def _load_signatures(self) -> List[Dict[str, Any]]:
        """Loads and compiles JSON signatures for high-speed matching."""
        if not self.signatures_path.exists():
            logger.warning(f"Signatures database not found at {self.signatures_path}")
            return []

        try:
            with open(self.signatures_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_techs = data.get("technologies", [])
            compiled = []
            for item in raw_techs:
                entry = {
                    "name": item.get("name"),
                    "category": item.get("category", "General"),
                    "headers": {},
                    "cookies": [],
                    "meta": {},
                    "scripts": [],
                    "html": [],
                }
                # Compile headers regex
                for h_key, h_pattern in item.get("headers", {}).items():
                    entry["headers"][h_key.lower()] = re.compile(h_pattern, re.IGNORECASE)
                # Compile cookies regex
                for c_pattern in item.get("cookies", []):
                    entry["cookies"].append(re.compile(c_pattern, re.IGNORECASE))
                # Compile meta regex
                for m_key, m_pattern in item.get("meta", {}).items():
                    entry["meta"][m_key.lower()] = re.compile(m_pattern, re.IGNORECASE)
                # Compile scripts regex
                for s_pattern in item.get("scripts", []):
                    entry["scripts"].append(re.compile(s_pattern, re.IGNORECASE))
                # Compile html regex
                for ht_pattern in item.get("html", []):
                    entry["html"].append(re.compile(ht_pattern, re.IGNORECASE))

                compiled.append(entry)
            return compiled
        except Exception as e:
            logger.error(f"Failed to load technology signatures: {e}")
            return []

    def extract_dom_indicators(
        self, html_content: str
    ) -> Tuple[Dict[str, str], List[str]]:
        """Extracts metadata tags and script source URLs from HTML."""
        meta_dict = {}
        for m in _META_REGEX.finditer(html_content):
            meta_dict[m.group(1).lower()] = m.group(2)
        for m in _META_REGEX_REVERSE.finditer(html_content):
            meta_dict[m.group(2).lower()] = m.group(1)

        scripts = []
        for s in _SCRIPT_SRC_REGEX.finditer(html_content):
            scripts.append(s.group(1))

        return meta_dict, scripts

    def analyze_fingerprint(
        self,
        target_url: str,
        raw_headers: Dict[str, str],
        cookies: List[Dict[str, Any]],
        html_content: str = "",
    ) -> List[TechResult]:
        """
        Evaluates a single target using headers, cookies, and DOM context.
        Returns a list of detected technologies with verified confidence levels.
        """
        results: List[TechResult] = []
        meta_dict, script_srcs = (
            self.extract_dom_indicators(html_content) if html_content else ({}, [])
        )

        for sig in self.signatures:
            tech_name = sig["name"]
            category = sig["category"]
            matched_indicators: List[str] = []
            extracted_version: Optional[str] = None
            factor_types: Set[str] = set()

            # 1. Header Matching
            for h_name, h_regex in sig["headers"].items():
                if h_name in raw_headers:
                    h_val = raw_headers[h_name]
                    match = h_regex.search(h_val)
                    if match:
                        matched_indicators.append(f"header:{h_name}={h_val}")
                        factor_types.add("header")
                        if match.groups() and match.group(1):
                            extracted_version = match.group(1)

            # 2. Cookie Matching
            for c_regex in sig["cookies"]:
                for c in cookies:
                    c_name = c.get("name", "")
                    if c_regex.search(c_name):
                        matched_indicators.append(f"cookie:{c_name}")
                        factor_types.add("cookie")

            # 3. Meta Tag Matching
            for m_name, m_regex in sig["meta"].items():
                if m_name in meta_dict:
                    m_val = meta_dict[m_name]
                    match = m_regex.search(m_val)
                    if match:
                        matched_indicators.append(f"meta:{m_name}={m_val}")
                        factor_types.add("meta")
                        if match.groups() and match.group(1):
                            extracted_version = match.group(1)

            # 4. Script Matching
            for s_regex in sig["scripts"]:
                for src in script_srcs:
                    match = s_regex.search(src)
                    if match:
                        matched_indicators.append(f"script:{src}")
                        factor_types.add("script")
                        if match.groups() and match.group(1):
                            extracted_version = match.group(1)

            # 5. HTML Content Matching
            if html_content:
                for ht_regex in sig["html"]:
                    match = ht_regex.search(html_content)
                    if match:
                        matched_indicators.append("html_pattern")
                        factor_types.add("html")
                        if match.groups() and match.group(1):
                            extracted_version = match.group(1)

            # If any indicators matched, assign calibrated confidence level
            if matched_indicators:
                # 2 or more distinct factor types (e.g. header + script) -> Confirmed
                if len(factor_types) >= 2 or len(matched_indicators) >= 3:
                    confidence = "Confirmed"
                # 1 strong definitive factor (e.g. meta generator with version, or X-Powered-By) -> Probable
                elif any(f in factor_types for f in ("meta", "script", "html")) or extracted_version:
                    confidence = "Probable"
                else:
                    confidence = "Suspected"

                results.append(
                    TechResult(
                        target_url=target_url,
                        name=tech_name,
                        category=category,
                        version=extracted_version,
                        confidence=confidence,
                        matched_indicators=matched_indicators,
                    )
                )

        return results

    def run(
        self, http_fingerprints: Optional[List[HttpFingerprintResult]] = None
    ) -> List[TechResult]:
        """
        Runs fingerprinting across all provided HTTP endpoints.
        Queries HTML body if needed to perform DOM and script analysis.
        """
        all_techs: List[TechResult] = []
        seen_keys: Set[Tuple[str, str]] = set()

        if not http_fingerprints:
            return []

        self._emit_log(
            f"Iniciando Technology Fingerprinting sobre {len(http_fingerprints)} huella(s) HTTP...",
            level="INFO",
        )

        headers_req = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SECMASTER/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        for fp in http_fingerprints:
            url = fp.target_url
            html_body = ""
            # Safely fetch HTML body (first 64KB) for DOM and script inspection
            try:
                resp = requests.get(
                    url,
                    headers=headers_req,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                html_body = resp.text[:65536] if resp.text else ""
            except Exception as e:
                logger.debug(f"Could not retrieve HTML body for {url}: {e}")

            detected = self.analyze_fingerprint(
                target_url=url,
                raw_headers=fp.raw_headers,
                cookies=fp.cookies,
                html_content=html_body,
            )

            for t in detected:
                key = (t.target_url, t.name)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_techs.append(t)

        self._emit_log(
            f"Technology Fingerprinting completado: {len(all_techs)} tecnologías identificadas.",
            level="INFO",
        )

        return all_techs

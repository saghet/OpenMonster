"""
SSL/TLS Configuration and Certificate Integrity Plugin for SECMASTER.
Audits HTTPS transport security, certificate validity, expiration, and host matching.
"""

from datetime import datetime, timezone
import socket
import ssl
from typing import List, Optional
from urllib.parse import urlparse
import requests

from engine.core.event import EventEmitter
from engine.core.module import Finding, SecurityModule


class PluginScanner(SecurityModule):
    def __init__(self):
        super().__init__(
            module_id="ssl-tls-auditor",
            name="SSL/TLS Transport Security Auditor",
            description="Revisa vigencia del certificado X.509, coincidencia de nombre común (CN/SAN), algoritmos de firma y seguridad de capa de transporte.",
            version="1.0.0",
            category="Network Security",
            risk_level="medium",
            cwe="CWE-295",
            owasp="A02:2021 - Cryptographic Failures",
            remediation="Instalar certificados válidos emitidos por una Autoridad de Certificación (CA) de confianza y renovar antes del vencimiento.",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cwe.mitre.org/data/definitions/295.html",
            ],
        )

    def scan(
        self,
        target_url: str,
        baseline_response: Optional[requests.Response],
        session: requests.Session,
        emitter: EventEmitter,
    ) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(target_url)

        if parsed.scheme != "https":
            emitter.emit_log(f"Target {target_url} does not use HTTPS; skipping TLS certificate audit.", level="INFO")
            return findings

        hostname = parsed.hostname or "localhost"
        port = parsed.port or 443

        emitter.emit_log(f"Auditing TLS certificate handshake on {hostname}:{port}...", level="INFO")

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    if not cert:
                        emitter.emit_log("No peer certificate retrieved during TLS handshake.", level="WARNING")
                        return findings

                    # Check expiration
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        # Format example: 'May 15 12:00:00 2027 GMT'
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_remaining = (not_after - now).days

                        if days_remaining < 0:
                            findings.append(
                                Finding(
                                    title=f"Expired SSL/TLS Certificate on {hostname}",
                                    category=self.category,
                                    attack_type="expired_certificate",
                                    vector=f"tls:{hostname}:{port}",
                                    severity="high",
                                    confidence=100,
                                    cwe=self.cwe,
                                    owasp=self.owasp,
                                    cvss_score=7.4,
                                    description=f"The SSL/TLS certificate expired {abs(days_remaining)} days ago on {not_after_str}.",
                                    evidence={
                                        "hostname": hostname,
                                        "port": port,
                                        "not_after": not_after_str,
                                        "days_remaining": days_remaining,
                                    },
                                    remediation=self.remediation,
                                    verified=True,
                                )
                            )
                        elif days_remaining < 15:
                            findings.append(
                                Finding(
                                    title=f"SSL/TLS Certificate Expiring Soon ({days_remaining} days)",
                                    category=self.category,
                                    attack_type="expiring_certificate",
                                    vector=f"tls:{hostname}:{port}",
                                    severity="low",
                                    confidence=100,
                                    cwe=self.cwe,
                                    owasp=self.owasp,
                                    cvss_score=3.5,
                                    description=f"The SSL/TLS certificate will expire in {days_remaining} days on {not_after_str}.",
                                    evidence={
                                        "hostname": hostname,
                                        "port": port,
                                        "not_after": not_after_str,
                                        "days_remaining": days_remaining,
                                    },
                                    remediation="Renew the certificate before expiration to prevent service outages.",
                                    verified=True,
                                )
                            )

                    emitter.emit_log(f"TLS established using {tls_version} with cipher {cipher[0]} ({cipher[2]} bits)", level="INFO")

        except ssl.SSLCertVerificationError as e:
            findings.append(
                Finding(
                    title=f"Invalid or Untrusted SSL/TLS Certificate on {hostname}",
                    category=self.category,
                    attack_type="untrusted_certificate",
                    vector=f"tls:{hostname}:{port}",
                    severity="high",
                    confidence=100,
                    cwe=self.cwe,
                    owasp=self.owasp,
                    cvss_score=6.8,
                    description=f"The certificate could not be verified by the system trust store: {e.verify_message}",
                    evidence={
                        "hostname": hostname,
                        "port": port,
                        "verify_code": e.verify_code,
                        "verify_message": e.verify_message,
                    },
                    remediation=self.remediation,
                    verified=True,
                )
            )
        except Exception as e:
            emitter.emit_log(f"TLS probe could not complete: {e}", level="DEBUG")

        return findings

"""
Local Ollama AI Integration Client for SECMASTER.
Operates exclusively over local HTTP (127.0.0.1:11434) to assist security analysts
with technical explanations, remediation code snippets, and risk prioritization.

Strict Architectural Guarantees:
- Fully air-gapped: Zero outbound external telemetry or cloud AI endpoints.
- Read-only advisor: Cannot execute commands or bypass engine authorization controls.
- Graceful offline fallback: The platform remains 100% operational without Ollama.
"""

from dataclasses import dataclass
import json
import logging
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger("sec_master.ollama")

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_TIMEOUT = 30  # seconds


@dataclass
class OllamaStatus:
    available: bool
    models: List[str]
    error_message: Optional[str] = None


class OllamaClient:
    """Interface to local Ollama instance for cybersecurity analytical assistance."""

    def __init__(self, base_url: str = DEFAULT_OLLAMA_HOST, default_model: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model

    def check_health(self) -> OllamaStatus:
        """Check if local Ollama daemon is active and list available models."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", []) if "name" in m]
                return OllamaStatus(available=True, models=models)
            return OllamaStatus(
                available=False,
                models=[],
                error_message=f"Ollama returned HTTP status {resp.status_code}",
            )
        except requests.exceptions.ConnectionError:
            return OllamaStatus(
                available=False,
                models=[],
                error_message="Ollama local daemon is not running (connection refused on 127.0.0.1:11434).",
            )
        except Exception as e:
            return OllamaStatus(available=False, models=[], error_message=str(e))

    def _get_active_model(self) -> Optional[str]:
        if self.default_model:
            return self.default_model
        status = self.check_health()
        if status.available and status.models:
            return status.models[0]
        return None

    def query(self, prompt: str, system_prompt: Optional[str] = None, model: Optional[str] = None) -> Dict[str, Any]:
        """Send analytical prompt to local Ollama model."""
        target_model = model or self._get_active_model()
        if not target_model:
            return {
                "success": False,
                "error": "No local model available. Run 'ollama pull llama3' or 'ollama pull mistral'.",
                "response": None,
            }

        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 200:
                result = resp.json()
                return {
                    "success": True,
                    "model": target_model,
                    "response": result.get("response", ""),
                    "total_duration": result.get("total_duration"),
                }
            return {
                "success": False,
                "error": f"Ollama generation failed with status {resp.status_code}: {resp.text}",
                "response": None,
            }
        except Exception as e:
            return {"success": False, "error": str(e), "response": None}

    def explain_vulnerability(
        self,
        title: str,
        category: str,
        severity: str,
        cwe: Optional[str],
        description: str,
        evidence: Any,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a technical explanation and defensive developer fix for a finding."""
        system_prompt = (
            "Eres un especialista senior en ciberseguridad defensiva y auditoría de código para SECMASTER. "
            "Tu tarea es analizar hallazgos técnicos confirmados, explicar de forma concisa el impacto real para la "
            "organización y proporcionar código de ejemplo seguro y defensivo para remediar la vulnerabilidad. "
            "Responde siempre en español, de forma profesional y orientada a la ingeniería segura."
        )

        prompt = f"""
Por favor, analiza el siguiente hallazgo de seguridad:

- Título: {title}
- Categoría: {category}
- Severidad: {severity.upper()}
- CWE: {cwe or 'No especificado'}
- Descripción: {description}
- Evidencia Técnica:
```json
{json.dumps(evidence, indent=2) if isinstance(evidence, (dict, list)) else str(evidence)}
```

Proporciona:
1. Resumen Ejecutivo del Riesgo.
2. Vector de Explotación Teórico (cómo un atacante podría abusar de esto).
3. Guía de Remediación Paso a Paso para Desarrolladores (con ejemplo de código seguro).
"""
        return self.query(prompt, system_prompt=system_prompt, model=model)

    def prioritize_remediations(
        self,
        vulnerabilities: List[Dict[str, Any]],
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze a collection of findings and generate a risk-prioritized action plan."""
        system_prompt = (
            "Eres un Lead Auditor de Ciberseguridad. Evalúa los hallazgos reportados y clasifícalos por orden de prioridad "
            "considerando la facilidad de explotación y el impacto en el negocio. Sé metódico y estructurado."
        )

        vuln_summary = []
        for v in vulnerabilities[:15]:  # limit context to top 15
            vuln_summary.append(
                f"- ID: {v.get('id', 'N/A')} | {v.get('title')} | Severidad: {v.get('severity')} | CVSS: {v.get('cvss_score', 'N/A')}"
            )

        prompt = f"""
Se han detectado los siguientes hallazgos durante la auditoría:

{chr(10).join(vuln_summary)}

Genera una matriz de priorización:
1. Urgencia Inmediata (Hotfixes recomendados en menos de 24h).
2. Prioridad Alta (Siguiente sprint de desarrollo).
3. Deuda Técnica y Buenas Prácticas.
"""
        return self.query(prompt, system_prompt=system_prompt, model=model)

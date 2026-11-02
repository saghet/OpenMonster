"""
Professional Cybersecurity Assessment HTML Report Generator.
Generates self-contained, interactive, enterprise-grade reports conforming to
executive and technical audit documentation standards.
"""

import html
import json
import time
from typing import Any, Dict, List, Optional


class HTMLReportGenerator:
    @staticmethod
    def generate(
        title: str,
        target_name: str,
        target_url: str,
        auditor_name: str,
        report_type: str,  # 'executive' or 'technical'
        vulnerabilities: List[Dict[str, Any]],
        tools_versions: Optional[Dict[str, str]] = None,
        scope_authorized: bool = True,
    ) -> str:
        if tools_versions is None:
            tools_versions = {
                "Platform": "SECMASTER-OpenMonster v1.0.0-GPL",
                "Desktop Core": "Tauri 2 / Rust 1.80+",
                "Analysis Engine": "Python 3.12+ Async Sandbox",
                "Integrity Model": "GPL-3.0 Attribution Preserved",
            }

        crit_count = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        med_count = sum(1 for v in vulnerabilities if v.get("severity") == "medium")
        low_count = sum(1 for v in vulnerabilities if v.get("severity") == "low")

        vuln_rows = ""
        for v in vulnerabilities:
            sev = v.get("severity", "medium").lower()
            color = "#ef4444" if sev == "critical" else "#f97316" if sev == "high" else "#eab308" if sev == "medium" else "#3b82f6"

            evidence_str = ""
            if report_type == "technical":
                raw_ev = v.get("evidence_json", "{}")
                if isinstance(raw_ev, str):
                    try:
                        raw_ev = json.loads(raw_ev)
                    except:
                        pass
                evidence_formatted = html.escape(json.dumps(raw_ev, indent=2))
                evidence_str = f"""
                <div class="technical-box">
                    <strong>Evidencia Técnica Reproducible:</strong>
                    <pre><code>{evidence_formatted}</code></pre>
                    <div class="mitigation-box">
                        <strong>Recomendación de Mitigación:</strong>
                        <p>{html.escape(v.get('remediation', 'Aplicar principios de codificación defensiva y sanitización estricta.'))}</p>
                    </div>
                </div>
                """

            vuln_rows += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div>
                        <span class="severity-badge" style="background: {color}20; color: {color}; border: 1px solid {color}40;">
                            {v.get('severity', 'MEDIUM').upper()}
                        </span>
                        <h3 class="finding-title">{html.escape(v.get('title', ''))}</h3>
                    </div>
                    <div class="finding-meta">
                        <span>CVSS: <strong>{v.get('cvss_score', 'N/A')}</strong></span>
                        <span>CWE: <strong>{html.escape(v.get('cwe', 'N/A'))}</strong></span>
                        <span>Confianza: <strong>{v.get('confidence', 80)}%</strong></span>
                    </div>
                </div>
                <p class="finding-desc">{html.escape(v.get('description', 'Sin descripción adicional.'))}</p>
                {evidence_str}
            </div>
            """

        generated_date = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)} - SECMASTER Audit Report</title>
    <style>
        :root {{
            --bg: #0a0d14;
            --card-bg: #111726;
            --border: #1f293d;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent: #00f0ff;
            --emerald: #10b981;
            --rose: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }}
        header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .brand-subtitle {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: var(--accent);
            font-weight: 700;
        }}
        h1 {{ font-size: 24px; font-weight: 800; margin-top: 4px; }}
        .meta-line {{ font-size: 12px; color: var(--text-muted); margin-top: 6px; }}
        section {{ margin-bottom: 36px; }}
        h2 {{
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--accent);
            margin-bottom: 14px;
            font-weight: 700;
        }}
        p {{ font-size: 13px; color: #cbd5e1; margin-bottom: 12px; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: #0d121f;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            text-align: center;
        }}
        .metric-num {{ font-size: 24px; font-weight: 800; font-family: monospace; }}
        .metric-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px 14px;
            border: 1px solid var(--border);
            text-align: left;
        }}
        th {{ background: #0d121f; color: var(--text-muted); font-weight: 600; }}
        td {{ background: #111726; }}
        .finding-card {{
            background: #0d121f;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }}
        .finding-title {{ font-size: 14px; font-weight: 700; color: #fff; margin-top: 4px; }}
        .finding-meta {{ font-size: 11px; font-family: monospace; color: var(--text-muted); display: flex; gap: 14px; }}
        .severity-badge {{
            display: inline-block;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 9999px;
            text-transform: uppercase;
            font-family: monospace;
        }}
        .finding-desc {{ font-size: 12px; color: #cbd5e1; margin-bottom: 12px; }}
        .technical-box {{
            background: #070a10;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            margin-top: 12px;
            font-size: 11px;
        }}
        pre {{
            background: #000;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
            margin-top: 6px;
            color: var(--accent);
            font-family: monospace;
        }}
        .mitigation-box {{
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.25);
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
            color: #d1fae5;
        }}
        .alert-box {{
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 8px;
            padding: 12px;
            font-size: 12px;
            color: #fef3c7;
            margin-bottom: 24px;
        }}
        footer {{
            border-top: 1px solid var(--border);
            padding-top: 20px;
            margin-top: 32px;
            font-size: 11px;
            color: var(--text-muted);
            display: flex;
            justify-content: space-between;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .container {{ box-shadow: none; border: none; padding: 0; max-width: 100%; }}
            .finding-card, .technical-box, .metric-card, td, th {{ background: #fff !important; color: #000 !important; border-color: #cbd5e1 !important; }}
            pre {{ background: #f8fafc !important; color: #000 !important; }}
            .mitigation-box {{ background: #f0fdf4 !important; color: #166534 !important; }}
            .alert-box {{ background: #fffbeb !important; color: #92400e !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <span class="brand-subtitle">SECMASTER-OpenMonster Enterprise Security</span>
                <h1>{html.escape(title)}</h1>
                <div class="meta-line">
                    <strong>Fecha de Emisión:</strong> {generated_date} | <strong>Tipo:</strong> {report_type.upper()}
                </div>
            </div>
            <div style="text-align: right; font-size: 11px; color: var(--text-muted);">
                <div>Auditor Responsable: <strong>{html.escape(auditor_name)}</strong></div>
                <div>Objetivo: <strong>{html.escape(target_name)}</strong></div>
            </div>
        </header>

        <div class="alert-box">
            <strong>Declaración de Transparencia:</strong> Este informe es válido exclusivamente para los activos autorizados especificados durante la ventana de tiempo de evaluación. No constituye una certificación de inmunidad absoluta ante ataques no contemplados en el alcance.
        </div>

        <!-- 1. Resumen Ejecutivo -->
        <section>
            <h2>1. Resumen Ejecutivo</h2>
            <p>
                Se ha llevado a cabo una evaluación de seguridad sobre el activo <strong>{html.escape(target_name)}</strong> ({html.escape(target_url)}) utilizando la plataforma de escritorio <strong>SECMASTER-OpenMonster</strong>. Durante las pruebas se evaluaron vectores web y configuraciones mediante análisis no destructivo y verificación diferencial.
            </p>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-num" style="color: var(--rose);">{crit_count}</div>
                    <div class="metric-label">Críticas</div>
                </div>
                <div class="metric-card">
                    <div class="metric-num" style="color: #f97316;">{high_count}</div>
                    <div class="metric-label">Altas</div>
                </div>
                <div class="metric-card">
                    <div class="metric-num" style="color: #eab308;">{med_count}</div>
                    <div class="metric-label">Medias</div>
                </div>
                <div class="metric-card">
                    <div class="metric-num" style="color: #3b82f6;">{low_count}</div>
                    <div class="metric-label">Bajas</div>
                </div>
            </div>
        </section>

        <!-- 2. Alcance Autorizado y Metodología -->
        <section>
            <h2>2. Alcance Autorizado y Metodología</h2>
            <table>
                <thead>
                    <tr>
                        <th>Activo Objetivo</th>
                        <th>Dirección / URL</th>
                        <th>Autorización de Alcance</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>{html.escape(target_name)}</td>
                        <td><code>{html.escape(target_url)}</code></td>
                        <td><span style="color: var(--emerald); font-weight: bold;">{'Autorizado Explícitamente' if scope_authorized else 'Modo Pasivo Restringido'}</span></td>
                    </tr>
                </tbody>
            </table>
            <p style="margin-top: 14px;">
                <strong>Metodología de Verificación Diferencial:</strong> Las pruebas se ejecutan comparando respuestas base contra sondas de inyección aleatorias para suprimir falsos positivos por eco en el DOM o números estáticos.
            </p>
        </section>

        <!-- 3. Herramientas y Versiones -->
        <section>
            <h2>3. Herramientas y Entorno de Ejecución</h2>
            <table>
                <thead>
                    <tr>
                        <th>Componente</th>
                        <th>Versión / Especificación</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f"<tr><td>{html.escape(k)}</td><td><code>{html.escape(v)}</code></td></tr>" for k, v in tools_versions.items())}
                </tbody>
            </table>
        </section>

        <!-- 4. Vulnerabilidades y Hallazgos -->
        <section>
            <h2>4. Vulnerabilidades y Hallazgos Encontrados ({len(vulnerabilities)})</h2>
            {vuln_rows if vuln_rows else '<p>No se identificaron vulnerabilidades durante esta evaluación.</p>'}
        </section>

        <!-- 5. Limitaciones y Conclusiones -->
        <section>
            <h2>5. Limitaciones y Conclusiones</h2>
            <p>
                <strong>Limitaciones:</strong> La evaluación no contempló ataques de Denegación de Servicio (DoS), ingeniería social sobre usuarios finales, ni pruebas físicas sobre centros de datos.
            </p>
            <p>
                <strong>Conclusiones:</strong> Se recomienda proceder de inmediato a la subsanación de los hallazgos críticos y altos detallados, aplicando las pautas de mitigación antes de la puesta en producción.
            </p>
        </section>

        <footer>
            <div>SECMASTER-OpenMonster | GPL-3.0 Licensed Platform</div>
            <div>Página 1 de 1</div>
        </footer>
    </div>
</body>
</html>
"""

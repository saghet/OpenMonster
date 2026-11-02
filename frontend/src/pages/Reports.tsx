import React, { useState } from 'react';
import {
  FileText,
  Printer,
  ShieldCheck,
  FileCode,
  FileSpreadsheet,
  AlertCircle,
  Globe
} from 'lucide-react';
import { Asset, Vulnerability } from '../types';

interface ReportsProps {
  assets: Asset[];
  vulnerabilities: Vulnerability[];
}

export const Reports: React.FC<ReportsProps> = ({ assets, vulnerabilities }) => {
  const [reportType, setReportType] = useState<'executive' | 'technical'>('executive');
  const [targetAssetId, setTargetAssetId] = useState<string>('all');

  const targetAsset = assets.find((a) => a.id === targetAssetId);
  const relevantVulns =
    targetAssetId === 'all'
      ? vulnerabilities
      : vulnerabilities.filter((v) => v.asset_id === targetAssetId);

  const handleDownloadJSON = () => {
    const reportData = {
      title: `SECMASTER Security Audit Report (${reportType.toUpperCase()})`,
      timestamp: new Date().toISOString(),
      report_type: reportType,
      authorized_scope: targetAsset
        ? [{ name: targetAsset.name, target: targetAsset.target, authorized: targetAsset.authorized }]
        : assets.map((a) => ({ name: a.name, target: a.target, authorized: a.authorized })),
      methodology: 'SECMASTER Differential Analysis & Non-Destructive Ethical Hacking Framework',
      tools_versions: {
        platform: 'SECMASTER-OpenMonster v1.0.0-GPL',
        desktop: 'Tauri 2 / Rust 1.80+',
        engine: 'Python 3.12+ Async Sandbox',
      },
      audit_limitations:
        'Auditoría limitada estrictamente a los activos autorizados. No incluye ataques de denegación de servicio (DoS) ni ingeniería social.',
      vulnerabilities: relevantVulns,
      conclusions:
        relevantVulns.length > 0
          ? `Se identificaron ${relevantVulns.length} vulnerabilidades que requieren atención prioritaria de acuerdo con las matrices de riesgo adjuntas.`
          : 'No se detectaron vulnerabilidades críticas durante la ventana de evaluación bajo el alcance probado.',
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sec-master-report-${reportType}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadCSV = () => {
    const headers = ['ID', 'Severidad', 'Titulo', 'Categoria', 'CWE', 'CVE', 'CVSS', 'Confianza', 'Estado'];
    const rows = relevantVulns.map((v) => [
      v.id,
      v.severity,
      `"${v.title.replace(/"/g, '""')}"`,
      `"${v.category}"`,
      v.cwe || 'N/A',
      v.cve || 'N/A',
      v.cvss_score || 'N/A',
      `${v.confidence}%`,
      v.status,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sec-master-findings-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadHTML = () => {
    const title = `SECMASTER Security Audit Report (${reportType.toUpperCase()})`;
    const targetDesc = targetAsset ? `${targetAsset.name} (${targetAsset.target})` : 'Todos los activos autorizados';
    const critCount = relevantVulns.filter(v => v.severity === 'critical').length;
    const highCount = relevantVulns.filter(v => v.severity === 'high').length;
    const medCount = relevantVulns.filter(v => v.severity === 'medium').length;
    const lowCount = relevantVulns.filter(v => v.severity === 'low').length;

    const findingsHtml = relevantVulns.map(v => {
      const color = v.severity === 'critical' ? '#ef4444' : v.severity === 'high' ? '#f97316' : v.severity === 'medium' ? '#eab308' : '#3b82f6';
      let evidenceBlock = '';
      if (reportType === 'technical') {
        let evFormatted = v.evidence_json;
        try {
          evFormatted = JSON.stringify(JSON.parse(v.evidence_json), null, 2);
        } catch {}
        evidenceBlock = `
          <div style="background:#070a10; padding:12px; border-radius:6px; margin-top:10px; font-family:monospace; font-size:11px; color:#00f0ff; overflow-x:auto;">
            <strong>Evidencia Reproducible:</strong>
            <pre style="margin:6px 0 0 0;">${evFormatted.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
          </div>
          <div style="background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.3); padding:10px; border-radius:6px; margin-top:10px; font-size:12px; color:#d1fae5;">
            <strong>Recomendación de Mitigación:</strong> ${v.remediation || 'Aplicar codificación defensiva y sanitización.'}
          </div>
        `;
      }
      return `
        <div style="background:#111726; border:1px solid #1f293d; border-radius:8px; padding:16px; margin-bottom:14px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; align-items:center; gap:8px;">
              <span style="background:${color}22; color:${color}; border:1px solid ${color}44; padding:2px 8px; border-radius:12px; font-size:10px; font-weight:bold; font-family:monospace; text-transform:uppercase;">${v.severity}</span>
              <strong style="color:#f1f5f9; font-size:14px;">${v.title}</strong>
            </div>
            <div style="font-size:11px; font-family:monospace; color:#94a3b8;">
              CVSS: <strong style="color:#fff;">${v.cvss_score || 'N/A'}</strong> | CWE: <strong style="color:#00f0ff;">${v.cwe || 'N/A'}</strong> | Confianza: ${v.confidence}%
            </div>
          </div>
          <p style="color:#94a3b8; font-size:12px; margin:8px 0 0 0; line-height:1.5;">${v.description || 'Sin descripción.'}</p>
          ${evidenceBlock}
        </div>
      `;
    }).join('\n');

    const htmlContent = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0a0d14; color: #f1f5f9; margin: 0; padding: 40px; }
    .container { max-width: 900px; margin: 0 auto; background: #0d121f; border: 1px solid #1f293d; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    .header { border-bottom: 1px solid #1f293d; padding-bottom: 20px; margin-bottom: 24px; display: flex; justify-content: space-between; }
    .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .card { background: #111726; border: 1px solid #1f293d; padding: 12px; border-radius: 8px; text-align: center; }
    .card .val { font-size: 20px; font-weight: bold; font-family: monospace; }
    .disclaimer { background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); color: #fcd34d; padding: 12px; border-radius: 8px; font-size: 12px; margin-bottom: 24px; }
    @media print { body { background: #fff; color: #000; padding: 0; } .container { border: none; box-shadow: none; max-width: 100%; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div style="font-size:10px; font-family:monospace; color:#00f0ff; letter-spacing:1px; font-weight:bold; text-transform:uppercase;">SECMASTER CYBERSECURITY AUDIT REPORT</div>
        <h1 style="font-size:20px; margin:6px 0 0 0; color:#fff;">${title}</h1>
        <p style="font-size:12px; color:#94a3b8; margin:4px 0 0 0;">Objetivo: <strong>${targetDesc}</strong></p>
      </div>
      <div style="font-size:11px; color:#94a3b8; text-align:right;">
        <div>Generado: ${new Date().toISOString()}</div>
        <div style="color:#00f0ff; margin-top:4px;">GPL-3.0 Attribution Preserved</div>
      </div>
    </div>
    <div class="metrics">
      <div class="card"><div style="font-size:10px; color:#ef4444;">CRÍTICAS</div><div class="val" style="color:#ef4444;">${critCount}</div></div>
      <div class="card"><div style="font-size:10px; color:#f97316;">ALTAS</div><div class="val" style="color:#f97316;">${highCount}</div></div>
      <div class="card"><div style="font-size:10px; color:#eab308;">MEDIAS</div><div class="val" style="color:#eab308;">${medCount}</div></div>
      <div class="card"><div style="font-size:10px; color:#3b82f6;">BAJAS</div><div class="val" style="color:#3b82f6;">${lowCount}</div></div>
    </div>
    <div class="disclaimer">
      <strong>Declaración de Alcance Autorizado:</strong> Este reporte refleja auditorías de seguridad realizadas bajo alcance explícito con metodología diferencial y no destructiva.
    </div>
    <h2 style="font-size:15px; margin-bottom:14px; color:#f1f5f9;">Hallazgos Identificados</h2>
    ${findingsHtml || '<p style="color:#94a3b8; font-size:12px;">No se identificaron vulnerabilidades para el alcance filtrado.</p>'}
  </div>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sec-master-report-${reportType}-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Configuration Header */}
      <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <FileText size={18} className="text-cyan-400" />
            Generador de Informes Profesionales de Ciberseguridad
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Exportación conforme a estándares ejecutivos y técnicos en PDF, HTML, JSON y CSV.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Target Filter Dropdown */}
          <select
            value={targetAssetId}
            onChange={(e) => setTargetAssetId(e.target.value)}
            className="bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-1.5 text-xs text-slate-200 outline-none"
          >
            <option value="all">Alcance: Todos los Activos</option>
            {assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>

          {/* Report Version Switcher */}
          <div className="flex bg-[#0d121f] p-1 rounded-lg border border-[#1f293d]">
            <button
              onClick={() => setReportType('executive')}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                reportType === 'executive'
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Ejecutivo
            </button>
            <button
              onClick={() => setReportType('technical')}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                reportType === 'technical'
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Técnico Detallado
            </button>
          </div>

          {/* Export Actions */}
          <button
            onClick={handleDownloadJSON}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#162032] border border-[#27354f] text-slate-300 hover:text-white text-xs font-medium"
            title="Exportar JSON"
          >
            <FileCode size={14} className="text-cyan-400" />
            JSON
          </button>
          <button
            onClick={handleDownloadCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#162032] border border-[#27354f] text-slate-300 hover:text-white text-xs font-medium"
            title="Exportar CSV"
          >
            <FileSpreadsheet size={14} className="text-emerald-400" />
            CSV
          </button>
          <button
            onClick={handleDownloadHTML}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#162032] border border-[#27354f] text-slate-300 hover:text-white text-xs font-medium"
            title="Exportar HTML Standalone"
          >
            <Globe size={14} className="text-cyan-400" />
            HTML
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold shadow-md shadow-cyan-950"
          >
            <Printer size={14} />
            Imprimir / Guardar PDF
          </button>
        </div>
      </div>

      {/* Mandatory Scope & Limitation Alert */}
      <div className="p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs flex items-center gap-2.5">
        <AlertCircle size={16} className="text-amber-400 shrink-0" />
        <span>
          <strong>Declaración de Transparencia:</strong> Este informe refleja únicamente el alcance evaluado durante las fechas registradas. Las auditorías parciales nunca deben interpretarse como una garantía de inmunidad total del sistema.
        </span>
      </div>

      {/* Interactive Report Preview Sheet */}
      <div className="bg-[#0b101c] border border-[#1f293d] rounded-2xl p-8 space-y-8 text-slate-200 max-w-4xl mx-auto shadow-2xl">
        {/* Document Header */}
        <div className="border-b border-[#1f293d] pb-6 flex items-start justify-between">
          <div>
            <span className="text-[10px] font-mono tracking-widest text-cyan-400 uppercase font-bold">
              INFORME DE AUDITORÍA DE SEGURIDAD
            </span>
            <h1 className="text-xl font-extrabold text-slate-100 mt-1">
              SECMASTER-OpenMonster Assessment Report
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Versión: {reportType === 'executive' ? 'Resumen Ejecutivo' : 'Auditoría Técnica Completa'} | Fecha: {new Date().toLocaleDateString()}
            </p>
          </div>
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400">
            <ShieldCheck size={32} />
          </div>
        </div>

        {/* 1. Resumen Ejecutivo */}
        <section className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
            1. Resumen Ejecutivo
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            Se ha realizado una evaluación formal de ciberseguridad sobre la infraestructura seleccionada utilizando la plataforma <strong className="text-slate-100">SECMASTER-OpenMonster</strong>. Durante el periodo de pruebas se aplicaron metodologías de análisis no destructivo, verificación diferencial y correlación de vectores de ataque.
          </p>
        </section>

        {/* 2. Alcance Autorizado y Activos */}
        <section className="space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
            2. Alcance Autorizado y Metodología
          </h2>
          <div className="overflow-hidden rounded-lg border border-[#1f293d]">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0d121f] text-slate-400">
                <tr>
                  <th className="py-2 px-3">Activo</th>
                  <th className="py-2 px-3">Objetivo</th>
                  <th className="py-2 px-3">Tipo</th>
                  <th className="py-2 px-3">Estado de Alcance</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1f293d] bg-[#111726]">
                {(targetAsset ? [targetAsset] : assets).map((a) => (
                  <tr key={a.id}>
                    <td className="py-2 px-3 font-semibold">{a.name}</td>
                    <td className="py-2 px-3 font-mono text-cyan-300">{a.target}</td>
                    <td className="py-2 px-3 uppercase text-[10px]">{a.asset_type}</td>
                    <td className="py-2 px-3">
                      {a.authorized ? (
                        <span className="text-emerald-400 font-medium">Autorizado Explícitamente</span>
                      ) : (
                        <span className="text-rose-400 font-medium">Modo Pasivo Restringido</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* 3. Vulnerabilidades Encontradas */}
        <section className="space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
            3. Vulnerabilidades y Hallazgos Técnicos ({relevantVulns.length})
          </h2>

          <div className="space-y-3">
            {relevantVulns.map((v) => (
              <div key={v.id} className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-slate-100">{v.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    {v.severity}
                  </span>
                </div>

                <p className="text-xs text-slate-300">{v.description}</p>

                {reportType === 'technical' && (
                  <div className="mt-2 pt-2 border-t border-[#1f293d] space-y-2">
                    <div className="text-[11px] font-mono text-slate-400">
                      <strong>CWE / CVE:</strong> {v.cwe || 'N/A'} | {v.cve || 'N/A'} | <strong>CVSS:</strong> {v.cvss_score || 'N/A'}
                    </div>
                    <div>
                      <span className="text-[10px] font-bold text-slate-400 uppercase">Evidencia Técnica:</span>
                      <pre className="p-2 rounded bg-black/50 font-mono text-[10px] text-cyan-300 overflow-x-auto mt-1">
                        {v.evidence_json}
                      </pre>
                    </div>
                    <div className="p-2.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 text-xs">
                      <strong>Recomendación de Mitigación:</strong> {v.remediation}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* 4. Conclusiones y Limitaciones */}
        <section className="space-y-2 pt-4 border-t border-[#1f293d]">
          <h2 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
            4. Limitaciones y Conclusiones
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            Las pruebas se ejecutaron respetando los acuerdos de nivel de servicio (SLA) y tasas máximas de peticiones para no afectar la disponibilidad. Se recomienda implementar las remediaciones descritas y programar una auditoría de re-evaluación (re-test) para certificar la subsanación de los hallazgos.
          </p>
        </section>
      </div>
    </div>
  );
};

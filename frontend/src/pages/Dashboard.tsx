import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertOctagon,
  CheckCircle2,
  FileSearch,
  ExternalLink,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { Asset, AuditLog, DashboardStats, ModuleId, Vulnerability } from '../types';

interface DashboardProps {
  stats: DashboardStats;
  assets: Asset[];
  vulnerabilities: Vulnerability[];
  auditLogs: AuditLog[];
  onNavigate: (module: ModuleId) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b',
};

export const Dashboard: React.FC<DashboardProps> = ({
  stats,
  assets: _assets,
  vulnerabilities,
  auditLogs,
  onNavigate,
}) => {
  const chartData = [
    { name: 'Crítico', count: stats.critical_vulns, color: SEVERITY_COLORS.critical },
    { name: 'Alto', count: stats.high_vulns, color: SEVERITY_COLORS.high },
    { name: 'Medio', count: stats.medium_vulns, color: SEVERITY_COLORS.medium },
    { name: 'Bajo', count: stats.low_vulns, color: SEVERITY_COLORS.low },
  ];

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Scope Warning Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/40 via-[#111c30] to-cyan-950/20 border border-cyan-500/30 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              Sistema de Auditoría Operacional Activo
            </h3>
            <p className="text-xs text-slate-400">
              Controles de alcance y verificación diferencial activados. Las pruebas activas requieren autorización explícita del activo objetivo.
            </p>
          </div>
        </div>
        <button
          onClick={() => onNavigate('asset-discovery')}
          className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-xs font-semibold border border-cyan-500/40 transition-colors"
        >
          Gestionar Alcance
        </button>
      </div>

      {/* Metrics Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Assets */}
        <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Activos en Registro</span>
            <span className="p-1.5 rounded-lg bg-blue-500/10 text-blue-400">
              <FileSearch size={16} />
            </span>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-slate-100">{stats.total_assets}</span>
            <span className="text-[11px] text-emerald-400 font-medium">
              {stats.authorized_assets} autorizados
            </span>
          </div>
        </div>

        {/* Active Scans */}
        <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Escaneos Activos</span>
            <span className="p-1.5 rounded-lg bg-amber-500/10 text-amber-400">
              <Activity size={16} />
            </span>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-slate-100">{stats.active_scans}</span>
            <span className="text-[11px] text-slate-400 font-mono">Concurrencia: OK</span>
          </div>
        </div>

        {/* Total Vulnerabilities */}
        <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Vulnerabilidades Detectadas</span>
            <span className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400">
              <ShieldAlert size={16} />
            </span>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {stats.total_vulnerabilities}
            </span>
            <span className="text-[11px] text-emerald-400 font-medium">
              {stats.verified_vulns} verificadas
            </span>
          </div>
        </div>

        {/* Critical Hallmarks */}
        <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Nivel Crítico & Alto</span>
            <span className="p-1.5 rounded-lg bg-red-500/10 text-red-400">
              <AlertOctagon size={16} />
            </span>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-rose-400">
              {stats.critical_vulns + stats.high_vulns}
            </span>
            <span className="text-[11px] text-rose-400 font-medium">Prioridad inmediata</span>
          </div>
        </div>
      </div>

      {/* Phase 2: Active Sessions and Scope Exclusions Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400">Sesiones de Auditoría Activas</span>
            <div className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
              <span>{stats.active_sessions || 0}</span>
              <span className="text-xs text-emerald-400 font-normal">en curso</span>
            </div>
          </div>
          <button
            onClick={() => onNavigate('audit-logs')}
            className="px-3 py-1.5 rounded-lg bg-[#162032] hover:bg-[#1e2d45] border border-[#27354f] text-cyan-300 text-xs font-medium"
          >
            Ver Sesiones
          </button>
        </div>

        <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400">Reglas de Exclusión de Alcance</span>
            <div className="text-xl font-bold font-mono text-slate-100 flex items-center gap-2">
              <span>{stats.total_exclusions || 0}</span>
              <span className="text-xs text-amber-400 font-normal">rutas protegidas</span>
            </div>
          </div>
          <button
            onClick={() => onNavigate('asset-discovery')}
            className="px-3 py-1.5 rounded-lg bg-[#162032] hover:bg-[#1e2d45] border border-[#27354f] text-amber-300 text-xs font-medium"
          >
            Configurar Exclusiones
          </button>
        </div>
      </div>

      {/* Charts & Real-Time Stream Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200">
              Distribución de Vulnerabilidades por Severidad
            </h3>
            <span className="text-xs text-slate-400">Filtrado diferencial</span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0d121f',
                    border: '1px solid #1f293d',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Audit Stream / Event Log */}
        <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200">Registro de Acciones</h3>
            <button
              onClick={() => onNavigate('audit-logs')}
              className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
            >
              Ver todo <ExternalLink size={12} />
            </button>
          </div>
          <div className="flex-1 overflow-y-auto space-y-3 pr-1 text-xs">
            {auditLogs.slice(0, 5).map((log) => (
              <div
                key={log.id}
                className="p-2.5 rounded-lg bg-[#0d121f] border border-[#1f293d] space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-cyan-400 font-semibold">{log.action}</span>
                  <span className="text-[10px] text-slate-400">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div className="text-slate-300 truncate">{log.target || 'Sistema'}</div>
                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span>Actor: {log.actor}</span>
                  <span className="text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 size={10} /> {log.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Vulnerabilities Table */}
      <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d]">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-200">
            Hallazgos Recientes y Evidencias Reproducibles
          </h3>
          <button
            onClick={() => onNavigate('vulnerability-management')}
            className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
          >
            Gestor completo <ExternalLink size={12} />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0d121f] text-slate-400 border-b border-[#1f293d]">
              <tr>
                <th className="py-2.5 px-3">Severidad</th>
                <th className="py-2.5 px-3">Título</th>
                <th className="py-2.5 px-3">Vector</th>
                <th className="py-2.5 px-3">CWE / CVE</th>
                <th className="py-2.5 px-3">Confianza</th>
                <th className="py-2.5 px-3">Verificado</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f293d]">
              {vulnerabilities.slice(0, 5).map((v) => (
                <tr key={v.id} className="hover:bg-[#162032] transition-colors">
                  <td className="py-2.5 px-3">
                    <span
                      className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase font-mono"
                      style={{
                        backgroundColor: `${SEVERITY_COLORS[v.severity]}20`,
                        color: SEVERITY_COLORS[v.severity],
                        border: `1px solid ${SEVERITY_COLORS[v.severity]}40`,
                      }}
                    >
                      {v.severity}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-medium text-slate-200">{v.title}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-400">{v.vector}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{v.cve || v.cwe || 'N/A'}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{v.confidence}%</td>
                  <td className="py-2.5 px-3">
                    {v.verified ? (
                      <span className="flex items-center gap-1 text-emerald-400 font-medium">
                        <CheckCircle2 size={12} /> Verificado
                      </span>
                    ) : (
                      <span className="text-slate-400">Heurístico</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

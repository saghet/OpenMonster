import React, { useState, useEffect } from 'react';
import {
  ScrollText,
  Search,
  CheckCircle2,
  XCircle,
  FileCode,
  FileSpreadsheet,
  Plus,
  Play,
  CheckSquare,
  Layers
} from 'lucide-react';
import { Asset, AuditLog, AuditSession } from '../types';
import { api } from '../services/api';

interface AuditLogsProps {
  logs: AuditLog[];
  assets: Asset[];
}

export const AuditLogs: React.FC<AuditLogsProps> = ({ logs, assets }) => {
  const [activeTab, setActiveTab] = useState<'trail' | 'sessions'>('trail');
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [sessions, setSessions] = useState<AuditSession[]>([]);

  // New session modal state
  const [showSessionModal, setShowSessionModal] = useState(false);
  const [sessionName, setSessionName] = useState('');
  const [sessionAssetId, setSessionAssetId] = useState('');
  const [auditorName, setAuditorName] = useState('');

  // Close session modal state
  const [closingSessionId, setClosingSessionId] = useState<string | null>(null);
  const [closingSummary, setClosingSummary] = useState('');

  const loadSessions = async () => {
    try {
      const list = await api.listAuditSessions();
      setSessions(list);
    } catch (err) {
      console.error('Failed to load audit sessions:', err);
    }
  };

  useEffect(() => {
    loadSessions();
  }, []);

  const filteredLogs = logs.filter((l) => {
    const matchesSearch =
      l.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (l.target && l.target.toLowerCase().includes(searchTerm.toLowerCase())) ||
      l.actor.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesAction = actionFilter === 'all' || l.action === actionFilter;
    return matchesSearch && matchesAction;
  });

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredLogs, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-logs-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportCSV = () => {
    const headers = ['Timestamp', 'Actor', 'Action', 'Target', 'Details', 'Status'];
    const rows = filteredLogs.map((l) => [
      `"${l.timestamp}"`,
      `"${l.actor}"`,
      `"${l.action}"`,
      `"${l.target || ''}"`,
      `"${l.details_json.replace(/"/g, '""')}"`,
      `"${l.status}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-logs-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCreateSession = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sessionName.trim() || !sessionAssetId || !auditorName.trim()) return;

    try {
      await api.createAuditSession(sessionName.trim(), sessionAssetId, auditorName.trim());
      setShowSessionModal(false);
      setSessionName('');
      setAuditorName('');
      await loadSessions();
    } catch (err) {
      console.error('Error creating audit session:', err);
    }
  };

  const handleCloseSession = async () => {
    if (!closingSessionId) return;
    try {
      await api.closeAuditSession(closingSessionId, closingSummary.trim() || 'Auditoría concluida formalmente.');
      setClosingSessionId(null);
      setClosingSummary('');
      await loadSessions();
    } catch (err) {
      console.error('Error closing session:', err);
    }
  };

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header Overview */}
      <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <ScrollText size={18} className="text-cyan-400" />
            Sistema Integral de Auditoría y Trazabilidad (Compliance & Sessions)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Bitácora criptográficamente trazable de cada acción operativa y gestor de sesiones de evaluación.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          {/* Tabs Switcher */}
          <div className="flex bg-[#0d121f] p-1 rounded-lg border border-[#1f293d]">
            <button
              onClick={() => setActiveTab('trail')}
              className={`px-3 py-1.5 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                activeTab === 'trail'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <ScrollText size={13} />
              Bitácora de Acciones
            </button>
            <button
              onClick={() => setActiveTab('sessions')}
              className={`px-3 py-1.5 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                activeTab === 'sessions'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Layers size={13} />
              Sesiones de Auditoría ({sessions.filter((s) => s.status === 'active').length})
            </button>
          </div>

          {activeTab === 'trail' && (
            <div className="flex items-center space-x-2">
              <button
                onClick={handleExportJSON}
                className="p-2 rounded-lg bg-[#162032] border border-[#27354f] text-slate-300 hover:text-white text-xs"
                title="Exportar Bitácora en JSON"
              >
                <FileCode size={15} />
              </button>
              <button
                onClick={handleExportCSV}
                className="p-2 rounded-lg bg-[#162032] border border-[#27354f] text-slate-300 hover:text-white text-xs"
                title="Exportar Bitácora en CSV"
              >
                <FileSpreadsheet size={15} />
              </button>
            </div>
          )}

          {activeTab === 'sessions' && (
            <button
              onClick={() => {
                if (assets.length > 0) setSessionAssetId(assets[0].id);
                setShowSessionModal(true);
              }}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold transition-all shadow-md shadow-cyan-950"
            >
              <Plus size={15} />
              Nueva Sesión
            </button>
          )}
        </div>
      </div>

      {/* Tab 1: Audit Trail (Bitácora de Acciones) */}
      {activeTab === 'trail' && (
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="relative w-full md:w-80">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Buscar por acción, actor u objetivo..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-[#111726] border border-[#1f293d] rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/50"
              />
            </div>

            <div className="flex flex-wrap items-center gap-1 bg-[#111726] p-1 rounded-lg border border-[#1f293d] text-xs">
              {[
                { id: 'all', label: 'Todas' },
                { id: 'AUTHORIZE_SCOPE', label: 'Autorizaciones' },
                { id: 'START_SCAN', label: 'Escaneos' },
                { id: 'CANCEL_SCAN', label: 'Cancelaciones' },
                { id: 'ADD_SCOPE_EXCLUSION', label: 'Exclusiones' },
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActionFilter(item.id)}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    actionFilter === item.id
                      ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-xl bg-[#111726] border border-[#1f293d] overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0d121f] text-slate-400 border-b border-[#1f293d]">
                  <tr>
                    <th className="py-3 px-4">Marca Temporal</th>
                    <th className="py-3 px-4">Actor</th>
                    <th className="py-3 px-4">Acción Realizada</th>
                    <th className="py-3 px-4">Objetivo / Activo</th>
                    <th className="py-3 px-4">Detalles (JSON)</th>
                    <th className="py-3 px-4">Estado</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1f293d]">
                  {filteredLogs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-400 font-sans">
                        No hay registros que coincidan con la búsqueda.
                      </td>
                    </tr>
                  ) : (
                    filteredLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-[#162032] transition-colors">
                        <td className="py-3 px-4 text-slate-400">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-cyan-300 font-bold">{log.actor}</td>
                        <td className="py-3 px-4 text-slate-100 font-bold">{log.action}</td>
                        <td className="py-3 px-4 text-slate-300 truncate max-w-xs">
                          {log.target || '-'}
                        </td>
                        <td className="py-3 px-4 text-slate-400 truncate max-w-sm">
                          {log.details_json}
                        </td>
                        <td className="py-3 px-4">
                          {log.status === 'SUCCESS' ? (
                            <span className="flex items-center gap-1 text-emerald-400">
                              <CheckCircle2 size={12} /> ÉXITO
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-rose-400">
                              <XCircle size={12} /> DENEGADO
                            </span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Audit Sessions (Sesiones de Auditoría Formal) */}
      {activeTab === 'sessions' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {sessions.map((sess) => {
              const asset = assets.find((a) => a.id === sess.asset_id);
              const isActive = sess.status === 'active';
              return (
                <div
                  key={sess.id}
                  className={`p-5 rounded-xl border flex flex-col justify-between space-y-4 transition-all ${
                    isActive
                      ? 'bg-[#111726] border-cyan-500/40 shadow-lg shadow-cyan-950/20'
                      : 'bg-[#0d121f] border-[#1f293d] opacity-80'
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span
                        className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded-full border ${
                          isActive
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {isActive ? '● En Curso' : '✓ Concluida'}
                      </span>
                      <span className="text-[11px] text-slate-400 font-mono">
                        {new Date(sess.start_time).toLocaleDateString()}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-slate-100">{sess.name}</h4>
                    <p className="text-xs text-slate-300 font-mono truncate">
                      Activo: {asset ? asset.name : sess.asset_id}
                    </p>

                    <div className="text-xs text-slate-400 space-y-1 pt-1 border-t border-[#1f293d]">
                      <div>
                        Auditor Responsable:{' '}
                        <strong className="text-slate-200">{sess.auditor_name}</strong>
                      </div>
                      {sess.summary && (
                        <p className="text-[11px] text-slate-400 italic bg-black/30 p-2 rounded">
                          "{sess.summary}"
                        </p>
                      )}
                    </div>
                  </div>

                  {isActive && (
                    <button
                      onClick={() => setClosingSessionId(sess.id)}
                      className="w-full flex items-center justify-center gap-1.5 py-2 rounded-lg bg-[#162032] hover:bg-[#1e2d45] border border-[#27354f] text-cyan-300 text-xs font-semibold transition-colors"
                    >
                      <CheckSquare size={14} />
                      Concluir y Firmar Cierre
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Start Session Modal */}
      {showSessionModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111726] border border-[#1f293d] rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Play size={18} className="text-cyan-400" />
              Iniciar Nueva Sesión Formal de Auditoría
            </h3>

            <form onSubmit={handleCreateSession} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Nombre o Código de la Sesión</label>
                <input
                  type="text"
                  placeholder="ej. Auditoría Trimestral Q4 - Staging"
                  value={sessionName}
                  onChange={(e) => setSessionName(e.target.value)}
                  className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Activo Objetivo</label>
                <select
                  value={sessionAssetId}
                  onChange={(e) => setSessionAssetId(e.target.value)}
                  className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                >
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.target})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Auditor Responsable / Firma</label>
                <input
                  type="text"
                  placeholder="ej. Jane Doe (OSCP / CISSP #4029)"
                  value={auditorName}
                  onChange={(e) => setAuditorName(e.target.value)}
                  className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                  required
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowSessionModal(false)}
                  className="px-4 py-2 rounded-lg bg-[#162032] text-slate-300 hover:bg-[#1e2d45]"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-semibold"
                >
                  Iniciar Sesión
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Close Session Modal */}
      {closingSessionId && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111726] border border-[#1f293d] rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <CheckSquare size={18} className="text-emerald-400" />
              Cierre y Firma Ejecutiva de Auditoría
            </h3>

            <div className="space-y-3 text-xs">
              <p className="text-slate-300">
                Al concluir la sesión, el estado cambiará a <strong>Archivada</strong> y se registrará la marca de tiempo de cierre en la bitácora inmutable.
              </p>

              <div>
                <label className="block text-slate-400 mb-1">Resumen Ejecutivo de Conclusión</label>
                <textarea
                  placeholder="ej. Evaluación técnica completada sin incidentes de disponibilidad."
                  value={closingSummary}
                  onChange={(e) => setClosingSummary(e.target.value)}
                  rows={3}
                  className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setClosingSessionId(null)}
                  className="px-4 py-2 rounded-lg bg-[#162032] text-slate-300 hover:bg-[#1e2d45]"
                >
                  Cancelar
                </button>
                <button
                  type="button"
                  onClick={handleCloseSession}
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black font-semibold"
                >
                  Firmar y Concluir
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

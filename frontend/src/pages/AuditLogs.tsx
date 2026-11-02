import React, { useState } from 'react';
import { ScrollText, Search, ShieldCheck, CheckCircle2, XCircle } from 'lucide-react';
import { AuditLog } from '../types';

interface AuditLogsProps {
  logs: AuditLog[];
}

export const AuditLogs: React.FC<AuditLogsProps> = ({ logs }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredLogs = logs.filter(
    (l) =>
      l.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (l.target && l.target.toLowerCase().includes(searchTerm.toLowerCase())) ||
      l.actor.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <ScrollText size={18} className="text-cyan-400" />
            Registro Inmutable de Auditoría y Trazabilidad de Acciones
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Bitácora de seguridad que registra cada cambio de alcance, inicio de pruebas y detenciones de emergencia.
          </p>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-mono">
          <ShieldCheck size={16} />
          <span>Integridad Local Garantizada</span>
        </div>
      </div>

      {/* Search */}
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

      {/* Logs Table */}
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
                    No hay registros de auditoría que coincidan con la búsqueda.
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
                    <td className="py-3 px-4 text-slate-300 truncate max-w-xs">{log.target || '-'}</td>
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
  );
};

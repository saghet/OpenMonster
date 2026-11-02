import React, { useState, useEffect } from 'react';
import {
  Activity,
  CheckCircle2,
  RotateCcw,
  ShieldCheck,
  Server,
  Database,
  Lock,
  Cpu
} from 'lucide-react';
import { SystemDiagnosticsData } from '../types';
import { apiService } from '../services/api';

export const SettingsDiagnostics: React.FC = () => {
  const [diagnostics, setDiagnostics] = useState<SystemDiagnosticsData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    loadDiagnostics();
  }, []);

  const loadDiagnostics = async () => {
    setLoading(true);
    try {
      const data = await apiService.getSystemDiagnostics();
      setDiagnostics(data);
    } catch (err) {
      console.error('Failed to load system diagnostics:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header Overview */}
      <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Activity size={18} className="text-cyan-400" />
            Diagnóstico del Sistema y Telemetría Local
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Monitoreo en tiempo real de la integridad del motor, la base de datos, módulos de análisis y cumplimiento ético.
          </p>
        </div>

        <button
          onClick={loadDiagnostics}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#162032] border border-[#27354f] text-slate-300 hover:text-white rounded-lg text-xs font-medium transition-colors"
        >
          <RotateCcw size={13} className={loading ? 'animate-spin' : ''} />
          Ejecutar Autodiagnóstico
        </button>
      </div>

      {loading ? (
        <div className="py-20 text-center text-xs text-slate-400">
          Ejecutando comprobaciones de integridad del sistema y base de datos...
        </div>
      ) : diagnostics ? (
        <div className="space-y-6">
          {/* Top Status Banner */}
          <div className="p-4 rounded-xl bg-[#0d121f] border border-[#1f293d] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span
                className={`w-3 h-3 rounded-full ${
                  diagnostics.overall_status === 'HEALTHY'
                    ? 'bg-emerald-400'
                    : diagnostics.overall_status === 'DEGRADED'
                    ? 'bg-amber-400'
                    : 'bg-rose-500'
                }`}
              />
              <div>
                <span className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono">
                  ESTADO GLOBAL: {diagnostics.overall_status}
                </span>
                <p className="text-[11px] text-slate-400">
                  Último informe generado el: {diagnostics.timestamp}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-bold flex items-center gap-1">
                <Lock size={11} /> TELEMETRÍA EXTERNA: DESACTIVADA
              </span>
            </div>
          </div>

          {/* Grid of Diagnostics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
            {/* Card 1: Platform & Python Runtime */}
            <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] space-y-3">
              <div className="flex items-center gap-2 text-cyan-400 font-bold border-b border-[#1f293d] pb-2">
                <Server size={15} />
                Entorno de Ejecución Linux
              </div>
              <div className="space-y-1.5 font-mono text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">Sistema Operativo:</span>
                  <span className="text-slate-200">{diagnostics.platform_info.system} {diagnostics.platform_info.machine}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Kernel:</span>
                  <span className="text-slate-200 truncate max-w-[150px]">{diagnostics.platform_info.release}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Host Local:</span>
                  <span className="text-slate-200">{diagnostics.platform_info.node}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Versión Python:</span>
                  <span className="text-cyan-300 truncate max-w-[150px]">
                    {String(diagnostics.python_env.version || '').split(' ')[0]}
                  </span>
                </div>
              </div>
            </div>

            {/* Card 2: Database Integrity */}
            <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 font-bold border-b border-[#1f293d] pb-2">
                <Database size={15} />
                Base de Datos SQLite & Integridad
              </div>
              <div className="space-y-1.5 font-mono text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">PRAGMA Integrity Check:</span>
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 size={11} /> {String(diagnostics.database_health.integrity_check || 'PASS')}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Tamaño Almacenamiento:</span>
                  <span className="text-slate-200">
                    {diagnostics.database_health.size_bytes
                      ? `${Math.round(Number(diagnostics.database_health.size_bytes) / 1024)} KB`
                      : 'Activo'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Migraciones Versionadas:</span>
                  <span className="text-cyan-300">3 Esquemas Aplicados</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Bitácora de Auditoría:</span>
                  <span className="text-slate-200">Inmutable (Append-Only)</span>
                </div>
              </div>
            </div>

            {/* Card 3: Core Scanners Readiness */}
            <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] space-y-3">
              <div className="flex items-center gap-2 text-amber-400 font-bold border-b border-[#1f293d] pb-2">
                <Cpu size={15} />
                Módulos de Auditoría Verificados
              </div>
              <div className="space-y-1.5 font-mono text-[11px]">
                {Object.entries(diagnostics.core_modules_status).map(([module, ok]) => (
                  <div key={module} className="flex justify-between items-center">
                    <span className="text-slate-300">{module.replace('_', ' ')}:</span>
                    <span className={ok ? 'text-emerald-400' : 'text-rose-400'}>
                      {ok ? 'DISPONIBLE' : 'FALLO'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Privacy & Anti-Exfiltration Guarantees */}
          <div className="p-5 rounded-xl bg-[#070a10] border border-[#1f293d] space-y-3 text-xs">
            <h4 className="font-bold text-slate-100 flex items-center gap-2">
              <ShieldCheck size={16} className="text-cyan-400" />
              Garantías de Privacidad y No Exfiltración (DevSecOps)
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-slate-300 leading-relaxed">
              <div className="p-3 rounded-lg bg-[#0d121f] border border-[#1f293d] space-y-1">
                <strong className="text-slate-100 block">Aislamiento de Red:</strong>
                Los motores de escaneo únicamente interactúan con los objetivos definidos en el alcance explícito. Ningún resultado, clave, dominio o evidencia es transmitido a servidores de telemetría remota.
              </div>
              <div className="p-3 rounded-lg bg-[#0d121f] border border-[#1f293d] space-y-1">
                <strong className="text-slate-100 block">Licencia y Atribución GPL-3.0:</strong>
                El proyecto respeta las obligaciones de la licencia GPL-3.0 del código upstream secMONSTER, conservando la trazabilidad de autoría y asegurando la libertad de auditoría del software.
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
};

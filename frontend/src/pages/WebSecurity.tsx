import React, { useState, useEffect } from 'react';
import {
  Globe,
  Play,
  Square,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Terminal,
  Activity,
  CheckCircle2
} from 'lucide-react';
import { Asset } from '../types';
import { api } from '../services/api';

interface WebSecurityProps {
  selectedAsset: Asset | null;
  onLaunchScan: (assetId: string, name: string, vectors: string[]) => Promise<void>;
  onCancelScan: () => void;
  isScanning: boolean;
}

export const WebSecurity: React.FC<WebSecurityProps> = ({
  selectedAsset,
  onLaunchScan,
  onCancelScan,
  isScanning,
}) => {
  const [selectedVectors, setSelectedVectors] = useState<string[]>([
    'xss',
    'sqli',
    'ssti',
    'openredirect',
  ]);
  const [rateLimit, setRateLimit] = useState<number>(20);
  const [logs, setLogs] = useState<string[]>([
    '[INIT] Motor de Seguridad Web cargado.',
    '[VERIF] Módulo diferencial activo: Eliminación de falsos positivos en SSTI/XSS habilitada.',
    '[SCOPE] Esperando confirmación de alcance del objetivo.',
  ]);

  useEffect(() => {
    let unlistenFn: (() => void) | undefined;
    api.onScanEvent((event: any) => {
      if (event.type === 'log') {
        const msg = event.data?.message || '';
        const level = event.data?.level || 'INFO';
        setLogs((prev) => [...prev, `[${level}] ${msg}`]);
      } else if (event.type === 'progress') {
        const pct = Math.round(event.data?.percent || 0);
        const task = event.data?.current_task || '';
        setLogs((prev) => [...prev, `[PROG ${pct}%] ${task}`]);
      } else if (event.type === 'finding') {
        const title = event.data?.title || '';
        const sev = (event.data?.severity || 'info').toUpperCase();
        setLogs((prev) => [...prev, `[VULN DETECTADA - ${sev}] ${title}`]);
      } else if (event.type === 'completed') {
        const total = event.data?.total_findings || 0;
        setLogs((prev) => [...prev, `[COMPLETED] Auditoría finalizada con ${total} hallazgos.`]);
      } else if (event.type === 'error') {
        const err = event.data?.message || '';
        setLogs((prev) => [...prev, `[ERROR] ${err}`]);
      }
    }).then((fn) => {
      unlistenFn = fn;
    });

    return () => {
      if (unlistenFn) unlistenFn();
    };
  }, []);

  const toggleVector = (v: string) => {
    setSelectedVectors((prev) =>
      prev.includes(v) ? prev.filter((item) => item !== v) : [...prev, v]
    );
  };

  const handleStart = async () => {
    if (!selectedAsset) return;
    if (!selectedAsset.authorized) {
      alert('Error de Alcance: El activo no cuenta con autorización explícita para auditoría activa.');
      return;
    }

    setLogs((prev) => [
      ...prev,
      `[LAUNCH] Iniciando auditoría diferencial sobre: ${selectedAsset.target}`,
      `[CONFIG] Vectores seleccionados: ${selectedVectors.join(', ')}`,
      `[RATE] Límite de velocidad: ${rateLimit} req/s`,
      '[INFO] Obteniendo respuesta base (baseline) para detección diferencial...',
      '[TEST] Validando reflexión contextual de payloads XSS sin sanitizar...',
      '[TEST] Evaluando inyección matemática dinámica SSTI (ej: {{14819*39182}})...',
    ]);

    await onLaunchScan(
      selectedAsset.id,
      `Auditoría Web: ${selectedAsset.name}`,
      selectedVectors
    );
  };

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Target & Authorization Status Header */}
      <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Globe size={18} className="text-cyan-400" />
            Auditoría de Vulnerabilidades Web (Differential Engine)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Evaluación técnica no destructiva con verificación estricta para eliminar falsos positivos.
          </p>
        </div>

        {selectedAsset ? (
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-xs font-semibold text-slate-200">{selectedAsset.name}</div>
              <div className="text-[11px] font-mono text-cyan-400">{selectedAsset.target}</div>
            </div>
            {selectedAsset.authorized ? (
              <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <ShieldCheck size={20} />
              </span>
            ) : (
              <span className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/30">
                <ShieldAlert size={20} />
              </span>
            )}
          </div>
        ) : (
          <div className="text-xs text-amber-400 flex items-center gap-1.5">
            <AlertTriangle size={15} />
            Selecciona un activo en la barra superior
          </div>
        )}
      </div>

      {/* Scope Warning if Unauthorized */}
      {selectedAsset && !selectedAsset.authorized && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-200 flex items-start space-x-3 text-xs">
          <ShieldAlert size={20} className="text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="font-bold text-rose-300">Activo Fuera de Alcance Autorizado</h4>
            <p className="text-rose-300/80">
              Este activo está registrado en modo pasivo. No se pueden ejecutar inyecciones ni pruebas activas hasta que un operador firme la autorización formal en la sección <strong>Asset Discovery</strong>.
            </p>
          </div>
        </div>
      )}

      {/* Vectors & Parameters Configuration Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Test Vectors */}
        <div className="lg:col-span-2 space-y-4">
          <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d] space-y-4">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Vectores de Prueba Disponibles (Verificados)
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {[
                {
                  id: 'xss',
                  name: 'Cross-Site Scripting (XSS)',
                  desc: 'Reflexión en DOM/Atributos sin sanitizar (no simple regex).',
                  level: 'Alto',
                },
                {
                  id: 'sqli',
                  name: 'SQL Injection (SQLi)',
                  desc: 'Diferencial booleano y análisis de desviación de latencia.',
                  level: 'Crítico',
                },
                {
                  id: 'ssti',
                  name: 'Server-Side Template Injection',
                  desc: 'Inyección matemática dinámica {{rnd1*rnd2}} computada.',
                  level: 'Crítico',
                },
                {
                  id: 'openredirect',
                  name: 'Open Redirect',
                  desc: 'Validación de redirecciones en cabeceras Location.',
                  level: 'Medio',
                },
                {
                  id: 'lfi',
                  name: 'Local File Inclusion (LFI)',
                  desc: 'Pruebas controladas de traversal sin divulgación de secretos.',
                  level: 'Alto',
                },
                {
                  id: 'crlf',
                  name: 'CRLF / Header Injection',
                  desc: 'Inyección de cabeceras de respuesta controladas.',
                  level: 'Medio',
                },
              ].map((vec) => {
                const isSelected = selectedVectors.includes(vec.id);
                return (
                  <div
                    key={vec.id}
                    onClick={() => toggleVector(vec.id)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-slate-100 shadow-sm'
                        : 'bg-[#0d121f] border-[#1f293d] text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold">{vec.name}</span>
                      <span
                        className={`text-[9px] px-1.5 py-0.5 rounded font-mono ${
                          vec.level === 'Crítico'
                            ? 'bg-rose-500/20 text-rose-300'
                            : vec.level === 'Alto'
                            ? 'bg-orange-500/20 text-orange-300'
                            : 'bg-amber-500/20 text-amber-300'
                        }`}
                      >
                        {vec.level}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 leading-snug">{vec.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Scan Controls & Concurrency */}
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d] space-y-4">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Límites y Controles de Seguridad
            </h4>

            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1">
                <span>Tasa Máxima de Peticiones</span>
                <span className="font-mono text-cyan-400 font-semibold">{rateLimit} req/s</span>
              </div>
              <input
                type="range"
                min={5}
                max={100}
                step={5}
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
                className="w-full accent-cyan-400"
              />
              <span className="text-[10px] text-slate-400">
                Evita saturación del servidor objetivo o activación de DoS.
              </span>
            </div>

            <div className="pt-2">
              {isScanning ? (
                <button
                  onClick={onCancelScan}
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs transition-colors shadow-lg shadow-rose-950"
                >
                  <Square size={15} />
                  Detener Escaneo
                </button>
              ) : (
                <button
                  onClick={handleStart}
                  disabled={!selectedAsset || !selectedAsset.authorized || selectedVectors.length === 0}
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-800 disabled:text-slate-400 text-black font-bold text-xs transition-all shadow-md shadow-cyan-950"
                >
                  <Play size={15} />
                  Iniciar Auditoría Web
                </button>
              )}
            </div>
          </div>

          {/* Real-time Status Card */}
          <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] space-y-2 text-xs">
            <div className="flex items-center justify-between text-slate-400">
              <span>Estado del Motor:</span>
              <span className="text-emerald-400 font-medium flex items-center gap-1">
                <CheckCircle2 size={12} /> Listo para pruebas
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span>Aislamiento de Procesos:</span>
              <span className="text-slate-300 font-mono">Sandbox Local</span>
            </div>
          </div>
        </div>
      </div>

      {/* Real-time Output Terminal / Console */}
      <div className="p-4 rounded-xl bg-[#090d16] border border-[#1f293d] space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-400 border-b border-[#1f293d] pb-2">
          <div className="flex items-center gap-2 font-mono">
            <Terminal size={14} className="text-cyan-400" />
            <span>Consola de Ejecución en Tiempo Real</span>
          </div>
          <span className="text-[10px] text-slate-400 font-mono">
            {isScanning ? 'TRANSMITIENDO EVENTOS' : 'EN ESPERA'}
          </span>
        </div>

        <div className="h-44 overflow-y-auto font-mono text-[11px] text-slate-300 space-y-1 p-2 bg-black/40 rounded-lg">
          {logs.map((log, idx) => (
            <div key={idx} className="leading-relaxed">
              <span className="text-cyan-400 select-none mr-2">&gt;</span>
              {log}
            </div>
          ))}
          {isScanning && (
            <div className="flex items-center gap-2 text-amber-400 animate-pulse">
              <Activity size={12} />
              <span>Ejecutando consultas de sondeo diferencial...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

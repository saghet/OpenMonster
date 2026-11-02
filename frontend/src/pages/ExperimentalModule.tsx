import React from 'react';
import { AlertTriangle, Clock, ShieldAlert, Cpu, CheckCircle2, ArrowRight } from 'lucide-react';
import { ModuleItem } from '../types';

interface ExperimentalModuleProps {
  module: ModuleItem;
}

export const ExperimentalModule: React.FC<ExperimentalModuleProps> = ({ module }) => {
  const isPending = module.status === 'pending';

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Status Hero Banner */}
      <div
        className={`p-6 rounded-2xl border ${
          isPending
            ? 'bg-slate-900/60 border-slate-700/60'
            : 'bg-amber-950/20 border-amber-500/30'
        } space-y-4`}
      >
        <div className="flex items-center space-x-3">
          <div
            className={`p-3 rounded-xl border ${
              isPending
                ? 'bg-slate-800 text-slate-400 border-slate-700'
                : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
            }`}
          >
            {isPending ? <Clock size={28} /> : <AlertTriangle size={28} />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-slate-100">{module.name}</h2>
              <span
                className={`text-[10px] uppercase font-bold font-mono px-2 py-0.5 rounded-full border ${
                  isPending
                    ? 'bg-slate-800 text-slate-400 border-slate-700'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                }`}
              >
                {isPending ? 'En Desarrollo (Pending)' : 'Experimental (No Terminado)'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">{module.description}</p>
          </div>
        </div>

        {/* Audit Transparency Note */}
        <div className="p-4 rounded-xl bg-black/40 border border-white/5 space-y-2 text-xs">
          <h4 className="font-semibold text-slate-200 flex items-center gap-2">
            <ShieldAlert size={15} className="text-amber-400" />
            Dictamen de la Auditoría Técnica (Garantía Antigravity)
          </h4>
          <p className="text-slate-300 leading-relaxed">
            En la auditoría forense del repositorio original <code>secMONSTER</code>, se comprobó que este módulo carecía de implementación funcional verificable o dependía de expresiones regulares ingenuas con tasas inaceptables de falsos positivos (por ejemplo, buscar cadenas de texto en respuestas sin conexión real con APIs o entornos de ejecución).
          </p>
          <p className="text-cyan-300 font-medium">
            En <strong>SECMASTER-OpenMonster</strong> se prohíbe simular resultados falsos. Este módulo permanecerá clasificado como experimental hasta que las pruebas unitarias y de integración contra servicios reales sean completadas en Fase 5.
          </p>
        </div>
      </div>

      {/* Technical Roadmap for this Module */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d] space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Cpu size={15} className="text-cyan-400" />
            Requisitos de Implementación Segura
          </h4>
          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-start gap-2">
              <CheckCircle2 size={14} className="text-emerald-400 shrink-0 mt-0.5" />
              <span>Aislamiento estricto de subprocesos con permisos mínimos de usuario.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 size={14} className="text-emerald-400 shrink-0 mt-0.5" />
              <span>Pruebas controladas sin ejecución arbitraria ni payloads destructivos.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 size={14} className="text-emerald-400 shrink-0 mt-0.5" />
              <span>Verificación de tokens y firmas sin falsos positivos por eco en cabeceras.</span>
            </li>
          </ul>
        </div>

        <div className="p-5 rounded-xl bg-[#111726] border border-[#1f293d] space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <ArrowRight size={15} className="text-cyan-400" />
            Siguientes Pasos Planificados (Fase 5)
          </h4>
          <div className="space-y-2 text-xs text-slate-400">
            <div className="p-2.5 rounded-lg bg-[#0d121f] border border-[#1f293d]">
              <strong className="text-slate-200">1. Desacoplamiento de SDKs:</strong> Integración de librerías oficiales para endpoints validados.
            </div>
            <div className="p-2.5 rounded-lg bg-[#0d121f] border border-[#1f293d]">
              <strong className="text-slate-200">2. Entornos Vulnerables Locales:</strong> Pruebas automatizadas en contenedores de prueba antes del despliegue.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

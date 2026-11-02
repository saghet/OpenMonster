import React from 'react';
import { ShieldCheck, ShieldAlert, Ban, Activity, RefreshCw } from 'lucide-react';
import { Asset, ModuleItem } from '../types';

interface HeaderProps {
  currentModule: ModuleItem;
  assets: Asset[];
  selectedAsset: Asset | null;
  onSelectAsset: (asset: Asset) => void;
  onEmergencyStop: () => void;
  onRefresh: () => void;
  isScanning: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  currentModule,
  assets,
  selectedAsset,
  onSelectAsset,
  onEmergencyStop,
  onRefresh,
  isScanning,
}) => {
  return (
    <header className="h-16 bg-[#0d121f] border-b border-[#1f293d] px-6 flex items-center justify-between">
      {/* Module Title and Description */}
      <div className="flex items-center space-x-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold text-slate-100">{currentModule.name}</h2>
            {currentModule.status === 'verified' && (
              <span className="text-[10px] bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full font-medium">
                Verified Engine
              </span>
            )}
            {currentModule.status === 'experimental' && (
              <span className="text-[10px] bg-amber-500/15 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded-full font-medium">
                Experimental Feature
              </span>
            )}
            {currentModule.status === 'pending' && (
              <span className="text-[10px] bg-slate-800 text-slate-400 border border-slate-700 px-2 py-0.5 rounded-full font-medium">
                Roadmap Spec
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400">{currentModule.description}</p>
        </div>
      </div>

      {/* Target Selector & Scope Enforcement */}
      <div className="flex items-center space-x-4">
        {/* Active Target Dropdown */}
        <div className="flex items-center bg-[#162032] border border-[#27354f] rounded-lg px-3 py-1.5 space-x-2">
          <span className="text-[11px] font-medium text-slate-400">Objetivo:</span>
          <select
            value={selectedAsset?.id || ''}
            onChange={(e) => {
              const found = assets.find((a) => a.id === e.target.value);
              if (found) onSelectAsset(found);
            }}
            aria-label="Seleccionar activo objetivo"
            className="bg-transparent text-xs text-slate-200 font-mono outline-none cursor-pointer"
          >
            {assets.length === 0 ? (
              <option value="">Sin activos registrados</option>
            ) : (
              assets.map((a) => (
                <option key={a.id} value={a.id} className="bg-[#0d121f] text-slate-200">
                  {a.name} ({a.target})
                </option>
              ))
            )}
          </select>
        </div>

        {/* Scope Authorization Status Indicator */}
        {selectedAsset && (
          <div
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium ${
              selectedAsset.authorized
                ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                : 'bg-rose-500/10 text-rose-300 border-rose-500/30'
            }`}
          >
            {selectedAsset.authorized ? (
              <>
                <ShieldCheck size={14} className="text-emerald-400" />
                <span>Alcance Autorizado</span>
              </>
            ) : (
              <>
                <ShieldAlert size={14} className="text-rose-400" />
                <span>Modo Pasivo Restringido</span>
              </>
            )}
          </div>
        )}

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          className="p-2 rounded-lg bg-[#162032] border border-[#27354f] text-slate-300 hover:text-white hover:bg-[#1e2d45] transition-colors"
          title="Actualizar datos"
        >
          <RefreshCw size={15} />
        </button>

        {/* Emergency Stop Button */}
        <button
          onClick={onEmergencyStop}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all ${
            isScanning
              ? 'bg-rose-600 hover:bg-rose-500 text-white border-rose-400 animate-pulse shadow-lg shadow-rose-950/50'
              : 'bg-rose-950/40 text-rose-300 border-rose-800/40 hover:bg-rose-900/60'
          }`}
        >
          <Ban size={14} />
          <span>Detención Inmediata</span>
        </button>

        {/* System Activity */}
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#111726] border border-[#1f293d] text-[11px] font-mono text-slate-400">
          <Activity size={12} className={isScanning ? 'text-amber-400 animate-spin' : 'text-emerald-400'} />
          <span>{isScanning ? 'ESCANEANDO' : 'LISTO'}</span>
        </div>
      </div>
    </header>
  );
};

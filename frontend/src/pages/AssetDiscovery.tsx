import React, { useState } from 'react';
import {
  Plus,
  ShieldCheck,
  Search,
  Globe,
  Server,
  Network,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import { Asset } from '../types';

interface AssetDiscoveryProps {
  assets: Asset[];
  onAddAsset: (name: string, target: string, assetType: 'domain' | 'ip' | 'url' | 'cidr', notes?: string) => Promise<void>;
  onToggleAuthorization: (id: string, currentStatus: boolean) => Promise<void>;
}

export const AssetDiscovery: React.FC<AssetDiscoveryProps> = ({
  assets,
  onAddAsset,
  onToggleAuthorization,
}) => {
  const [showModal, setShowModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');

  // Form states
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [assetType, setAssetType] = useState<'domain' | 'ip' | 'url' | 'cidr'>('url');
  const [notes, setNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const filteredAssets = assets.filter((a) => {
    const matchesSearch =
      a.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.target.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = selectedType === 'all' || a.asset_type === selectedType;
    return matchesSearch && matchesType;
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !target.trim()) {
      setErrorMsg('Nombre y objetivo son requeridos.');
      return;
    }
    setErrorMsg('');
    setSubmitting(true);
    try {
      await onAddAsset(name.trim(), target.trim(), assetType, notes.trim());
      setShowModal(false);
      setName('');
      setTarget('');
      setNotes('');
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Error al registrar activo');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Scope Policy Information */}
      <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex items-start justify-between">
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <ShieldCheck size={18} className="text-cyan-400" />
            Control de Alcance y Whitelisting Obligatorio
          </h3>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            De acuerdo con los estándares de Ethical Hacking, ningún escaneo activo puede iniciarse sin que el objetivo esté expresamente autorizado. Por defecto, los objetivos se registran en <strong className="text-slate-200">Modo Pasivo Restringido</strong>.
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold transition-all shadow-md shadow-cyan-950"
        >
          <Plus size={16} />
          Registrar Objetivo
        </button>
      </div>

      {/* Filters and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative w-full sm:w-80">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Buscar por nombre o dirección..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#111726] border border-[#1f293d] rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        <div className="flex items-center space-x-2">
          {['all', 'url', 'domain', 'ip', 'cidr'].map((t) => (
            <button
              key={t}
              onClick={() => setSelectedType(t)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                selectedType === t
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-[#111726] border border-[#1f293d] text-slate-400 hover:text-white'
              }`}
            >
              {t === 'all' ? 'Todos' : t.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Assets Table */}
      <div className="rounded-xl bg-[#111726] border border-[#1f293d] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0d121f] text-slate-400 border-b border-[#1f293d]">
              <tr>
                <th className="py-3 px-4">Tipo</th>
                <th className="py-3 px-4">Nombre del Activo</th>
                <th className="py-3 px-4">Objetivo / FQDN</th>
                <th className="py-3 px-4">Estado de Autorización</th>
                <th className="py-3 px-4">Auditor / Fecha</th>
                <th className="py-3 px-4 text-right">Acción de Alcance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f293d]">
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    No hay activos registrados en este filtro.
                  </td>
                </tr>
              ) : (
                filteredAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-[#162032] transition-colors">
                    <td className="py-3 px-4">
                      <span className="flex items-center gap-1.5 font-mono text-[11px] text-slate-300">
                        {asset.asset_type === 'url' && <Globe size={14} className="text-blue-400" />}
                        {asset.asset_type === 'domain' && <Server size={14} className="text-cyan-400" />}
                        {asset.asset_type === 'ip' && <Network size={14} className="text-purple-400" />}
                        {asset.asset_type === 'cidr' && <Network size={14} className="text-amber-400" />}
                        {asset.asset_type.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-100">{asset.name}</td>
                    <td className="py-3 px-4 font-mono text-cyan-300">{asset.target}</td>
                    <td className="py-3 px-4">
                      {asset.authorized ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          <CheckCircle size={11} /> Autorizado para Escaneo
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/30">
                          <XCircle size={11} /> Solo Pasivo
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {asset.authorized_by ? (
                        <div>
                          <div>{asset.authorized_by}</div>
                          <div className="text-[10px] text-slate-400">
                            {new Date(asset.authorized_at || '').toLocaleDateString()}
                          </div>
                        </div>
                      ) : (
                        <span className="text-slate-400 italic">No firmado</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onToggleAuthorization(asset.id, asset.authorized)}
                        className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${
                          asset.authorized
                            ? 'bg-rose-950/40 text-rose-300 border-rose-800/40 hover:bg-rose-900/60'
                            : 'bg-emerald-950/40 text-emerald-300 border-emerald-800/40 hover:bg-emerald-900/60'
                        }`}
                      >
                        {asset.authorized ? 'Revocar Alcance' : 'Firmar Autorización'}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Register Asset Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111726] border border-[#1f293d] rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Plus size={18} className="text-cyan-400" />
              Registrar Nuevo Activo Objetivo
            </h3>

            {errorMsg && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle size={15} />
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Nombre del Activo / Aplicación</label>
                <input
                  type="text"
                  placeholder="ej. Servidor de Facturación"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Tipo de Activo</label>
                <select
                  value={assetType}
                  onChange={(e) => setAssetType(e.target.value as 'domain' | 'ip' | 'url' | 'cidr')}
                  className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                >
                  <option value="url">URL Web (http/https)</option>
                  <option value="domain">Nombre de Dominio (FQDN)</option>
                  <option value="ip">Dirección IP Individual</option>
                  <option value="cidr">Rango de Red (CIDR)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Dirección / Objetivo</label>
                <input
                  type="text"
                  placeholder="ej. https://app.corp.local o 192.168.1.50"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-cyan-500/50"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Notas de Alcance y Reglas de Compromiso</label>
                <textarea
                  placeholder="ej. Autorizado únicamente en ventana nocturna."
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  rows={3}
                  className="w-full bg-[#0d121f] border border-[#1f293d] rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-lg bg-[#162032] text-slate-300 hover:bg-[#1e2d45]"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-semibold disabled:opacity-50"
                >
                  {submitting ? 'Guardando...' : 'Registrar Objetivo'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

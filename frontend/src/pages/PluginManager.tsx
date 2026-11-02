import React, { useState, useEffect } from 'react';
import {
  Puzzle,
  CheckCircle2,
  RotateCcw,
  Code2,
  FileCode,
  X,
  Lock,
  Layers
} from 'lucide-react';
import { PluginItem } from '../types';
import { apiService } from '../services/api';

export const PluginManager: React.FC = () => {
  const [plugins, setPlugins] = useState<PluginItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedPlugin, setSelectedPlugin] = useState<PluginItem | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [togglingId, setTogglingId] = useState<string | null>(null);

  useEffect(() => {
    loadPlugins();
  }, []);

  const loadPlugins = async () => {
    setLoading(true);
    try {
      const list = await apiService.listPlugins();
      setPlugins(list);
    } catch (err) {
      console.error('Failed to load plugins:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async (plugin: PluginItem) => {
    setTogglingId(plugin.plugin_id);
    const newStatus = !plugin.enabled;
    try {
      await apiService.togglePlugin(plugin.plugin_id, newStatus);
      setPlugins(plugins.map(p => p.plugin_id === plugin.plugin_id ? { ...p, enabled: newStatus } : p));
    } catch (err) {
      console.error('Failed to toggle plugin status:', err);
      alert('Error al modificar el estado del plugin: ' + String(err));
    } finally {
      setTogglingId(null);
    }
  };

  const categories = ['all', ...Array.from(new Set(plugins.map(p => p.category)))];
  const filteredPlugins = plugins.filter(
    p => categoryFilter === 'all' || p.category.toLowerCase() === categoryFilter.toLowerCase()
  );

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Overview Header */}
      <div className="p-4 rounded-xl bg-[#111726] border border-[#1f293d] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <Puzzle size={18} className="text-cyan-400" />
            Gestor de Plugins y Extensiones Modulares
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Arquitectura desacoplada con manifiestos JSON, verificación criptográfica SHA-256 y aislamiento de permisos.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadPlugins}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#162032] border border-[#27354f] text-slate-300 hover:text-white rounded-lg text-xs font-medium transition-colors"
          >
            <RotateCcw size={13} className={loading ? 'animate-spin' : ''} />
            Escanear Directorio
          </button>
        </div>
      </div>

      {/* Security Isolation Notice */}
      <div className="p-3.5 rounded-lg bg-[#070a10] border border-[#1f293d] flex items-center justify-between text-xs text-slate-300">
        <div className="flex items-center gap-2">
          <Lock size={15} className="text-cyan-400 shrink-0" />
          <span>
            <strong>Sandbox y Restricción de Alcance:</strong> Los plugins tienen estrictamente prohibido omitir los controles de autorización o ejecutar órdenes con privilegios root.
          </span>
        </div>
        <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-mono font-bold">
          SANDBOX ACTIVO
        </span>
      </div>

      {/* Categories Filter */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-400 flex items-center gap-1">
          <Layers size={13} /> Filtrar por categoría:
        </span>
        <div className="flex bg-[#111726] p-1 rounded-lg border border-[#1f293d]">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                categoryFilter === cat
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {cat === 'all' ? 'Todos los plugins' : cat}
            </button>
          ))}
        </div>
      </div>

      {/* Plugins Grid */}
      {loading ? (
        <div className="py-16 text-center text-xs text-slate-400">
          Descubriendo módulos y verificando firmas criptográficas...
        </div>
      ) : filteredPlugins.length === 0 ? (
        <div className="py-16 text-center text-xs text-slate-400 bg-[#111726] border border-[#1f293d] rounded-xl">
          No se encontraron plugins registrados para esta categoría.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredPlugins.map((plugin) => (
            <div
              key={plugin.plugin_id}
              className={`p-5 rounded-xl border transition-all ${
                plugin.enabled
                  ? 'bg-[#111726] border-[#1f293d] hover:border-cyan-500/40'
                  : 'bg-[#0d121f] border-[#162032] opacity-60'
              }`}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      v{plugin.version}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 bg-[#0d121f] px-2 py-0.5 rounded border border-[#1f293d]">
                      {plugin.license}
                    </span>
                    <span className="text-[10px] font-mono uppercase text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                      {plugin.risk_level}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-slate-100 mt-2">{plugin.name}</h4>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">{plugin.description}</p>
                </div>

                {/* Toggle switch */}
                <button
                  onClick={() => handleToggle(plugin)}
                  disabled={togglingId === plugin.plugin_id}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors cursor-pointer shrink-0 ml-4 ${
                    plugin.enabled ? 'bg-cyan-500' : 'bg-slate-700'
                  }`}
                  title={plugin.enabled ? 'Deshabilitar plugin' : 'Habilitar plugin'}
                >
                  <div
                    className={`bg-black w-4 h-4 rounded-full shadow-md transform transition-transform ${
                      plugin.enabled ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>

              {/* Permissions & Dependencies */}
              <div className="mt-4 pt-3 border-t border-[#1f293d] flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[10px] text-slate-400 font-mono">Permisos:</span>
                  {plugin.permissions.map((perm) => (
                    <span
                      key={perm}
                      className="text-[10px] font-mono bg-[#162032] text-slate-300 px-2 py-0.5 rounded border border-[#27354f]"
                    >
                      {perm}
                    </span>
                  ))}
                </div>

                <div className="flex items-center gap-2">
                  {plugin.integrity_hash && (
                    <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-mono" title={`SHA-256: ${plugin.integrity_hash}`}>
                      <CheckCircle2 size={11} /> Integridad OK
                    </span>
                  )}
                  <button
                    onClick={() => setSelectedPlugin(plugin)}
                    className="text-cyan-400 hover:text-cyan-300 text-xs font-medium flex items-center gap-1"
                  >
                    <FileCode size={12} /> Manifiesto
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Manifest Inspection Modal */}
      {selectedPlugin && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-xl bg-[#0d121f] border border-[#1f293d] rounded-2xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-start justify-between border-b border-[#1f293d] pb-3">
              <div>
                <h4 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Code2 size={16} className="text-cyan-400" />
                  Manifiesto de Plugin: {selectedPlugin.plugin_id}
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">Autor: {selectedPlugin.author} | Licencia: {selectedPlugin.license}</p>
              </div>
              <button
                onClick={() => setSelectedPlugin(null)}
                className="p-1 rounded-lg bg-[#162032] text-slate-400 hover:text-white"
              >
                <X size={16} />
              </button>
            </div>

            <div className="space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Huella SHA-256 del Entrypoint:</span>
              <div className="p-2 rounded bg-[#070a10] border border-[#1f293d] font-mono text-[11px] text-cyan-300 select-all">
                {selectedPlugin.integrity_hash || 'No calculada'}
              </div>
            </div>

            <pre className="p-4 rounded-xl bg-[#070a10] border border-[#1f293d] font-mono text-[11px] text-slate-200 overflow-x-auto max-h-80">
              {JSON.stringify(selectedPlugin, null, 2)}
            </pre>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedPlugin(null)}
                className="px-4 py-1.5 bg-[#162032] text-slate-200 hover:text-white text-xs font-semibold rounded-lg"
              >
                Cerrar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Radar,
  Globe,
  Layers,
  ShieldAlert,
  Server,
  Terminal,
  Play,
  Square,
  RefreshCw,
  Search,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Lock,
  Cpu,
  Database,
  ArrowRight,
  FileJson,
  FileSpreadsheet
} from 'lucide-react';
import {
  Asset,
  ReconScan,
  ReconSummary
} from '../types';
import { api } from '../services/api';

interface ReconnaissanceProps {
  selectedAsset: Asset | null;
  onRefreshGlobal?: () => void;
  onNavigateToAssetDiscovery?: () => void;
}

type ReconTab = 'subdomains' | 'dns' | 'technologies' | 'http_tls' | 'topology' | 'history';

export const Reconnaissance: React.FC<ReconnaissanceProps> = ({
  selectedAsset,
  onRefreshGlobal,
  onNavigateToAssetDiscovery
}) => {
  const [activeTab, setActiveTab] = useState<ReconTab>('subdomains');
  const [summary, setSummary] = useState<ReconSummary>({
    subdomains: [],
    dns_records: [],
    technologies: [],
    http_fingerprints: [],
  });
  const [scans, setScans] = useState<ReconScan[]>([]);
  const [activeScan, setActiveScan] = useState<ReconScan | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanMode, setScanMode] = useState<'all' | 'passive' | 'dns' | 'http' | 'tech'>('all');
  const [passiveOnly, setPassiveOnly] = useState(false);
  const [rateLimit, setRateLimit] = useState<number>(10);
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const [statusMessage, setStatusMessage] = useState<string>('Listo para iniciar reconocimiento');
  const [liveLogs, setLiveLogs] = useState<Array<{ timestamp: string; message: string; level: string }>>([]);
  const [showLogs, setShowLogs] = useState(false);

  // Search & Filter States
  const [subdomainSearch, setSubdomainSearch] = useState('');
  const [subdomainFilterLive, setSubdomainFilterLive] = useState<'all' | 'live' | 'unconfirmed'>('all');
  const [dnsTypeFilter, setDnsTypeFilter] = useState<string>('ALL');
  const [techCategoryFilter, setTechCategoryFilter] = useState<string>('ALL');
  const [importedSubdomains, setImportedSubdomains] = useState<Set<string>>(new Set());

  const handleImportSubdomain = async (sub: any) => {
    try {
      await api.createAsset(
        sub.subdomain,
        sub.subdomain,
        'domain',
        `Importado automáticamente desde Reconnaissance Engine (Origen: ${sub.source}, Confianza: ${sub.confidence}%)`
      );
      setImportedSubdomains((prev) => new Set(prev).add(sub.subdomain));
      onRefreshGlobal?.();
    } catch (err) {
      console.error('Failed to import subdomain as asset:', err);
    }
  };

  // Load summary and historical scans for the asset
  const loadData = useCallback(async () => {
    if (!selectedAsset) return;
    try {
      const [sum, scanList] = await Promise.all([
        api.getReconSummary(selectedAsset.id),
        api.listReconScans(selectedAsset.id),
      ]);
      setSummary(sum);
      setScans(scanList);

      const running = scanList.find((s) => s.status === 'running' || s.status === 'pending');
      if (running) {
        setIsScanning(true);
        setActiveScan(running);
      } else if (isScanning && !running) {
        setIsScanning(false);
        setActiveScan(null);
        setProgressPercent(100);
        setStatusMessage('Reconocimiento completado.');
        onRefreshGlobal?.();
      }
    } catch (err) {
      console.error('Error fetching recon data:', err);
    }
  }, [selectedAsset, isScanning, onRefreshGlobal]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Listen to Tauri real-time events via @tauri-apps/api/event if running inside desktop
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    const setupListener = async () => {
      if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
        try {
          const { listen } = await import('@tauri-apps/api/event');
          unlisten = await listen<any>('recon-event', (event) => {
            const payload = event.payload;
            if (!payload) return;

            const timeStr = new Date().toLocaleTimeString();
            if (payload.type === 'progress') {
              setProgressPercent(payload.data?.percent || 0);
              setStatusMessage(payload.data?.message || 'Procesando...');
            } else if (payload.type === 'log') {
              setLiveLogs((prev) => [
                ...prev.slice(-100),
                { timestamp: timeStr, message: payload.data?.message, level: payload.data?.level || 'INFO' },
              ]);
            } else if (payload.type === 'completed') {
              setIsScanning(false);
              setProgressPercent(100);
              setStatusMessage('Auditoría de superficie finalizada.');
              loadData();
            } else if (payload.type === 'error') {
              setStatusMessage(`Error: ${payload.data?.message}`);
              setIsScanning(false);
            }
          });
        } catch (e) {
          console.warn('Could not attach Tauri recon-event listener:', e);
        }
      }
    };
    setupListener();

    return () => {
      if (unlisten) unlisten();
    };
  }, [loadData]);

  // Launch Recon Scan
  const handleStartScan = async () => {
    if (!selectedAsset) return;
    try {
      setIsScanning(true);
      setProgressPercent(5);
      setStatusMessage('Iniciando proceso de reconocimiento...');
      setLiveLogs([]);

      const scan = await api.createReconScan({
        asset_id: selectedAsset.id,
        mode: scanMode,
        allowed_targets: selectedAsset.target,
        passive_only: passiveOnly,
        rate_limit: rateLimit,
      });

      setActiveScan(scan);
      await loadData();
    } catch (err: any) {
      console.error('Failed to launch recon scan:', err);
      setStatusMessage(`Fallo de inicio: ${err?.message || err}`);
      setIsScanning(false);
    }
  };

  // Emergency Stop Scan
  const handleStopScan = async () => {
    if (!activeScan) return;
    try {
      await api.cancelReconScan(activeScan.id);
      setIsScanning(false);
      setActiveScan(null);
      setStatusMessage('Proceso cancelado por el operador.');
      await loadData();
    } catch (err) {
      console.error('Failed to cancel recon scan:', err);
    }
  };

  // Filtered Subdomains
  const filteredSubdomains = useMemo(() => {
    return summary.subdomains.filter((sub) => {
      const matchesSearch =
        sub.subdomain.toLowerCase().includes(subdomainSearch.toLowerCase()) ||
        sub.ip_addresses.toLowerCase().includes(subdomainSearch.toLowerCase()) ||
        sub.source.toLowerCase().includes(subdomainSearch.toLowerCase());

      const matchesLive =
        subdomainFilterLive === 'all'
          ? true
          : subdomainFilterLive === 'live'
          ? sub.is_live
          : !sub.is_live;

      return matchesSearch && matchesLive;
    });
  }, [summary.subdomains, subdomainSearch, subdomainFilterLive]);

  // Filtered DNS Records
  const filteredDns = useMemo(() => {
    if (dnsTypeFilter === 'ALL') return summary.dns_records;
    return summary.dns_records.filter((d) => d.record_type.toUpperCase() === dnsTypeFilter);
  }, [summary.dns_records, dnsTypeFilter]);

  // Filtered Technologies
  const filteredTechs = useMemo(() => {
    if (techCategoryFilter === 'ALL') return summary.technologies;
    return summary.technologies.filter((t) => t.category === techCategoryFilter);
  }, [summary.technologies, techCategoryFilter]);

  // IP Clusters derived from DNS and subdomains
  const ipClusters = useMemo(() => {
    const clusters: Record<string, string[]> = {};
    for (const sub of summary.subdomains) {
      if (sub.ip_addresses) {
        const ips = sub.ip_addresses.replace(/[[\]"]/g, '').split(',');
        for (const rawIp of ips) {
          const ip = rawIp.trim();
          if (ip) {
            if (!clusters[ip]) clusters[ip] = [];
            if (!clusters[ip].includes(sub.subdomain)) clusters[ip].push(sub.subdomain);
          }
        }
      }
    }
    for (const d of summary.dns_records) {
      if (d.record_type === 'A' || d.record_type === 'AAAA') {
        const ip = d.record_value.trim();
        if (ip) {
          if (!clusters[ip]) clusters[ip] = [];
          if (!clusters[ip].includes(d.domain)) clusters[ip].push(d.domain);
        }
      }
    }
    return clusters;
  }, [summary.subdomains, summary.dns_records]);

  // Takeover Risk Candidates
  const takeoverCandidates = useMemo(() => {
    return summary.dns_records.filter((d) => d.is_takeover_risk);
  }, [summary.dns_records]);

  // Export JSON Report
  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(summary, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `recon_${selectedAsset?.name || 'target'}_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Export CSV of subdomains
  const handleExportCsv = () => {
    const headers = ['Subdomain', 'IP Addresses', 'Source', 'Confidence', 'Is Live', 'HTTP Status'];
    const rows = summary.subdomains.map((s) => [
      s.subdomain,
      `"${s.ip_addresses.replace(/"/g, '')}"`,
      `"${s.source}"`,
      s.confidence,
      s.is_live,
      s.http_status || 'N/A',
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `subdomains_${selectedAsset?.name || 'target'}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  if (!selectedAsset) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 text-center text-slate-400">
        <Radar size={48} className="text-cyan-500 mb-4 animate-pulse" />
        <h2 className="text-xl font-bold text-slate-200">Reconocimiento & Intelligence Engine</h2>
        <p className="max-w-md mt-2 text-sm text-slate-400">
          Por favor, selecciona un activo autorizado en el selector superior para iniciar la auditoría de superficie de ataque, DNS, cabeceras y tecnologías.
        </p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto space-y-6">
      {/* Target & Execution Controller Header */}
      <div className="bg-[#111622] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Radar size={22} className={isScanning ? 'animate-spin' : ''} />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl font-bold text-white tracking-tight">Reconocimiento de Superficie</h1>
                  <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Motor Verificado
                  </span>
                  <span className="px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300">
                    Objetivo: {selectedAsset.target}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 mt-0.5">
                  <p className="text-xs text-slate-400">
                    Descubrimiento pasivo de subdominios, resolución multirregistro DNS, fingerprinting tecnológico Wappalyzer e inspección TLS/HTTP.
                  </p>
                  {onNavigateToAssetDiscovery && (
                    <button
                      onClick={onNavigateToAssetDiscovery}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1 cursor-pointer shrink-0"
                    >
                      <span>Ver Catálogo de Activos</span>
                      <ArrowRight size={11} />
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Action Buttons & Mode Selector */}
          <div className="flex flex-wrap items-center gap-3">
            <select
              value={scanMode}
              onChange={(e) => setScanMode(e.target.value as any)}
              disabled={isScanning}
              className="bg-[#0d121d] border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 outline-none focus:border-cyan-500"
            >
              <option value="all">Modo Completo (All Engines)</option>
              <option value="passive">Solo Pasivo (CT Logs / OSINT)</option>
              <option value="dns">Inteligencia DNS & Takeover</option>
              <option value="http">Cabeceras HTTP & TLS X.509</option>
              <option value="tech">Tecnologías (Fingerprinting)</option>
            </select>

            <select
              value={rateLimit}
              onChange={(e) => setRateLimit(Number(e.target.value))}
              disabled={isScanning}
              className="bg-[#0d121d] border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-2 outline-none focus:border-cyan-500"
              title="Límite de velocidad / peticiones por segundo"
            >
              <option value={5}>5 req/s (Sigiloso)</option>
              <option value={10}>10 req/s (Estándar)</option>
              <option value={20}>20 req/s (Rápido)</option>
            </select>

            <label className="flex items-center gap-1.5 text-xs text-slate-300 select-none cursor-pointer">
              <input
                type="checkbox"
                checked={passiveOnly}
                onChange={(e) => setPassiveOnly(e.target.checked)}
                disabled={isScanning}
                className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0"
              />
              Estrictamente Pasivo
            </label>

            {!isScanning ? (
              <button
                onClick={handleStartScan}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg shadow-sm shadow-cyan-900/30 transition-all cursor-pointer"
              >
                <Play size={14} />
                Iniciar Reconocimiento
              </button>
            ) : (
              <button
                onClick={handleStopScan}
                className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-medium rounded-lg shadow-sm shadow-rose-900/30 transition-all cursor-pointer"
              >
                <Square size={14} />
                Detener Escaneo
              </button>
            )}

            <button
              onClick={loadData}
              title="Refrescar Datos"
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors cursor-pointer"
            >
              <RefreshCw size={15} />
            </button>

            {/* Export Dropdown */}
            <div className="flex items-center gap-1">
              <button
                onClick={handleExportJson}
                title="Exportar JSON"
                className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition-colors cursor-pointer"
              >
                <FileJson size={14} className="text-amber-400" />
                JSON
              </button>
              <button
                onClick={handleExportCsv}
                title="Exportar CSV Subdominios"
                className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg transition-colors cursor-pointer"
              >
                <FileSpreadsheet size={14} className="text-emerald-400" />
                CSV
              </button>
            </div>
          </div>
        </div>

        {/* Progress Bar & Telemetry Status */}
        {isScanning && (
          <div className="mt-4 pt-4 border-t border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium flex items-center gap-2">
                <span className="inline-block w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                {statusMessage}
              </span>
              <span className="text-cyan-400 font-mono font-bold">{progressPercent}%</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-1.5 transition-all duration-300 rounded-full"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* KPI Overview Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#111622] border border-slate-800/80 rounded-xl p-4 flex items-center gap-3">
          <div className="p-3 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Globe size={20} />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-medium">Subdominios</div>
            <div className="text-2xl font-bold text-white mt-0.5">{summary.subdomains.length}</div>
            <div className="text-[11px] text-emerald-400 font-medium">
              {summary.subdomains.filter((s) => s.is_live).length} activos en vivo
            </div>
          </div>
        </div>

        <div className="bg-[#111622] border border-slate-800/80 rounded-xl p-4 flex items-center gap-3">
          <div className="p-3 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Server size={20} />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-medium">Registros DNS</div>
            <div className="text-2xl font-bold text-white mt-0.5">{summary.dns_records.length}</div>
            <div className="text-[11px] text-slate-400 font-medium">
              {Object.keys(ipClusters).length} IPs identificadas
            </div>
          </div>
        </div>

        <div className="bg-[#111622] border border-slate-800/80 rounded-xl p-4 flex items-center gap-3">
          <div className="p-3 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Cpu size={20} />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-medium">Tecnologías</div>
            <div className="text-2xl font-bold text-white mt-0.5">{summary.technologies.length}</div>
            <div className="text-[11px] text-purple-400 font-medium">
              {summary.technologies.filter((t) => t.confidence === 'Confirmed').length} confirmadas
            </div>
          </div>
        </div>

        <div className="bg-[#111622] border border-slate-800/80 rounded-xl p-4 flex items-center gap-3">
          <div className={`p-3 rounded-lg border ${
            takeoverCandidates.length > 0
              ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
              : 'bg-slate-800/50 text-slate-400 border-slate-700/50'
          }`}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-medium">Alertas Takeover</div>
            <div className="text-2xl font-bold text-white mt-0.5">{takeoverCandidates.length}</div>
            <div className={`text-[11px] font-medium ${takeoverCandidates.length > 0 ? 'text-amber-400' : 'text-slate-500'}`}>
              {takeoverCandidates.length > 0 ? 'Requiere validación' : 'Sin vectores dangling'}
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800">
        <div className="flex space-x-1">
          {[
            { id: 'subdomains', label: `Subdominios (${summary.subdomains.length})`, icon: Globe },
            { id: 'dns', label: `Registros DNS (${summary.dns_records.length})`, icon: Server },
            { id: 'technologies', label: `Tecnologías (${summary.technologies.length})`, icon: Cpu },
            { id: 'http_tls', label: `Cabeceras & TLS (${summary.http_fingerprints.length})`, icon: Lock },
            { id: 'topology', label: `Topología & Clusters (${Object.keys(ipClusters).length})`, icon: Layers },
            { id: 'history', label: `Historial (${scans.length})`, icon: Database },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as ReconTab)}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer ${
                  isActive
                    ? 'border-cyan-500 text-cyan-400 bg-cyan-500/5'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <Icon size={15} />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Toggle Live Logs button */}
        <button
          onClick={() => setShowLogs(!showLogs)}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg transition-colors cursor-pointer ${
            showLogs ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal size={14} />
          Terminal de Eventos
        </button>
      </div>

      {/* Collapsible Live Terminal Log Box */}
      {showLogs && (
        <div className="bg-[#070a0f] border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 max-h-48 overflow-y-auto space-y-1">
          <div className="text-slate-500 text-[11px] border-b border-slate-800 pb-1 mb-2 flex items-center justify-between">
            <span>REGISTRO DE TELEMETRÍA EN TIEMPO REAL (JSON LINES)</span>
            <span>{liveLogs.length} eventos</span>
          </div>
          {liveLogs.length === 0 ? (
            <div className="text-slate-500 italic">Esperando eventos del orquestador...</div>
          ) : (
            liveLogs.map((log, idx) => (
              <div key={idx} className="flex gap-2">
                <span className="text-slate-500 select-none">{log.timestamp}</span>
                <span
                  className={`font-semibold ${
                    log.level === 'WARNING'
                      ? 'text-amber-400'
                      : log.level === 'ERROR'
                      ? 'text-rose-400'
                      : log.level === 'DEBUG'
                      ? 'text-slate-500'
                      : 'text-cyan-400'
                  }`}
                >
                  [{log.level}]
                </span>
                <span className="text-slate-300">{log.message}</span>
              </div>
            ))
          )}
        </div>
      )}

      {/* TAB CONTENT: 1. SUBDOMAINS */}
      {activeTab === 'subdomains' && (
        <div className="space-y-4">
          {/* Subdomain Search & Filter Bar */}
          <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-[#111622] p-3 rounded-lg border border-slate-800">
            <div className="relative flex-1 w-full">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={subdomainSearch}
                onChange={(e) => setSubdomainSearch(e.target.value)}
                placeholder="Buscar subdominio, IP o fuente..."
                className="w-full bg-[#0d121d] border border-slate-700/80 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Estado:</span>
              <select
                value={subdomainFilterLive}
                onChange={(e) => setSubdomainFilterLive(e.target.value as any)}
                className="bg-[#0d121d] border border-slate-700/80 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 outline-none focus:border-cyan-500"
              >
                <option value="all">Todos ({summary.subdomains.length})</option>
                <option value="live">Activos en Vivo ({summary.subdomains.filter((s) => s.is_live).length})</option>
                <option value="unconfirmed">Solo Pasivo ({summary.subdomains.filter((s) => !s.is_live).length})</option>
              </select>
            </div>
          </div>

          {/* Subdomains Table */}
          <div className="bg-[#111622] border border-slate-800 rounded-xl overflow-hidden shadow">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0d121d] text-slate-400 border-b border-slate-800 uppercase text-[10px] font-semibold">
                  <tr>
                    <th className="py-3 px-4">Subdominio</th>
                    <th className="py-3 px-4">Direcciones IP</th>
                    <th className="py-3 px-4">Estado</th>
                    <th className="py-3 px-4">HTTP</th>
                    <th className="py-3 px-4">Procedencia</th>
                    <th className="py-3 px-4">Confianza</th>
                    <th className="py-3 px-4 text-right">Acción</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredSubdomains.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500 italic">
                        No se encontraron subdominios con los criterios actuales.
                      </td>
                    </tr>
                  ) : (
                    filteredSubdomains.map((sub) => {
                      const ips = sub.ip_addresses ? sub.ip_addresses.replace(/[[\]"]/g, '').split(',').filter(Boolean) : [];
                      return (
                        <tr key={sub.id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3 px-4 font-semibold text-slate-200 flex items-center gap-2">
                            <span>{sub.subdomain}</span>
                            <a
                              href={`https://${sub.subdomain}`}
                              target="_blank"
                              rel="noreferrer"
                              className="text-slate-500 hover:text-cyan-400 transition-colors"
                              title="Abrir en navegador"
                            >
                              <ExternalLink size={12} />
                            </a>
                          </td>
                          <td className="py-3 px-4 text-slate-300">
                            {ips.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {ips.map((ip, i) => (
                                  <span key={i} className="px-1.5 py-0.5 rounded bg-slate-800 text-[11px] text-slate-300">
                                    {ip.trim()}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-slate-500 italic">No resuelta</span>
                            )}
                          </td>
                          <td className="py-3 px-4">
                            {sub.is_live ? (
                              <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-sans font-medium">
                                <CheckCircle2 size={13} /> Activo
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-[11px] text-slate-500 font-sans">
                                Pasivo (OSINT)
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-4">
                            {sub.http_status ? (
                              <span
                                className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                                  sub.http_status >= 200 && sub.http_status < 300
                                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                    : sub.http_status >= 300 && sub.http_status < 400
                                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                }`}
                              >
                                {sub.http_status}
                              </span>
                            ) : (
                              <span className="text-slate-500">-</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-slate-400 font-sans text-[11px]">{sub.source}</td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold text-[11px]">
                              {sub.confidence}%
                            </span>
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => handleImportSubdomain(sub)}
                              disabled={importedSubdomains.has(sub.subdomain)}
                              title={importedSubdomains.has(sub.subdomain) ? 'Ya importado como activo' : 'Registrar en Asset Discovery'}
                              className={`inline-flex items-center gap-1 px-2.5 py-1 text-[11px] rounded font-sans transition-colors cursor-pointer ${
                                importedSubdomains.has(sub.subdomain)
                                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                  : 'bg-slate-800 hover:bg-cyan-600 hover:text-white text-slate-300'
                              }`}
                            >
                              {importedSubdomains.has(sub.subdomain) ? (
                                <>
                                  <CheckCircle2 size={11} />
                                  <span>Importado</span>
                                </>
                              ) : (
                                <>
                                  <span>Importar</span>
                                  <ArrowRight size={11} />
                                </>
                              )}
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 2. DNS INTELLIGENCE */}
      {activeTab === 'dns' && (
        <div className="space-y-4">
          {/* DNSSEC Status & Filter Banner */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-[#111622] p-4 rounded-xl border border-slate-800">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                <Server size={18} />
              </div>
              <div>
                <div className="text-xs text-slate-400">DNSSEC Estado Criptográfico</div>
                <div className="text-sm font-bold text-white mt-0.5">
                  {summary.dns_records.find((d) => d.record_type === 'DNSSEC')?.record_value || 'No verificado'}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Tipo:</span>
              <div className="flex flex-wrap gap-1">
                {['ALL', 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR'].map((type) => (
                  <button
                    key={type}
                    onClick={() => setDnsTypeFilter(type)}
                    className={`px-2.5 py-1 text-[11px] rounded font-semibold transition-colors cursor-pointer ${
                      dnsTypeFilter === type
                        ? 'bg-cyan-500 text-white'
                        : 'bg-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* DNS Table */}
          <div className="bg-[#111622] border border-slate-800 rounded-xl overflow-hidden shadow">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0d121d] text-slate-400 border-b border-slate-800 uppercase text-[10px] font-semibold">
                <tr>
                  <th className="py-3 px-4">Dominio / Host</th>
                  <th className="py-3 px-4">Tipo</th>
                  <th className="py-3 px-4">Valor del Registro (RDATA)</th>
                  <th className="py-3 px-4">TTL</th>
                  <th className="py-3 px-4 text-right">Riesgo Takeover</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredDns.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 italic">
                      No hay registros DNS registrados para este filtro.
                    </td>
                  </tr>
                ) : (
                  filteredDns.map((dns) => (
                    <tr key={dns.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 text-slate-200 font-semibold">{dns.domain}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                            dns.record_type === 'A' || dns.record_type === 'AAAA'
                              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                              : dns.record_type === 'CNAME'
                              ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                              : dns.record_type === 'MX'
                              ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              : dns.record_type === 'DNSSEC'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {dns.record_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-md truncate" title={dns.record_value}>
                        {dns.record_value}
                      </td>
                      <td className="py-3 px-4 text-slate-400">{dns.ttl ? `${dns.ttl}s` : '-'}</td>
                      <td className="py-3 px-4 text-right">
                        {dns.is_takeover_risk ? (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[11px] font-sans font-bold cursor-help"
                            title={dns.takeover_reason || 'Riesgo de subdomain takeover detectado'}
                          >
                            <AlertTriangle size={12} />
                            Alerta Takeover
                          </span>
                        ) : (
                          <span className="text-slate-500 font-sans text-[11px]">Seguro</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 3. TECHNOLOGIES */}
      {activeTab === 'technologies' && (
        <div className="space-y-4">
          {/* Tech Filter */}
          <div className="flex items-center justify-between bg-[#111622] p-3 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-400">Filtrar por Categoría Tecnológica:</div>
            <select
              value={techCategoryFilter}
              onChange={(e) => setTechCategoryFilter(e.target.value)}
              className="bg-[#0d121d] border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 outline-none focus:border-cyan-500"
            >
              <option value="ALL">Todas las Categorías</option>
              <option value="Web Server">Servidores Web</option>
              <option value="Web Framework">Frameworks</option>
              <option value="CMS">CMS (Gestores de Contenido)</option>
              <option value="CDN">CDN & WAF</option>
              <option value="Programming Language">Lenguajes</option>
              <option value="JavaScript Library">Librerías JS</option>
            </select>
          </div>

          {/* Technologies Grid Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredTechs.length === 0 ? (
              <div className="col-span-full py-12 text-center text-slate-500 italic bg-[#111622] rounded-xl border border-slate-800">
                No se detectaron tecnologías con los filtros seleccionados.
              </div>
            ) : (
              filteredTechs.map((tech) => {
                let indicators: string[] = [];
                try {
                  indicators = JSON.parse(tech.matched_indicators_json);
                } catch {
                  indicators = [];
                }

                return (
                  <div
                    key={tech.id}
                    className="bg-[#111622] border border-slate-800 rounded-xl p-4 shadow flex flex-col justify-between hover:border-slate-700 transition-colors"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                          {tech.category}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            tech.confidence === 'Confirmed'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : tech.confidence === 'Probable'
                              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {tech.confidence}
                        </span>
                      </div>
                      <div className="text-lg font-bold text-white mt-1 flex items-baseline gap-2">
                        <span>{tech.name}</span>
                        {tech.version && (
                          <span className="text-xs font-mono font-normal text-cyan-400">
                            v{tech.version}
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono mt-1 truncate" title={tech.target_url}>
                        URL: {tech.target_url}
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-slate-800/80">
                      <div className="text-[10px] text-slate-500 font-semibold mb-1">INDICADORES DE COINCIDENCIA:</div>
                      <div className="flex flex-wrap gap-1">
                        {indicators.map((ind, i) => (
                          <span key={i} className="px-1.5 py-0.5 bg-slate-800 rounded text-[10px] font-mono text-slate-300">
                            {ind}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* TAB CONTENT: 4. HTTP & TLS FINGERPRINTS */}
      {activeTab === 'http_tls' && (
        <div className="space-y-4">
          {summary.http_fingerprints.length === 0 ? (
            <div className="py-12 text-center text-slate-500 italic bg-[#111622] rounded-xl border border-slate-800">
              No hay huellas HTTP/TLS recopiladas aún. Ejecuta un reconocimiento en modo Completo o HTTP.
            </div>
          ) : (
            summary.http_fingerprints.map((fp) => {
              let secHeaders: Record<string, string> = {};
              let cookies: any[] = [];
              try {
                secHeaders = JSON.parse(fp.security_headers_json);
              } catch {}
              try {
                cookies = JSON.parse(fp.cookies_json);
              } catch {}

              const isTlsExpiring = fp.tls_cert_days_left !== undefined && fp.tls_cert_days_left !== null && fp.tls_cert_days_left < 30;

              return (
                <div key={fp.id} className="bg-[#111622] border border-slate-800 rounded-xl p-5 shadow space-y-4">
                  {/* Endpoint Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-white font-mono">{fp.target_url}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-bold ${
                            fp.status_code >= 200 && fp.status_code < 300
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          }`}
                        >
                          HTTP {fp.status_code}
                        </span>
                      </div>
                      {fp.title && <div className="text-xs text-slate-400 mt-0.5">Título: "{fp.title}"</div>}
                    </div>
                    {fp.server_header && (
                      <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-mono text-xs">
                        Server: {fp.server_header}
                      </span>
                    )}
                  </div>

                  {/* TLS & X.509 Certificate Card */}
                  {fp.tls_version && (
                    <div className="bg-[#0d121d] border border-slate-800/80 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5">
                          <Lock size={13} />
                          Criptografía TLS / Certificado X.509
                        </span>
                        <span className="text-xs font-mono font-bold text-slate-300">{fp.tls_version}</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                        <div>
                          <span className="text-slate-500">Emisor (CA): </span>
                          <span className="text-slate-300 font-mono">{fp.tls_cert_issuer || 'N/A'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Cifrado: </span>
                          <span className="text-slate-300 font-mono">{fp.tls_cipher || 'N/A'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Validez restante: </span>
                          <span
                            className={`font-mono font-bold ${
                              isTlsExpiring ? 'text-rose-400' : 'text-emerald-400'
                            }`}
                          >
                            {fp.tls_cert_days_left !== null && fp.tls_cert_days_left !== undefined
                              ? `${fp.tls_cert_days_left} días`
                              : 'N/A'}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Security Headers & Cookies Breakdown */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div>
                      <div className="text-[11px] font-semibold text-slate-400 uppercase mb-2">
                        Cabeceras de Seguridad Detectadas:
                      </div>
                      <div className="space-y-1 font-mono">
                        {[
                          'content-security-policy',
                          'strict-transport-security',
                          'x-frame-options',
                          'x-content-type-options',
                          'referrer-policy',
                        ].map((h) => {
                          const val = secHeaders[h];
                          return (
                            <div key={h} className="flex items-center justify-between p-1.5 bg-slate-800/40 rounded">
                              <span className="text-slate-300">{h}</span>
                              {val ? (
                                <span className="text-emerald-400 flex items-center gap-1 font-sans text-[11px]">
                                  <CheckCircle2 size={12} /> Presente
                                </span>
                              ) : (
                                <span className="text-rose-400 flex items-center gap-1 font-sans text-[11px]">
                                  <XCircle size={12} /> Ausente
                                </span>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    <div>
                      <div className="text-[11px] font-semibold text-slate-400 uppercase mb-2">
                        Cookies Inspeccionadas ({cookies.length}):
                      </div>
                      {cookies.length === 0 ? (
                        <div className="text-slate-500 italic p-2 bg-slate-800/30 rounded">
                          No se transmitieron cookies en esta respuesta.
                        </div>
                      ) : (
                        <div className="space-y-1.5">
                          {cookies.map((c, i) => (
                            <div key={i} className="p-2 bg-slate-800/40 rounded flex items-center justify-between text-[11px]">
                              <span className="font-mono text-slate-200">{c.name}</span>
                              <div className="flex gap-1.5">
                                <span
                                  className={`px-1.5 py-0.2 rounded font-semibold ${
                                    c.secure ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                                  }`}
                                >
                                  Secure: {c.secure ? 'Sí' : 'No'}
                                </span>
                                <span
                                  className={`px-1.5 py-0.2 rounded font-semibold ${
                                    c.httponly ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'
                                  }`}
                                >
                                  HttpOnly: {c.httponly ? 'Sí' : 'No'}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* TAB CONTENT: 5. TOPOLOGY & CLUSTERS */}
      {activeTab === 'topology' && (
        <div className="space-y-4">
          <div className="bg-[#111622] border border-slate-800 rounded-xl p-5 shadow space-y-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Layers size={16} className="text-cyan-400" />
                Agrupación por Infraestructura Compartida (IP Clustering)
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Identifica subdominios y activos que comparten la misma dirección IP en el proveedor de alojamiento.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.keys(ipClusters).length === 0 ? (
                <div className="col-span-full py-8 text-center text-slate-500 italic">
                  No se ha establecido correlación de clusters de IP aún.
                </div>
              ) : (
                Object.entries(ipClusters).map(([ip, domains]) => (
                  <div key={ip} className="bg-[#0d121d] border border-slate-800 rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-cyan-400">{ip}</span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 font-semibold">
                        {domains.length} host(s)
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {domains.map((dom, i) => (
                        <span key={i} className="px-2 py-1 bg-slate-800/80 rounded text-xs font-mono text-slate-200">
                          {dom}
                        </span>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 6. HISTORY */}
      {activeTab === 'history' && (
        <div className="bg-[#111622] border border-slate-800 rounded-xl overflow-hidden shadow">
          <div className="p-4 border-b border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Database size={16} className="text-cyan-400" />
              Historial de Auditorías de Reconocimiento
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Registro histórico de escaneos de superficie de ataque realizados sobre este objetivo.
            </p>
          </div>

          <table className="w-full text-left text-xs">
            <thead className="bg-[#0d121d] text-slate-400 border-b border-slate-800 uppercase text-[10px] font-semibold">
              <tr>
                <th className="py-3 px-4">ID de Sesión</th>
                <th className="py-3 px-4">Modo</th>
                <th className="py-3 px-4">Estado</th>
                <th className="py-3 px-4">Subdominios</th>
                <th className="py-3 px-4">Registros DNS</th>
                <th className="py-3 px-4">Tecnologías</th>
                <th className="py-3 px-4 text-right">Fecha</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {scans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 italic">
                    No se han registrado auditorías previas para este activo.
                  </td>
                </tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 text-slate-300 font-bold">{s.id.slice(0, 8)}...</td>
                    <td className="py-3 px-4 uppercase text-[11px] font-sans font-semibold text-cyan-400">{s.mode}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-sans font-bold ${
                          s.status === 'completed'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : s.status === 'running'
                            ? 'bg-cyan-500/10 text-cyan-400'
                            : s.status === 'cancelled'
                            ? 'bg-slate-700 text-slate-300'
                            : 'bg-rose-500/10 text-rose-400'
                        }`}
                      >
                        {s.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-200">{s.subdomains_count}</td>
                    <td className="py-3 px-4 text-slate-200">{s.dns_records_count}</td>
                    <td className="py-3 px-4 text-slate-200">{s.technologies_count}</td>
                    <td className="py-3 px-4 text-right text-slate-400 font-sans text-[11px]">
                      {new Date(s.started_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

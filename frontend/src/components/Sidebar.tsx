import React from 'react';
import {
  LayoutDashboard,
  Compass,
  Radar,
  Globe,
  Network,
  Syringe,
  Cloud,
  Box,
  Server,
  KeyRound,
  Bot,
  ShieldAlert,
  FileText,
  Puzzle,
  Settings,
  ScrollText,
  ShieldCheck,
  AlertTriangle,
  Clock
} from 'lucide-react';
import { ModuleId, ModuleItem } from '../types';

interface SidebarProps {
  activeModule: ModuleId;
  onSelectModule: (module: ModuleId) => void;
}

export const MODULES: ModuleItem[] = [
  // CORE & ASSETS
  { id: 'dashboard', name: 'Dashboard', category: 'core', status: 'verified', description: 'Central security posture overview and metrics' },
  { id: 'asset-discovery', name: 'Asset Discovery', category: 'core', status: 'verified', description: 'Scope whitelisting & target asset registry' },
  { id: 'reconnaissance', name: 'Reconocimiento', category: 'core', status: 'verified', description: 'Passive DNS, headers & tech fingerprinting' },

  // AUDIT & SCANNERS (VERIFIED / OPERATIONAL)
  { id: 'web-security', name: 'Web Security', category: 'scanners', status: 'verified', description: 'Differential XSS, SQLi, SSTI, LFI & OpenRedirect' },
  { id: 'api-security', name: 'API Security', category: 'scanners', status: 'experimental', description: 'REST & GraphQL schema introspection audits' },
  { id: 'injection-testing', name: 'Injection Testing', category: 'scanners', status: 'verified', description: 'Non-destructive parameter fuzzing & headers' },
  { id: 'auth-testing', name: 'Authentication Testing', category: 'scanners', status: 'experimental', description: 'JWT signature confusion & header bypass tests' },

  // INFRASTRUCTURE & EMERGING (EXPERIMENTAL / ROADMAP)
  { id: 'cloud-security', name: 'Cloud Security', category: 'infrastructure', status: 'experimental', description: 'Metadata service exposure (AWS, GCP, Azure)' },
  { id: 'container-security', name: 'Container Security', category: 'infrastructure', status: 'pending', description: 'Docker socket exposure & image misconfigurations' },
  { id: 'kubernetes-security', name: 'Kubernetes Security', category: 'infrastructure', status: 'pending', description: 'API secrets exposure & RBAC evaluation' },
  { id: 'ai-security', name: 'AI Security', category: 'infrastructure', status: 'experimental', description: 'Prompt injection & insecure output detection' },

  // GOVERNANCE & REMEDIATION
  { id: 'vulnerability-management', name: 'Vulnerability Mgmt', category: 'governance', status: 'verified', description: 'CVE/CWE mapping, deduplication & remediation' },
  { id: 'reports', name: 'Reports', category: 'governance', status: 'verified', description: 'Executive & technical PDF/HTML/JSON reports' },
  { id: 'plugin-manager', name: 'Plugin Manager', category: 'governance', status: 'verified', description: 'Extensible isolated scanner plugin runtime' },
  { id: 'audit-logs', name: 'Audit Logs', category: 'governance', status: 'verified', description: 'Immutable trail of operator actions & scope checks' },
  { id: 'settings', name: 'Settings', category: 'governance', status: 'verified', description: 'Engine concurrency, timeouts & safety thresholds' },
];

const ICONS: Record<ModuleId, React.ReactNode> = {
  'dashboard': <LayoutDashboard size={18} />,
  'asset-discovery': <Compass size={18} />,
  'reconnaissance': <Radar size={18} />,
  'web-security': <Globe size={18} />,
  'api-security': <Network size={18} />,
  'injection-testing': <Syringe size={18} />,
  'cloud-security': <Cloud size={18} />,
  'container-security': <Box size={18} />,
  'kubernetes-security': <Server size={18} />,
  'auth-testing': <KeyRound size={18} />,
  'ai-security': <Bot size={18} />,
  'vulnerability-management': <ShieldAlert size={18} />,
  'reports': <FileText size={18} />,
  'plugin-manager': <Puzzle size={18} />,
  'settings': <Settings size={18} />,
  'audit-logs': <ScrollText size={18} />,
};

export const Sidebar: React.FC<SidebarProps> = ({ activeModule, onSelectModule }) => {
  return (
    <aside className="w-72 bg-[#0d121f] border-r border-[#1f293d] flex flex-col h-screen select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-[#1f293d] flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <ShieldCheck size={24} />
          </div>
          <div>
            <h1 className="font-bold text-sm tracking-wide text-slate-100 flex items-center gap-1.5">
              SECMASTER
              <span className="text-[10px] bg-cyan-950 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-800">
                Linux
              </span>
            </h1>
            <p className="text-[11px] text-slate-400">OpenMonster Enterprise Core</p>
          </div>
        </div>
      </div>

      {/* Module Navigation List */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        <div className="px-2 pb-1.5 text-[10px] font-semibold tracking-wider text-slate-400 uppercase">
          Plataforma de Auditoría
        </div>

        {MODULES.map((mod) => {
          const isActive = activeModule === mod.id;
          return (
            <button
              key={mod.id}
              onClick={() => onSelectModule(mod.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-300 hover:bg-[#162032] hover:text-white'
              }`}
            >
              <div className="flex items-center space-x-2.5 truncate">
                <span className={isActive ? 'text-cyan-400' : 'text-slate-400'}>
                  {ICONS[mod.id]}
                </span>
                <span className="truncate">{mod.name}</span>
              </div>

              {/* Status Badges */}
              {mod.status === 'experimental' && (
                <span className="flex items-center gap-1 text-[9px] bg-amber-500/15 text-amber-300 border border-amber-500/30 px-1.5 py-0.5 rounded font-mono">
                  <AlertTriangle size={10} />
                  EXP
                </span>
              )}
              {mod.status === 'pending' && (
                <span className="flex items-center gap-1 text-[9px] bg-slate-800 text-slate-400 border border-slate-700 px-1.5 py-0.5 rounded font-mono">
                  <Clock size={10} />
                  DEV
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom Safety Status */}
      <div className="p-3 border-t border-[#1f293d] bg-[#0a0e17]">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Motor Local Seguro
          </span>
          <span className="font-mono text-[10px] text-slate-400">v1.0.0-GPL</span>
        </div>
      </div>
    </aside>
  );
};

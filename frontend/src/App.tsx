import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, MODULES } from './components/Sidebar';
import { Header } from './components/Header';
import { Dashboard } from './pages/Dashboard';
import { AssetDiscovery } from './pages/AssetDiscovery';
import { WebSecurity } from './pages/WebSecurity';
import { VulnerabilityManagement } from './pages/VulnerabilityManagement';
import { Reports } from './pages/Reports';
import { AuditLogs } from './pages/AuditLogs';
import { ExperimentalModule } from './pages/ExperimentalModule';
import { Asset, AuditLog, DashboardStats, ModuleId, Vulnerability } from './types';
import { api } from './services/api';

export const App: React.FC = () => {
  const [activeModule, setActiveModule] = useState<ModuleId>('dashboard');
  const [stats, setStats] = useState<DashboardStats>({
    total_assets: 0,
    authorized_assets: 0,
    active_scans: 0,
    total_vulnerabilities: 0,
    critical_vulns: 0,
    high_vulns: 0,
    medium_vulns: 0,
    low_vulns: 0,
    verified_vulns: 0,
  });
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [s, a, v, l] = await Promise.all([
        api.getDashboardStats(),
        api.getAssets(),
        api.getVulnerabilities(),
        api.getAuditLogs(),
      ]);
      setStats(s);
      setAssets(a);
      setVulnerabilities(v);
      setAuditLogs(l);

      if (!selectedAsset && a.length > 0) {
        setSelectedAsset(a[0]);
      } else if (selectedAsset) {
        const updated = a.find((item) => item.id === selectedAsset.id);
        if (updated) setSelectedAsset(updated);
      }
    } catch (err) {
      console.error('Failed to load SECMASTER state:', err);
    }
  }, [selectedAsset]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleAddAsset = async (
    name: string,
    target: string,
    assetType: 'domain' | 'ip' | 'url' | 'cidr',
    notes?: string
  ) => {
    const newAsset = await api.createAsset(name, target, assetType, notes);
    await loadData();
    setSelectedAsset(newAsset);
  };

  const handleToggleAuthorization = async (id: string, currentStatus: boolean) => {
    await api.authorizeAsset(id, !currentStatus, 'Lead Security Auditor (SEC-01)');
    await loadData();
  };

  const handleLaunchScan = async (_assetId: string, _name: string, _vectors: string[]) => {
    setIsScanning(true);
    try {
      // In web fallback, simulate scan progress
      setActiveScanId(`scn-${Date.now()}`);
      setTimeout(async () => {
        setIsScanning(false);
        setActiveScanId(null);
        await loadData();
      }, 3500);
    } catch (err) {
      console.error('Error starting scan:', err);
      setIsScanning(false);
    }
  };

  const handleEmergencyStop = async () => {
    if (activeScanId) {
      await api.cancelScan(activeScanId);
    }
    setIsScanning(false);
    setActiveScanId(null);
    await loadData();
  };

  const currentModuleItem = MODULES.find((m) => m.id === activeModule) || MODULES[0];

  return (
    <div className="flex h-screen bg-[#0a0d14] text-slate-100 antialiased overflow-hidden select-none">
      {/* Sidebar Navigation */}
      <Sidebar activeModule={activeModule} onSelectModule={setActiveModule} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Header
          currentModule={currentModuleItem}
          assets={assets}
          selectedAsset={selectedAsset}
          onSelectAsset={setSelectedAsset}
          onEmergencyStop={handleEmergencyStop}
          onRefresh={loadData}
          isScanning={isScanning}
        />

        <main className="flex-1 overflow-hidden bg-[#0a0d14]">
          {activeModule === 'dashboard' && (
            <Dashboard
              stats={stats}
              assets={assets}
              vulnerabilities={vulnerabilities}
              auditLogs={auditLogs}
              onNavigate={setActiveModule}
            />
          )}

          {activeModule === 'asset-discovery' && (
            <AssetDiscovery
              assets={assets}
              onAddAsset={handleAddAsset}
              onToggleAuthorization={handleToggleAuthorization}
            />
          )}

          {activeModule === 'web-security' && (
            <WebSecurity
              selectedAsset={selectedAsset}
              onLaunchScan={handleLaunchScan}
              onCancelScan={handleEmergencyStop}
              isScanning={isScanning}
            />
          )}

          {activeModule === 'vulnerability-management' && (
            <VulnerabilityManagement vulnerabilities={vulnerabilities} />
          )}

          {activeModule === 'reports' && (
            <Reports assets={assets} vulnerabilities={vulnerabilities} />
          )}

          {activeModule === 'audit-logs' && <AuditLogs logs={auditLogs} />}

          {/* Fallback for all other experimental or pending modules */}
          {![
            'dashboard',
            'asset-discovery',
            'web-security',
            'vulnerability-management',
            'reports',
            'audit-logs',
          ].includes(activeModule) && <ExperimentalModule module={currentModuleItem} />}
        </main>
      </div>
    </div>
  );
};

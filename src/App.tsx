/**
 * VulnHunter AI - Mobile-First Security Workbench App
 * Real, rate-limited, non-destructive vulnerability assessment application.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar.tsx';
import { BottomNav, TabId } from './components/BottomNav.tsx';
import { OverviewTab } from './components/OverviewTab.tsx';
import { ScopeGateTab } from './components/ScopeGateTab.tsx';
import { AssetsTab } from './components/AssetsTab.tsx';
import { ScannerTab } from './components/ScannerTab.tsx';
import { ProxyRepeaterTab } from './components/ProxyRepeaterTab.tsx';
import { LocalLabTab } from './components/LocalLabTab.tsx';
import { FindingsTab } from './components/FindingsTab.tsx';
import { AuthIdorTab } from './components/AuthIdorTab.tsx';
import { TemplatesTab } from './components/TemplatesTab.tsx';
import { ReportsTab } from './components/ReportsTab.tsx';
import { ToolsAuditTab } from './components/ToolsAuditTab.tsx';
import { ScopeRule, Asset, ScanJob, Finding, ProxyLog, AuditLog, ToolHealth } from './types.ts';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  // Application Data States
  const [scopes, setScopes] = useState<ScopeRule[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [proxyLogs, setProxyLogs] = useState<ProxyLog[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [tools, setTools] = useState<Record<string, ToolHealth>>({});
  const [emergencyStop, setEmergencyStop] = useState<boolean>(false);
  const [proxyStatus, setProxyStatus] = useState<{ isRunning: boolean; port: number; host: string; note: string }>({
    isRunning: false,
    port: 8081,
    host: '127.0.0.1',
    note: ''
  });

  const [isLoading, setIsLoading] = useState(true);

  // Fetch all initial data
  const loadData = useCallback(async () => {
    try {
      const [healthRes, scopeRes, assetsRes, scansRes, findingsRes, proxyHistoryRes, proxyStatRes, auditRes] = 
        await Promise.all([
          fetch('/api/health').then(r => r.json()).catch(() => null),
          fetch('/api/scope').then(r => r.json()).catch(() => ({ scopes: [] })),
          fetch('/api/assets').then(r => r.json()).catch(() => ({ assets: [] })),
          fetch('/api/scans').then(r => r.json()).catch(() => ({ scans: [] })),
          fetch('/api/findings').then(r => r.json()).catch(() => ({ findings: [] })),
          fetch('/api/proxy/history').then(r => r.json()).catch(() => ({ logs: [] })),
          fetch('/api/proxy/status').then(r => r.json()).catch(() => null),
          fetch('/api/audit').then(r => r.json()).catch(() => ({ logs: [] }))
        ]);

      if (healthRes) {
        setEmergencyStop(Boolean(healthRes.emergencyStop));
        if (healthRes.tools) setTools(healthRes.tools);
      }
      if (scopeRes?.scopes) setScopes(scopeRes.scopes);
      if (assetsRes?.assets) setAssets(assetsRes.assets);
      if (scansRes?.scans) setScans(scansRes.scans);
      if (findingsRes?.findings) setFindings(findingsRes.findings);
      if (proxyHistoryRes?.logs) setProxyLogs(proxyHistoryRes.logs);
      if (proxyStatRes) setProxyStatus(proxyStatRes);
      if (auditRes?.logs) setAuditLogs(auditRes.logs);
    } catch (err) {
      console.error('Error fetching VulnHunter data:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Periodic refresh for background scans and proxy events
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [loadData]);

  // Scope Handlers
  const handleAddScope = async (target: string, type: string, allowPrivate: boolean, notes: string) => {
    const res = await fetch('/api/scope', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, target_type: type, allow_private_ip: allowPrivate, notes })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to add scope.');
    await loadData();
  };

  const handleDeleteScope = async (id: string) => {
    const res = await fetch(`/api/scope/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to delete scope.');
    await loadData();
  };

  const handleToggleScope = async (id: string) => {
    const res = await fetch(`/api/scope/${id}/toggle`, { method: 'PATCH' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to toggle scope.');
    await loadData();
  };

  // Emergency Stop Handler
  const handleToggleEmergencyStop = async () => {
    const endpoint = emergencyStop ? '/api/emergency-stop/clear' : '/api/emergency-stop/activate';
    const res = await fetch(endpoint, { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      setEmergencyStop(!emergencyStop);
      await loadData();
    } else {
      alert(`Emergency Stop action failed: ${data.error}`);
    }
  };

  // Scanner Handlers
  const handleStartScan = async (target: string, scanType: string) => {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, scan_type: scanType })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to dispatch scan.');
    await loadData();
    return data;
  };

  const handleCancelScan = async (scanId: string) => {
    const res = await fetch(`/api/scans/${scanId}/cancel`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to cancel scan.');
    await loadData();
  };

  // Asset Handlers
  const handleImportAssets = async (entries: string[], provenance: string) => {
    const res = await fetch('/api/assets/manual-import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entries, provenance })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to import assets.');
    await loadData();
  };

  const handleRunSubfinder = async (domain: string) => {
    const res = await fetch('/api/assets/discover-subfinder', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Subfinder run failed.');
    await loadData();
    return data;
  };

  const handleProbeAsset = async (assetId: string) => {
    const res = await fetch(`/api/assets/${assetId}/probe`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Probe failed.');
    await loadData();
    return data;
  };

  // Findings Handlers
  const handleUpdateFindingStatus = async (findingId: string, status: Finding['verification_status']) => {
    const res = await fetch(`/api/findings/${findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verification_status: status })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to update finding status.');
    await loadData();
  };

  const handleAnalyzeWithAi = async (finding: Finding, forceDeterministic = false) => {
    const res = await fetch('/api/ai/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: finding.title,
        category: finding.category,
        evidence: finding.evidence_json,
        impact: finding.impact,
        forceDeterministic
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Analysis failed.');
    return data;
  };

  // Proxy Handlers
  const handleStartProxy = async (port = 8081) => {
    const res = await fetch('/api/proxy/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port })
    });
    const data = await res.json();
    await loadData();
    return data;
  };

  const handleStopProxy = async () => {
    const res = await fetch('/api/proxy/stop', { method: 'POST' });
    const data = await res.json();
    await loadData();
    return data;
  };

  const handleClearProxyLogs = async () => {
    const res = await fetch('/api/proxy/clear', { method: 'POST' });
    const data = await res.json();
    await loadData();
    return data;
  };

  const handleReplayRequest = async (method: string, url: string, headers: Record<string, string>, body?: string) => {
    const res = await fetch('/api/proxy/replay', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method, url, headers, body })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Replay failed.');
    await loadData();
    return data;
  };

  // IDOR Comparison Handler
  const handleRunIdorComparison = async (payload: {
    userAToken: string;
    userBToken: string;
    targetUrlPattern: string;
    objectAId: string;
    objectBId: string;
  }) => {
    const res = await fetch('/api/idor/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Comparison failed.');
    await loadData();
    return data;
  };

  // Report Download Handlers
  const handleDownloadJson = () => {
    window.location.href = '/api/reports/data';
  };

  const handleDownloadMarkdown = () => {
    window.location.href = '/api/reports/markdown';
  };

  const activeScansCount = scans.filter(s => s.status === 'running' || s.status === 'queued').length;
  const activeScopesCount = scopes.filter(s => s.is_active === 1).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-emerald-500 selection:text-slate-950">
      {/* Sticky App Header */}
      <Navbar
        emergencyStop={emergencyStop}
        onToggleEmergencyStop={handleToggleEmergencyStop}
        activeScopesCount={activeScopesCount}
        findingsCount={findings.length}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-3 sm:p-6 overflow-y-auto">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-500 font-mono-code text-xs gap-3">
            <div className="w-8 h-8 border-2 border-emerald-500/30 border-t-emerald-400 rounded-full animate-spin" />
            <p>Initializing VulnHunter AI Engine...</p>
          </div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <OverviewTab
                scopes={scopes}
                scans={scans}
                findings={findings}
                assets={assets}
                tools={tools}
                emergencyStop={emergencyStop}
                onNavigate={setActiveTab}
                onQuickScan={handleStartScan}
                onCancelScan={handleCancelScan}
              />
            )}

            {activeTab === 'scope' && (
              <ScopeGateTab
                scopes={scopes}
                onAddScope={handleAddScope}
                onDeleteScope={handleDeleteScope}
                onToggleScope={handleToggleScope}
                emergencyStop={emergencyStop}
                onToggleEmergencyStop={handleToggleEmergencyStop}
              />
            )}

            {activeTab === 'assets' && (
              <AssetsTab
                assets={assets}
                scopes={scopes}
                findings={findings}
                tools={tools}
                onImportAssets={handleImportAssets}
                onRunSubfinder={handleRunSubfinder}
                onProbeAsset={handleProbeAsset}
              />
            )}

            {activeTab === 'scanners' && (
              <ScannerTab
                scans={scans}
                scopes={scopes}
                emergencyStop={emergencyStop}
                onStartScan={handleStartScan}
                onCancelScan={handleCancelScan}
              />
            )}

            {activeTab === 'proxy' && (
              <ProxyRepeaterTab
                logs={proxyLogs}
                proxyStatus={proxyStatus}
                onStartProxy={handleStartProxy}
                onStopProxy={handleStopProxy}
                onClearLogs={handleClearProxyLogs}
                onReplayRequest={handleReplayRequest}
              />
            )}

            {activeTab === 'lab' && (
              <LocalLabTab onRunTest={handleStartScan} />
            )}

            {activeTab === 'findings' && (
              <FindingsTab
                findings={findings}
                onUpdateStatus={handleUpdateFindingStatus}
                onAnalyzeWithAi={handleAnalyzeWithAi}
              />
            )}

            {activeTab === 'idor' && (
              <AuthIdorTab onRunComparison={handleRunIdorComparison} />
            )}

            {activeTab === 'templates' && (
              <TemplatesTab
                scopes={scopes}
                tools={tools}
                onStartTemplateScan={(target, rateLimit) => handleStartScan(target, 'templates')}
              />
            )}

            {activeTab === 'reports' && (
              <ReportsTab
                findings={findings}
                scopes={scopes}
                onDownloadJson={handleDownloadJson}
                onDownloadMarkdown={handleDownloadMarkdown}
              />
            )}

            {activeTab === 'tools' && (
              <ToolsAuditTab
                tools={tools}
                auditLogs={auditLogs}
              />
            )}
          </>
        )}
      </main>

      {/* Mobile-First Sticky Bottom Navigation */}
      <BottomNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        findingsCount={findings.length}
        activeScansCount={activeScansCount}
      />
    </div>
  );
}

import React, { useState } from 'react';
import { 
  Globe, 
  Upload, 
  Search, 
  Radio, 
  RefreshCw, 
  ShieldAlert, 
  CheckCircle, 
  ExternalLink,
  Plus,
  Terminal
} from 'lucide-react';
import { Asset, ToolHealth, ScopeRule } from '../types.ts';

interface AssetsTabProps {
  assets: Asset[];
  scopes: ScopeRule[];
  tools: Record<string, ToolHealth>;
  onImportAssets: (entries: string[], provenance: string) => Promise<void>;
  onRunSubfinder: (domain: string) => Promise<any>;
  onProbeAsset: (assetId: string) => Promise<any>;
}

export const AssetsTab: React.FC<AssetsTabProps> = ({
  assets,
  scopes,
  tools,
  onImportAssets,
  onRunSubfinder,
  onProbeAsset
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'inventory' | 'import' | 'subfinder'>('inventory');
  const [manualText, setManualText] = useState('');
  const [subfinderDomain, setSubfinderDomain] = useState('');
  const [isImporting, setIsImporting] = useState(false);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [probingId, setProbingId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

  const subfinderReady = tools.subfinder?.isAvailable;

  const handleManualImport = async (e: React.FormEvent) => {
    e.preventDefault();
    const lines = manualText
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0 && !l.startsWith('#'));

    if (lines.length === 0) return;
    setIsImporting(true);
    setStatusMessage(null);

    try {
      await onImportAssets(lines, 'manual_import');
      setManualText('');
      setStatusMessage({ type: 'success', msg: `Imported ${lines.length} assets into inventory.` });
      setActiveSubTab('inventory');
    } catch (err: any) {
      setStatusMessage({ type: 'error', msg: err.message || 'Import failed.' });
    } finally {
      setIsImporting(false);
    }
  };

  const handleRunSubfinder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!subfinderDomain.trim()) return;

    setIsDiscovering(true);
    setStatusMessage(null);

    try {
      const res = await onRunSubfinder(subfinderDomain.trim());
      setStatusMessage({ 
        type: 'success', 
        msg: `Subfinder finished: Discovered ${res.totalDiscovered} subdomains (${res.newlyAdded} new).` 
      });
      setActiveSubTab('inventory');
    } catch (err: any) {
      setStatusMessage({ type: 'error', msg: err.message || 'Subfinder run failed.' });
    } finally {
      setIsDiscovering(false);
    }
  };

  const handleProbe = async (id: string) => {
    setProbingId(id);
    try {
      await onProbeAsset(id);
    } catch (err: any) {
      alert(`Probe failed: ${err.message}`);
    } finally {
      setProbingId(null);
    }
  };

  const filteredAssets = assets.filter(a => 
    a.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (a.title && a.title.toLowerCase().includes(searchQuery.toLowerCase())) ||
    a.provenance.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-4 pb-20">
      {/* Tab Switcher */}
      <div className="flex rounded-xl bg-slate-900 p-1 border border-slate-800 text-xs font-mono-code">
        <button
          onClick={() => setActiveSubTab('inventory')}
          className={`flex-1 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'inventory' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Inventory ({assets.length})
        </button>
        <button
          onClick={() => setActiveSubTab('import')}
          className={`flex-1 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'import' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Manual Import
        </button>
        <button
          onClick={() => setActiveSubTab('subfinder')}
          className={`flex-1 py-1.5 rounded-lg font-semibold transition-all flex items-center justify-center gap-1 ${
            activeSubTab === 'subfinder' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Terminal className="w-3 h-3 text-cyan-400" />
          Subfinder
        </button>
      </div>

      {statusMessage && (
        <div className={`p-3 rounded-xl text-xs font-mono-code ${
          statusMessage.type === 'success' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
        }`}>
          {statusMessage.msg}
        </div>
      )}

      {/* Subtab 1: Inventory */}
      {activeSubTab === 'inventory' && (
        <div className="space-y-3">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter assets by host, provenance, title..."
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white font-mono-code focus:outline-none focus:border-emerald-500"
            />
          </div>

          {filteredAssets.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400">
              <Globe className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              <p>No assets discovered yet.</p>
              <p className="text-[11px] text-slate-500 mt-1">
                Use "Manual Import" or "Subfinder" to populate your target inventory.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredAssets.map(asset => (
                <div key={asset.id} className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="font-mono-code font-bold text-white break-all">{asset.host}</span>
                        {asset.status_code && (
                          <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono-code font-semibold ${
                            asset.status_code >= 200 && asset.status_code < 300
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : asset.status_code >= 300 && asset.status_code < 400
                              ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                              : 'bg-slate-800 text-slate-400'
                          }`}>
                            HTTP {asset.status_code}
                          </span>
                        )}
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono-code">
                          {asset.provenance}
                        </span>
                      </div>
                      {asset.title && (
                        <p className="mt-1 text-[11px] text-slate-300 font-mono-code truncate">
                          "{asset.title}"
                        </p>
                      )}
                      <div className="mt-1 flex items-center gap-2 text-[10px] text-slate-500 font-mono-code">
                        <span>Port {asset.port}</span>
                        <span>•</span>
                        <span>{new Date(asset.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        onClick={() => handleProbe(asset.id)}
                        disabled={probingId === asset.id}
                        className="px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-mono-code flex items-center gap-1"
                        title="Probe HTTP status and title"
                      >
                        <RefreshCw className={`w-3 h-3 ${probingId === asset.id ? 'animate-spin text-emerald-400' : ''}`} />
                        <span>Probe</span>
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Subtab 2: Manual Import */}
      {activeSubTab === 'import' && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div>
            <h3 className="text-xs font-bold text-white font-mono-code">Passive & Manual Asset Import</h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Paste newline-separated domains, hostnames, or URLs. Provenance will be marked as "manual_import".
            </p>
          </div>

          <form onSubmit={handleManualImport} className="space-y-3">
            <textarea
              rows={6}
              value={manualText}
              onChange={e => setManualText(e.target.value)}
              placeholder={"sub1.example.com\nsub2.example.com\napi.example.com"}
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-emerald-500"
              required
            />

            <button
              type="submit"
              disabled={isImporting || !manualText.trim()}
              className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono-code text-xs transition-all active:scale-95 disabled:opacity-50"
            >
              {isImporting ? 'Importing Assets...' : 'Import Assets'}
            </button>
          </form>
        </div>
      )}

      {/* Subtab 3: Subfinder Adapter */}
      {activeSubTab === 'subfinder' && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-white font-mono-code flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-cyan-400" />
              Subfinder Binary Adapter
            </h3>
            <span className={`text-[10px] px-2 py-0.5 rounded font-mono-code font-bold ${
              subfinderReady ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
            }`}>
              {subfinderReady ? 'INSTALLED & READY' : 'NOT INSTALLED'}
            </span>
          </div>

          {!subfinderReady ? (
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 space-y-2">
              <p className="text-amber-300 font-semibold font-mono-code">
                Subfinder binary is not present in PATH.
              </p>
              <p className="text-[11px] leading-relaxed">
                VulnHunter AI gracefully handles missing external binaries. You can either use <strong>Manual Asset Import</strong>, or install Subfinder in Android Termux using Golang:
              </p>
              <pre className="p-2 rounded bg-slate-900 text-slate-200 text-[10px] font-mono-code overflow-x-auto">
pkg install -y golang
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:~/go/bin
              </pre>
            </div>
          ) : (
            <form onSubmit={handleRunSubfinder} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
                  Target Domain (Must be in Scope Gate)
                </label>
                <input
                  type="text"
                  value={subfinderDomain}
                  onChange={e => setSubfinderDomain(e.target.value)}
                  placeholder="e.g. example.com"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400">
                Notice: Discovered assets will NOT be automatically marked as authorized targets until verified against your scope rules.
              </div>

              <button
                type="submit"
                disabled={isDiscovering || !subfinderDomain.trim()}
                className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold font-mono-code text-xs transition-all active:scale-95 disabled:opacity-50"
              >
                {isDiscovering ? 'Executing Subfinder...' : 'Launch Subfinder Discovery'}
              </button>
            </form>
          )}
        </div>
      )}
    </div>
  );
};

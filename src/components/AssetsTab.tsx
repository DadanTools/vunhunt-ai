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
  Terminal,
  Network,
  FileCode,
  Key,
  Flame,
  Copy,
  Check,
  Code2,
  FileSearch,
  Sparkles,
  AlertTriangle,
  Lock
} from 'lucide-react';
import { Asset, ToolHealth, ScopeRule, Finding } from '../types.ts';
import { AttackSurfaceGraph } from './AttackSurfaceGraph.tsx';

interface AssetsTabProps {
  assets: Asset[];
  scopes: ScopeRule[];
  findings: Finding[];
  tools: Record<string, ToolHealth>;
  onImportAssets: (entries: string[], provenance: string) => Promise<void>;
  onRunSubfinder: (domain: string) => Promise<any>;
  onProbeAsset: (assetId: string) => Promise<any>;
  onRefreshFindings?: () => void;
}

export const AssetsTab: React.FC<AssetsTabProps> = ({
  assets,
  scopes,
  findings,
  tools,
  onImportAssets,
  onRunSubfinder,
  onProbeAsset,
  onRefreshFindings
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'inventory' | 'attack_surface' | 'js_crawler' | 'import' | 'subfinder'>('inventory');
  const [manualText, setManualText] = useState('');
  const [subfinderDomain, setSubfinderDomain] = useState('');
  const [isImporting, setIsImporting] = useState(false);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [probingId, setProbingId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

  // Dynamic JS Crawler State
  const [isCrawlingJs, setIsCrawlingJs] = useState(false);
  const [crawlingAssetId, setCrawlingAssetId] = useState<string | null>(null);
  const [jsCrawlTarget, setJsCrawlTarget] = useState('http://localhost:3000');
  const [jsCrawlResult, setJsCrawlResult] = useState<any | null>(null);
  const [jsActiveTab, setJsActiveTab] = useState<'endpoints' | 'secrets' | 'sinks' | 'sourcemaps' | 'scripts'>('endpoints');
  const [jsFilter, setJsFilter] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const subfinderReady = tools.subfinder?.isAvailable;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

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

  // Dynamic JS Crawler Function (Dynamic crawl for hidden .js files & secrets using regex scanner)
  const handleCrawlJs = async (targetUrl: string, assetId?: string) => {
    const cleanUrl = targetUrl.startsWith('http://') || targetUrl.startsWith('https://')
      ? targetUrl
      : `http://${targetUrl}`;

    setJsCrawlTarget(cleanUrl);
    setIsCrawlingJs(true);
    if (assetId) setCrawlingAssetId(assetId);
    setStatusMessage(null);

    try {
      const res = await fetch('/api/recon/js-extract', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: cleanUrl })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to crawl JavaScript files.');

      setJsCrawlResult(data.result);
      setActiveSubTab('js_crawler');
      setStatusMessage({
        type: 'success',
        msg: `JS Crawl complete for ${cleanUrl}: Analyzed ${data.result.totalScriptsAnalyzed} scripts, found ${data.result.hiddenEndpoints?.length || 0} hidden endpoints and ${data.result.discoveredSecrets?.length || 0} secrets.`
      });

      if (onRefreshFindings) {
        onRefreshFindings();
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        msg: `Dynamic JS Crawl error: ${err.message}`
      });
    } finally {
      setIsCrawlingJs(false);
      setCrawlingAssetId(null);
    }
  };

  const filteredAssets = assets.filter(a => 
    a.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (a.title && a.title.toLowerCase().includes(searchQuery.toLowerCase())) ||
    a.provenance.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredEndpoints = (jsCrawlResult?.hiddenEndpoints || []).filter((ep: any) => {
    if (!jsFilter) return true;
    return ep.endpoint.toLowerCase().includes(jsFilter.toLowerCase()) ||
           ep.category.toLowerCase().includes(jsFilter.toLowerCase());
  });

  return (
    <div className="space-y-4 pb-20">
      {/* Subtab Switcher */}
      <div className="flex rounded-xl bg-slate-900 p-1 border border-slate-800 text-xs font-mono-code flex-wrap gap-1">
        <button
          onClick={() => setActiveSubTab('inventory')}
          className={`flex-1 py-1.5 px-2 rounded-lg font-semibold transition-all ${
            activeSubTab === 'inventory' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Inventory ({assets.length})
        </button>

        <button
          onClick={() => setActiveSubTab('attack_surface')}
          className={`flex-1 py-1.5 px-2 rounded-lg font-semibold transition-all flex items-center justify-center gap-1 ${
            activeSubTab === 'attack_surface' ? 'bg-slate-800 text-cyan-400' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Network className="w-3 h-3 text-cyan-400" />
          <span>Attack Graph</span>
        </button>

        <button
          onClick={() => setActiveSubTab('js_crawler')}
          className={`flex-1 py-1.5 px-2 rounded-lg font-semibold transition-all flex items-center justify-center gap-1 ${
            activeSubTab === 'js_crawler' ? 'bg-cyan-600 text-slate-950 font-black shadow' : 'text-cyan-400 hover:text-cyan-300'
          }`}
        >
          <FileCode className="w-3 h-3" />
          <span>JS Crawler & Secrets</span>
          {jsCrawlResult && (
            <span className="text-[9px] bg-slate-950/60 text-white px-1 rounded ml-0.5">
              {jsCrawlResult.hiddenEndpoints?.length || 0}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab('import')}
          className={`flex-1 py-1.5 px-2 rounded-lg font-semibold transition-all ${
            activeSubTab === 'import' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Manual Import
        </button>

        <button
          onClick={() => setActiveSubTab('subfinder')}
          className={`flex-1 py-1.5 px-2 rounded-lg font-semibold transition-all flex items-center justify-center gap-1 ${
            activeSubTab === 'subfinder' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Terminal className="w-3 h-3 text-cyan-400" />
          <span>Subfinder</span>
        </button>
      </div>

      {statusMessage && (
        <div className={`p-3 rounded-xl text-xs font-mono-code flex items-center justify-between ${
          statusMessage.type === 'success' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
        }`}>
          <span>{statusMessage.msg}</span>
          <button onClick={() => setStatusMessage(null)} className="text-slate-400 hover:text-white ml-2 text-sm">&times;</button>
        </div>
      )}

      {/* Subtab: Attack Surface Graph */}
      {activeSubTab === 'attack_surface' && (
        <AttackSurfaceGraph
          assets={assets}
          findings={findings}
          scopes={scopes}
        />
      )}

      {/* Subtab 1: Inventory Table */}
      {activeSubTab === 'inventory' && (
        <div className="space-y-3">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search assets by hostname, title, or provenance..."
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>

          {filteredAssets.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-slate-900 border border-slate-800 text-slate-500 font-mono-code text-xs">
              No assets discovered yet. Import hosts manually, run Subfinder, or launch an AI Hunt.
            </div>
          ) : (
            <div className="space-y-2">
              {filteredAssets.map(asset => (
                <div 
                  key={asset.id}
                  className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-white text-xs font-mono-code">
                          {asset.host}
                        </span>
                        {asset.status_code !== undefined && asset.status_code > 0 && (
                          <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono-code font-bold ${
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
                      {/* Dynamic JS Crawl Button */}
                      <button
                        onClick={() => handleCrawlJs(asset.url || `http://${asset.host}:${asset.port}`, asset.id)}
                        disabled={isCrawlingJs && crawlingAssetId === asset.id}
                        className="px-2 py-1 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700 text-[10px] font-mono-code flex items-center gap-1 transition-all"
                        title="Dynamic crawl for hidden .js files and extract hardcoded secrets"
                      >
                        <FileCode className={`w-3 h-3 ${isCrawlingJs && crawlingAssetId === asset.id ? 'animate-spin text-cyan-400' : 'text-cyan-400'}`} />
                        <span>{isCrawlingJs && crawlingAssetId === asset.id ? 'Crawling...' : 'Crawl JS'}</span>
                      </button>

                      {/* Probe Button */}
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

      {/* Subtab: Dynamic JS Crawler & Secret Spy */}
      {activeSubTab === 'js_crawler' && (
        <div className="p-4 rounded-xl bg-slate-900 border border-cyan-500/40 space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <FileCode className="w-5 h-5 text-cyan-400" />
              <div>
                <h3 className="text-xs font-bold text-white uppercase flex items-center gap-2">
                  <span>Dynamic JS Crawler & Regex-Based Secret Scanner</span>
                  <span className="text-[9px] bg-cyan-500 text-slate-950 px-1.5 py-0.5 rounded font-black">
                    DYNAMIC CRAWL
                  </span>
                </h3>
                <p className="text-[11px] text-slate-400">
                  Crawls the DOM for script tags, downloads client-side bundles, and extracts hidden API endpoints & hardcoded keys.
                </p>
              </div>
            </div>
          </div>

          {/* Crawler Input Form */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <label className="text-[11px] font-mono-code text-slate-300 block">
              Target Asset URL or Host
            </label>
            <div className="flex flex-col sm:flex-row items-center gap-2">
              <input
                type="text"
                value={jsCrawlTarget}
                onChange={e => setJsCrawlTarget(e.target.value)}
                placeholder="e.g. http://localhost:3000 or https://authorized-asset.com"
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono-code text-xs focus:outline-none focus:border-cyan-500"
              />

              <div className="flex items-center gap-2 w-full sm:w-auto shrink-0">
                <button
                  onClick={() => handleCrawlJs(jsCrawlTarget)}
                  disabled={isCrawlingJs || !jsCrawlTarget.trim()}
                  className="w-full sm:w-auto px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black font-mono-code text-xs flex items-center justify-center gap-1.5 transition-all shadow active:scale-95 disabled:opacity-50"
                >
                  {isCrawlingJs ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <FileCode className="w-3.5 h-3.5" />}
                  <span>{isCrawlingJs ? 'Crawling & Parsing...' : 'Initiate Dynamic JS Crawl'}</span>
                </button>

                {assets.length > 0 && (
                  <select
                    onChange={e => {
                      if (e.target.value) {
                        setJsCrawlTarget(e.target.value);
                        handleCrawlJs(e.target.value);
                      }
                    }}
                    defaultValue=""
                    className="px-2 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs font-mono-code"
                  >
                    <option value="" disabled>Pick Asset...</option>
                    {assets.map(a => (
                      <option key={a.id} value={a.url || `http://${a.host}:${a.port}`}>
                        {a.host}
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </div>
          </div>

          {/* Active Crawling Animation */}
          {isCrawlingJs && (
            <div className="p-6 rounded-lg bg-slate-950 border border-cyan-500/40 text-center space-y-2 animate-pulse font-mono-code">
              <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
              <p className="text-xs font-bold text-white">Crawling DOM and extracting JavaScript bundles from {jsCrawlTarget}...</p>
              <p className="text-[10px] text-slate-400">Executing regex patterns for API endpoints, AWS keys, JWTs, and DOM sinks.</p>
            </div>
          )}

          {/* Results View */}
          {jsCrawlResult && !isCrawlingJs && (
            <div className="space-y-3">
              {/* Summary Stats */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono-code">
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Scripts Crawled</span>
                  <span className="text-lg font-black text-white">{jsCrawlResult.totalScriptsAnalyzed}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Hidden Endpoints</span>
                  <span className="text-lg font-black text-cyan-400">{jsCrawlResult.hiddenEndpoints?.length || 0}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Exposed Secrets</span>
                  <span className="text-lg font-black text-rose-400">{jsCrawlResult.discoveredSecrets?.length || 0}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">DOM Sinks</span>
                  <span className="text-lg font-black text-amber-400">{jsCrawlResult.domXssSinks?.length || 0}</span>
                </div>
              </div>

              {/* View Tabs */}
              <div className="flex items-center gap-1 border-b border-slate-800 text-[11px] font-mono-code overflow-x-auto pb-1">
                <button
                  onClick={() => setJsActiveTab('endpoints')}
                  className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                    jsActiveTab === 'endpoints' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Radio className="w-3 h-3" />
                  <span>Hidden Endpoints ({jsCrawlResult.hiddenEndpoints?.length || 0})</span>
                </button>

                <button
                  onClick={() => setJsActiveTab('secrets')}
                  className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                    jsActiveTab === 'secrets' ? 'bg-rose-500 text-slate-950' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Key className="w-3 h-3" />
                  <span>Secrets & Keys ({jsCrawlResult.discoveredSecrets?.length || 0})</span>
                </button>

                <button
                  onClick={() => setJsActiveTab('sinks')}
                  className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                    jsActiveTab === 'sinks' ? 'bg-amber-500 text-slate-950' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Flame className="w-3 h-3" />
                  <span>DOM XSS Sinks ({jsCrawlResult.domXssSinks?.length || 0})</span>
                </button>

                <button
                  onClick={() => setJsActiveTab('sourcemaps')}
                  className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                    jsActiveTab === 'sourcemaps' ? 'bg-emerald-500 text-slate-950' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <FileSearch className="w-3 h-3" />
                  <span>Source Maps ({jsCrawlResult.sourceMaps?.length || 0})</span>
                </button>

                <button
                  onClick={() => setJsActiveTab('scripts')}
                  className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                    jsActiveTab === 'scripts' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <FileCode className="w-3 h-3" />
                  <span>Bundles ({jsCrawlResult.scripts?.length || 0})</span>
                </button>
              </div>

              {/* Sub-Tab 1: Endpoints List */}
              {jsActiveTab === 'endpoints' && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <div className="relative flex-1">
                      <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                      <input
                        type="text"
                        value={jsFilter}
                        onChange={e => setJsFilter(e.target.value)}
                        placeholder="Search endpoints (e.g. /admin, /api/v1, /users)..."
                        className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                  </div>

                  {filteredEndpoints.length === 0 ? (
                    <div className="py-6 text-center text-slate-500 text-xs font-mono-code">
                      No endpoints matched search filter.
                    </div>
                  ) : (
                    <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
                      {filteredEndpoints.map((ep: any, idx: number) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 flex items-center justify-between gap-2 text-xs font-mono-code transition-all"
                        >
                          <div className="flex items-center gap-2 truncate">
                            <span className={`text-[9px] px-1.5 py-0.5 rounded font-black uppercase ${
                              ep.severity === 'critical' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                              ep.severity === 'high' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                              ep.severity === 'medium' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                              'bg-slate-800 text-slate-300'
                            }`}>
                              {ep.category}
                            </span>
                            <code className="text-white font-bold truncate">{ep.endpoint}</code>
                          </div>

                          <button
                            onClick={() => handleCopy(ep.endpoint, `ep_${idx}`)}
                            className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-[10px] flex items-center gap-1 border border-slate-700 shrink-0"
                          >
                            {copiedKey === `ep_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedKey === `ep_${idx}` ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 2: Secrets List */}
              {jsActiveTab === 'secrets' && (
                <div className="space-y-2">
                  {(!jsCrawlResult.discoveredSecrets || jsCrawlResult.discoveredSecrets.length === 0) ? (
                    <div className="py-6 text-center text-slate-500 text-xs font-mono-code">
                      No hardcoded API secrets or tokens detected in scraped JavaScript files.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                      {jsCrawlResult.discoveredSecrets.map((sec: any, idx: number) => (
                        <div
                          key={idx}
                          className="p-3 rounded-lg bg-slate-950 border border-rose-900/60 space-y-1.5 font-mono-code text-xs"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className={`text-[10px] px-2 py-0.5 rounded font-black ${
                                sec.priority === 'P1' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                                sec.priority === 'P2' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                                'bg-amber-950 text-amber-300 border border-amber-800'
                              }`}>
                                {sec.priority} &bull; {sec.severity.toUpperCase()}
                              </span>
                              <span className="font-bold text-white text-xs">{sec.title}</span>
                            </div>

                            <button
                              onClick={() => handleCopy(sec.secret, `sec_${idx}`)}
                              className="px-2 py-0.5 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 text-[10px] font-bold border border-rose-800 flex items-center gap-1"
                            >
                              {copiedKey === `sec_${idx}` ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === `sec_${idx}` ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>

                          <div className="p-2 rounded bg-slate-900 text-slate-300 text-[11px] truncate border border-slate-800">
                            Evidence: <span className="text-rose-400 font-bold">{sec.evidence}</span>
                          </div>

                          <div className="text-[10px] text-slate-500 truncate">
                            Found in: <code className="text-slate-400">{sec.foundInScript}</code>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 3: DOM XSS Sinks */}
              {jsActiveTab === 'sinks' && (
                <div className="space-y-2">
                  {(!jsCrawlResult.domXssSinks || jsCrawlResult.domXssSinks.length === 0) ? (
                    <div className="py-6 text-center text-slate-500 text-xs font-mono-code">
                      No dangerous DOM execution sinks detected.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                      {jsCrawlResult.domXssSinks.map((sink: any, idx: number) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-950 border border-amber-900/40 text-xs font-mono-code space-y-1"
                        >
                          <div className="flex items-center justify-between text-amber-400 font-bold">
                            <span className="flex items-center gap-1.5">
                              <Flame className="w-3.5 h-3.5" />
                              <span>{sink.sink}</span>
                            </span>
                            <span className="text-[10px] text-slate-500">DOM Execution Sink</span>
                          </div>
                          <div className="p-1.5 rounded bg-slate-900 text-slate-300 text-[10px] truncate border border-slate-800">
                            {sink.snippet}
                          </div>
                          <div className="text-[9px] text-slate-500 truncate">
                            Script: <code className="text-slate-400">{sink.foundInScript}</code>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 4: Source Maps */}
              {jsActiveTab === 'sourcemaps' && (
                <div className="space-y-2">
                  {(!jsCrawlResult.sourceMaps || jsCrawlResult.sourceMaps.length === 0) ? (
                    <div className="py-6 text-center text-slate-500 text-xs font-mono-code">
                      No client-side source maps (.map) referenced.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                      {jsCrawlResult.sourceMaps.map((sm: any, idx: number) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono-code flex items-center justify-between gap-2"
                        >
                          <div className="truncate">
                            <div className="flex items-center gap-2">
                              <span className={`text-[9px] px-1.5 py-0.2 rounded font-black ${
                                sm.isAccessible ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-800 text-slate-400'
                              }`}>
                                {sm.isAccessible ? 'EXPOSED (200 OK)' : 'PROTECTED'}
                              </span>
                              <code className="text-white font-bold truncate">{sm.mapUrl}</code>
                            </div>
                          </div>
                          {sm.isAccessible && (
                            <button
                              onClick={() => handleCopy(sm.mapUrl, `map_${idx}`)}
                              className="px-2 py-0.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-[10px] font-bold shrink-0"
                            >
                              {copiedKey === `map_${idx}` ? 'Copied' : 'Copy URL'}
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 5: Scraped Scripts List */}
              {jsActiveTab === 'scripts' && (
                <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
                  {jsCrawlResult.scripts?.map((s: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono-code flex items-center justify-between gap-2"
                    >
                      <div className="truncate">
                        <code className="text-slate-300 font-bold truncate block">{s.url}</code>
                        <span className="text-[10px] text-slate-500">
                          Size: {(s.sizeBytes / 1024).toFixed(1)} KB &bull; SourceMap: {s.hasSourceMap ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <button
                        onClick={() => handleCopy(s.url, `script_${idx}`)}
                        className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-[10px] border border-slate-700 shrink-0"
                      >
                        {copiedKey === `script_${idx}` ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  ))}
                </div>
              )}
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

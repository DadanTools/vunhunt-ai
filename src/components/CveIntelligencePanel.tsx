import React, { useState, useEffect } from 'react';
import { 
  Search, 
  ShieldAlert, 
  ExternalLink, 
  CheckCircle2, 
  AlertTriangle, 
  Copy, 
  Check, 
  RefreshCw, 
  Globe, 
  BookOpen, 
  Clock, 
  Tag, 
  Sparkles,
  Layers,
  ArrowRight
} from 'lucide-react';

export interface CveSource {
  title: string;
  url: string;
}

export interface CveIntelligenceRecord {
  id: string;
  query: string;
  cve_id: string;
  title: string;
  severity: string;
  cvss_score: number;
  affected_software: string;
  cwe: string;
  description: string;
  remediation: string;
  sources: CveSource[];
  source_engine: string;
  created_at: string;
}

const TRENDING_SEARCHES = [
  { label: 'CVE-2024-3400', desc: 'PAN-OS Command Injection' },
  { label: 'CVE-2023-44487', desc: 'HTTP/2 Rapid Reset' },
  { label: 'CVE-2021-44228', desc: 'Log4Shell RCE' },
  { label: 'Express.js', desc: 'Open Redirect & URL' },
  { label: 'Nginx', desc: 'Buffer & Protocol' },
  { label: 'OpenSSL', desc: 'Certificate & Handshake' }
];

export const CveIntelligencePanel: React.FC = () => {
  const [query, setQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeRecord, setActiveRecord] = useState<CveIntelligenceRecord | null>(null);
  const [history, setHistory] = useState<CveIntelligenceRecord[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Fetch recent CVE lookup history
  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/cve/history');
      if (res.ok) {
        const data = await res.json();
        if (data.history) {
          setHistory(data.history);
          if (!activeRecord && data.history.length > 0) {
            setActiveRecord(data.history[0]);
          }
        }
      }
    } catch {}
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleLookup = async (searchTarget?: string) => {
    const q = (searchTarget || query).trim();
    if (!q) return;

    setIsLoading(true);
    setErrorMsg(null);

    try {
      const res = await fetch('/api/cve/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to fetch CVE intelligence.');
      }

      if (data.result) {
        setActiveRecord(data.result);
        setQuery('');
        fetchHistory();
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Error executing CVE intelligence search.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getSeverityBadgeClass = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === 'CRITICAL') return 'bg-rose-950 text-rose-300 border-rose-700 animate-pulse';
    if (s === 'HIGH') return 'bg-orange-950 text-orange-300 border-orange-700';
    if (s === 'MEDIUM') return 'bg-amber-950 text-amber-300 border-amber-700';
    return 'bg-blue-950 text-blue-300 border-blue-700';
  };

  return (
    <div className="space-y-4 font-mono-code text-xs">
      {/* Search Header Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white">CVE & Security Advisory Intelligence</h3>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 border border-slate-700 flex items-center gap-1">
                  <Sparkles className="w-2.5 h-2.5" /> Google Search Grounded
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Live vulnerability research querying NVD, MITRE CVE, and GitHub Security Advisories
              </p>
            </div>
          </div>
        </div>

        {/* Search Bar Input */}
        <form 
          onSubmit={e => {
            e.preventDefault();
            handleLookup();
          }} 
          className="flex flex-col sm:flex-row items-center gap-2"
        >
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search CVE ID (e.g. CVE-2024-3400) or software (e.g. Express, OpenSSL, Nginx)..."
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            type="submit"
            disabled={isLoading || !query.trim()}
            className="w-full sm:w-auto px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold flex items-center justify-center gap-1.5 transition-all shadow-sm active:scale-95 disabled:opacity-50"
          >
            {isLoading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Search className="w-3.5 h-3.5" />
            )}
            <span>{isLoading ? 'Searching...' : 'Search NVD/GitHub'}</span>
          </button>
        </form>

        {/* Trending Searches Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-[10px] text-slate-500 uppercase font-bold mr-1">Trending:</span>
          {TRENDING_SEARCHES.map(item => (
            <button
              key={item.label}
              onClick={() => handleLookup(item.label)}
              disabled={isLoading}
              className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/50 text-slate-300 hover:text-cyan-300 text-[11px] transition-all"
            >
              <span className="font-bold">{item.label}</span>
              <span className="text-[9px] text-slate-500 ml-1">({item.desc})</span>
            </button>
          ))}
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-xl bg-rose-950/80 border border-rose-700 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Main Intelligence Advisory Display Card */}
      {activeRecord && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3.5">
          {/* Header Row */}
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 pb-2 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span className="text-sm font-black text-white">{activeRecord.cve_id}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold border ${getSeverityBadgeClass(activeRecord.severity)}`}>
                  {activeRecord.severity} &bull; CVSS {activeRecord.cvss_score}
                </span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {activeRecord.source_engine === 'gemini_search_grounding' ? 'GOOGLE SEARCH GROUNDED' : 'NVD CATALOG'}
                </span>
              </div>
              <h4 className="text-xs font-bold text-cyan-300 leading-snug">{activeRecord.title}</h4>
            </div>

            {/* Quick Copy Advisory Summary */}
            <button
              onClick={() => handleCopy(`${activeRecord.cve_id}: ${activeRecord.title}\nSeverity: ${activeRecord.severity} (CVSS ${activeRecord.cvss_score})\nAffected: ${activeRecord.affected_software}\nCWE: ${activeRecord.cwe}\n\nDescription:\n${activeRecord.description}\n\nRemediation:\n${activeRecord.remediation}`, 'advisory_full')}
              className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white text-xs flex items-center gap-1 transition-all self-start"
              title="Copy full advisory report"
            >
              {copiedKey === 'advisory_full' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKey === 'advisory_full' ? 'Copied' : 'Copy Report'}</span>
            </button>
          </div>

          {/* Key Intelligence Fields Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-bold block">Affected Software / Ecosystem</span>
              <span className="text-white font-semibold">{activeRecord.affected_software}</span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-bold block">Weakness Classification (CWE)</span>
              <span className="text-cyan-400 font-semibold">{activeRecord.cwe}</span>
            </div>
          </div>

          {/* Technical Description */}
          <div className="space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-bold">Vulnerability Mechanism & Impact</span>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-[11px] leading-relaxed">
              {activeRecord.description}
            </div>
          </div>

          {/* Remediation & Mitigation */}
          <div className="space-y-1">
            <span className="text-[10px] text-emerald-400 uppercase font-bold">Remediation & Patch Guidance</span>
            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-emerald-300 text-[11px] leading-relaxed">
              {activeRecord.remediation}
            </div>
          </div>

          {/* Grounded Web Sources & Official Links */}
          {activeRecord.sources && activeRecord.sources.length > 0 && (
            <div className="space-y-1.5 pt-1">
              <span className="text-[10px] text-slate-400 uppercase font-bold block">
                Verified Advisory Citations & Grounded Sources ({activeRecord.sources.length})
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {activeRecord.sources.map((src, idx) => (
                  <a
                    key={idx}
                    href={src.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/60 transition-all flex items-center justify-between text-slate-300 hover:text-white group"
                  >
                    <div className="min-w-0 pr-2">
                      <span className="text-[11px] font-semibold truncate block group-hover:text-cyan-400 transition-colors">
                        {src.title}
                      </span>
                      <span className="text-[9px] text-slate-500 truncate block">
                        {src.url.replace(/^https?:\/\//, '').split('/')[0]}
                      </span>
                    </div>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 shrink-0" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recent Intelligence Lookups History List */}
      {history.length > 0 && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white uppercase">Recent Intelligence Investigations</span>
            <span className="text-[10px] text-slate-500">Cached in local SQLite database</span>
          </div>

          <div className="space-y-1.5">
            {history.map(item => (
              <div
                key={item.id}
                onClick={() => setActiveRecord(item)}
                className={`p-2.5 rounded-lg border transition-all cursor-pointer flex items-center justify-between ${
                  activeRecord?.id === item.id
                    ? 'bg-slate-850 border-cyan-500 text-white'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                }`}
              >
                <div className="min-w-0 pr-2">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white text-xs">{item.cve_id}</span>
                    <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold border ${getSeverityBadgeClass(item.severity)}`}>
                      {item.severity}
                    </span>
                    <span className="text-[10px] text-slate-400 truncate hidden sm:inline">
                      {item.title}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-slate-500">{new Date(item.created_at).toLocaleDateString()}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

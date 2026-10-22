import React, { useState } from 'react';
import { 
  Play, 
  Crosshair, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  RotateCw,
  StopCircle,
  FileSearch,
  Zap,
  Globe2,
  Lock,
  Layers,
  ShieldCheck,
  Server,
  Terminal,
  Copy,
  Check,
  ExternalLink,
  Search,
  Sparkles,
  Cpu
} from 'lucide-react';
import { ScanJob, ScopeRule } from '../types.ts';

interface ScannerTabProps {
  scans: ScanJob[];
  scopes: ScopeRule[];
  emergencyStop: boolean;
  onStartScan: (target: string, scanType: string) => Promise<any>;
  onCancelScan: (scanId: string) => Promise<any>;
}

interface ReconData {
  host: string;
  targetUrl: string;
  dns: {
    a: string[];
    aaaa: string[];
    mx: Array<{ exchange: string; priority: number }>;
    txt: string[];
    cname: string[];
    ns: string[];
  };
  tls?: {
    authorized: boolean;
    protocol: string;
    cipher: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
    sans: string[];
  };
  technologies: Array<{ name: string; category: string; evidence: string }>;
  securityHeadersGrade: {
    grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
    score: number;
    checks: Array<{ header: string; status: 'present' | 'missing' | 'warning'; details: string }>;
  };
}

interface FuzzRow {
  path: string;
  url: string;
  statusCode: number;
  statusMessage: string;
  durationMs: number;
  contentLength: number;
  isInteresting: boolean;
  category: 'sensitive_file' | 'api_route' | 'admin_panel' | 'standard';
  findingCreated?: boolean;
}

export const ScannerTab: React.FC<ScannerTabProps> = ({
  scans,
  scopes,
  emergencyStop,
  onStartScan,
  onCancelScan
}) => {
  const activeScopes = scopes.filter(s => s.is_active === 1);
  const [activeSubTab, setActiveSubTab] = useState<'scanners' | 'recon' | 'fuzzer'>('scanners');

  // Scanner Form State
  const [targetUrl, setTargetUrl] = useState(
    activeScopes.length > 0 ? `http://${activeScopes[0].target}/api/lab/headers` : 'http://localhost:3000/api/lab/headers'
  );
  const [scanType, setScanType] = useState('exposure');
  const [isStarting, setIsStarting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Recon State
  const [reconTarget, setReconTarget] = useState(
    activeScopes.length > 0 ? activeScopes[0].target : 'localhost:3000'
  );
  const [isReconRunning, setIsReconRunning] = useState(false);
  const [reconResult, setReconResult] = useState<ReconData | null>(null);
  const [reconError, setReconError] = useState<string | null>(null);

  // Fuzzer State
  const [fuzzTarget, setFuzzTarget] = useState(
    activeScopes.length > 0 ? `http://${activeScopes[0].target}` : 'http://localhost:3000'
  );
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [fuzzResults, setFuzzResults] = useState<FuzzRow[]>([]);
  const [fuzzError, setFuzzError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    setIsStarting(true);
    setErrorMsg(null);

    try {
      await onStartScan(targetUrl.trim(), scanType);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to start scan.');
    } finally {
      setIsStarting(false);
    }
  };

  const handleRunRecon = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reconTarget.trim()) return;

    setIsReconRunning(true);
    setReconError(null);

    try {
      const res = await fetch('/api/recon/live', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: reconTarget.trim() })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Reconnaissance failed.');
      }
      setReconResult(data.result);
    } catch (err: any) {
      setReconError(err.message || 'Reconnaissance error');
    } finally {
      setIsReconRunning(false);
    }
  };

  const handleRunFuzzer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fuzzTarget.trim()) return;

    setIsFuzzing(true);
    setFuzzError(null);
    setFuzzResults([]);

    try {
      const res = await fetch('/api/fuzzer/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: fuzzTarget.trim() })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Endpoint fuzzing failed.');
      }
      setFuzzResults(data.results || []);
    } catch (err: any) {
      setFuzzError(err.message || 'Fuzzing error');
    } finally {
      setIsFuzzing(false);
    }
  };

  return (
    <div className="space-y-4 pb-24">
      {/* Workspace Header & Sub-Mode Switcher */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <Crosshair className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white font-mono-code">Security Scanner & Recon Suite</h2>
              <p className="text-[11px] text-slate-400">Deterministic vulnerability checks, live DNS/SSL recon & route fuzzing</p>
            </div>
          </div>
        </div>

        {/* Sub-Mode Tabs */}
        <div className="grid grid-cols-3 gap-1.5 p-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono-code">
          <button
            onClick={() => setActiveSubTab('scanners')}
            className={`py-1.5 px-2 rounded-md font-bold transition-all flex items-center justify-center gap-1.5 ${
              activeSubTab === 'scanners'
                ? 'bg-slate-800 text-emerald-400 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Audits & Scans</span>
          </button>

          <button
            onClick={() => setActiveSubTab('recon')}
            className={`py-1.5 px-2 rounded-md font-bold transition-all flex items-center justify-center gap-1.5 ${
              activeSubTab === 'recon'
                ? 'bg-slate-800 text-cyan-400 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Globe2 className="w-3.5 h-3.5" />
            <span>Live Recon & SSL</span>
          </button>

          <button
            onClick={() => setActiveSubTab('fuzzer')}
            className={`py-1.5 px-2 rounded-md font-bold transition-all flex items-center justify-center gap-1.5 ${
              activeSubTab === 'fuzzer'
                ? 'bg-slate-800 text-amber-400 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <FileSearch className="w-3.5 h-3.5" />
            <span>Route Fuzzer</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SUB-MODE 1: AUTOMATED AUDITS & SCANNERS                                   */}
      {/* ========================================================================= */}
      {activeSubTab === 'scanners' && (
        <div className="space-y-4">
          <form onSubmit={handleStartScan} className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white font-mono-code uppercase">Dispatch Assessment Job</span>
              {emergencyStop && (
                <span className="text-[10px] text-rose-400 font-mono-code font-bold">EMERGENCY STOP ACTIVE</span>
              )}
            </div>

            {errorMsg && (
              <div className="p-2.5 rounded-lg bg-rose-950/80 border border-rose-800 text-rose-300 text-xs font-mono-code">
                {errorMsg}
              </div>
            )}

            <div className="space-y-1">
              <label className="text-[11px] text-slate-400 font-mono-code">Target URL</label>
              <input
                type="text"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="http://localhost:3000/api/lab/headers"
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-emerald-500"
                required
              />
            </div>

            <div className="space-y-1">
              <label className="text-[11px] text-slate-400 font-mono-code">Assessment Technique</label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono-code">
                {[
                  { id: 'exposure', label: 'Fast Exposure', desc: 'Headers & Dotfiles' },
                  { id: 'heuristics', label: 'Heuristics', desc: 'Canary & CORS' },
                  { id: 'subfinder', label: 'Subfinder', desc: 'Passive Subdomains' },
                  { id: 'nuclei', label: 'Nuclei', desc: 'Baseline Templates' }
                ].map(type => (
                  <button
                    key={type.id}
                    type="button"
                    onClick={() => setScanType(type.id)}
                    className={`p-2 rounded-lg border text-left transition-all ${
                      scanType === type.id
                        ? 'bg-slate-850 border-emerald-500 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    <div className="font-bold text-[11px]">{type.label}</div>
                    <div className="text-[9px] text-slate-500">{type.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            <button
              type="submit"
              disabled={isStarting || emergencyStop}
              className={`w-full py-2.5 px-4 rounded-lg font-mono-code text-xs font-bold flex items-center justify-center gap-2 transition-all ${
                emergencyStop 
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-emerald-500 hover:bg-emerald-450 text-slate-950 active:scale-98 shadow-sm'
              }`}
            >
              {isStarting ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
              <span>{isStarting ? 'Initiating Scan Engine...' : 'Run Authorized Audit'}</span>
            </button>
          </form>

          {/* Jobs History Table */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white font-mono-code uppercase">Recent Audit Executions</span>
              <span className="text-[10px] text-slate-500 font-mono-code">{scans.length} recorded</span>
            </div>

            {scans.length === 0 ? (
              <div className="py-8 text-center text-slate-500 font-mono-code text-xs">
                No scans dispatched yet.
              </div>
            ) : (
              <div className="space-y-2">
                {scans.slice(0, 10).map(scan => (
                  <div key={scan.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2 text-xs font-mono-code">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${
                          scan.status === 'completed' ? 'bg-emerald-500' :
                          scan.status === 'running' ? 'bg-cyan-500 animate-pulse' :
                          scan.status === 'failed' ? 'bg-rose-500' : 'bg-slate-500'
                        }`} />
                        <span className="font-bold text-slate-200 truncate">{scan.target}</span>
                        <span className="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-400 uppercase">
                          {scan.scan_type}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : 'Pending'}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`text-[10px] font-bold ${
                        scan.status === 'completed' ? 'text-emerald-400' :
                        scan.status === 'running' ? 'text-cyan-400' : 'text-slate-400'
                      }`}>
                        {scan.status.toUpperCase()}
                      </span>
                      {scan.status === 'running' && (
                        <button
                          onClick={() => onCancelScan(scan.id)}
                          className="p-1 rounded text-rose-400 hover:bg-rose-950/50"
                          title="Cancel scan"
                        >
                          <StopCircle className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-MODE 2: LIVE RECONNAISSANCE & SSL/TLS INSPECTOR                       */}
      {/* ========================================================================= */}
      {activeSubTab === 'recon' && (
        <div className="space-y-4">
          <form onSubmit={handleRunRecon} className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white font-mono-code uppercase flex items-center gap-1.5">
                <Globe2 className="w-3.5 h-3.5 text-cyan-400" />
                Live Target Reconnaissance & SSL Inspector
              </span>
            </div>

            {reconError && (
              <div className="p-2.5 rounded-lg bg-rose-950/80 border border-rose-800 text-rose-300 text-xs font-mono-code">
                {reconError}
              </div>
            )}

            <div className="space-y-1">
              <label className="text-[11px] text-slate-400 font-mono-code">Host or Domain</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={reconTarget}
                  onChange={e => setReconTarget(e.target.value)}
                  placeholder="example.com or localhost:3000"
                  className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-cyan-500"
                  required
                />
                <button
                  type="submit"
                  disabled={isReconRunning}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold font-mono-code text-xs flex items-center gap-1.5 shrink-0 transition-all active:scale-98"
                >
                  {isReconRunning ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                  <span>{isReconRunning ? 'Probing...' : 'Run Live Recon'}</span>
                </button>
              </div>
            </div>
          </form>

          {reconResult && (
            <div className="space-y-4">
              {/* Security Headers Grade Banner */}
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between gap-3">
                <div>
                  <span className="text-[10px] text-slate-400 font-mono-code uppercase block">Observatory Security Grade</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={`text-2xl font-black font-mono-code px-3 py-1 rounded-lg border ${
                      reconResult.securityHeadersGrade.grade.startsWith('A') ? 'bg-emerald-950 text-emerald-400 border-emerald-800' :
                      reconResult.securityHeadersGrade.grade === 'B' ? 'bg-blue-950 text-blue-400 border-blue-800' :
                      reconResult.securityHeadersGrade.grade === 'C' ? 'bg-amber-950 text-amber-400 border-amber-800' :
                      'bg-rose-950 text-rose-400 border-rose-800'
                    }`}>
                      {reconResult.securityHeadersGrade.grade}
                    </span>
                    <div>
                      <span className="text-sm font-bold text-white font-mono-code">
                        Score: {reconResult.securityHeadersGrade.score} / 100
                      </span>
                      <p className="text-[10px] text-slate-400 font-mono-code">Defensive Header Posture</p>
                    </div>
                  </div>
                </div>

                <div className="text-right font-mono-code text-xs">
                  <span className="text-slate-400 text-[10px] block">Target Host:</span>
                  <span className="font-bold text-white">{reconResult.host}</span>
                </div>
              </div>

              {/* Technology Stack Grid */}
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
                <span className="text-xs font-bold text-white font-mono-code uppercase flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  Detected Technology Stack
                </span>

                {reconResult.technologies.length === 0 ? (
                  <p className="text-xs text-slate-500 font-mono-code">No distinct server banner or framework exposed.</p>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {reconResult.technologies.map((t, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono-code">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-emerald-400">{t.name}</span>
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">{t.category}</span>
                        </div>
                        <div className="text-[10px] text-slate-500 mt-1 truncate">{t.evidence}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Live DNS Records Card */}
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
                <span className="text-xs font-bold text-white font-mono-code uppercase flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-emerald-400" />
                  Live DNS Records
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono-code">
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-slate-400 text-[10px] block font-bold">A Records (IPv4):</span>
                    {reconResult.dns.a.length > 0 ? (
                      reconResult.dns.a.map((ip, i) => <div key={i} className="text-cyan-300 text-[11px]">{ip}</div>)
                    ) : (
                      <span className="text-slate-600 text-[10px]">None</span>
                    )}
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-slate-400 text-[10px] block font-bold">MX Records:</span>
                    {reconResult.dns.mx.length > 0 ? (
                      reconResult.dns.mx.map((m, i) => <div key={i} className="text-cyan-300 text-[11px] truncate">[{m.priority}] {m.exchange}</div>)
                    ) : (
                      <span className="text-slate-600 text-[10px]">None</span>
                    )}
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1 sm:col-span-2">
                    <span className="text-slate-400 text-[10px] block font-bold">TXT Records (SPF / Verification):</span>
                    {reconResult.dns.txt.length > 0 ? (
                      reconResult.dns.txt.map((t, i) => <div key={i} className="text-slate-300 text-[10px] break-all">{t}</div>)
                    ) : (
                      <span className="text-slate-600 text-[10px]">None</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Real SSL/TLS Certificate & SANs Subdomains */}
              {reconResult.tls && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white font-mono-code uppercase flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-emerald-400" />
                      SSL / TLS Certificate & SANs Subdomains
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded font-mono-code bg-emerald-950 text-emerald-400 border border-emerald-800">
                      {reconResult.tls.daysRemaining} days remaining
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono-code">
                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-slate-400 text-[9px] block">Issuer CA:</span>
                      <span className="text-white text-[11px] truncate block">{reconResult.tls.issuer}</span>
                    </div>

                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-slate-400 text-[9px] block">Protocol:</span>
                      <span className="text-cyan-400 text-[11px] block">{reconResult.tls.protocol}</span>
                    </div>

                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-slate-400 text-[9px] block">Cipher Suite:</span>
                      <span className="text-slate-300 text-[10px] truncate block">{reconResult.tls.cipher}</span>
                    </div>
                  </div>

                  {reconResult.tls.sans.length > 0 && (
                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1 text-xs font-mono-code">
                      <span className="text-slate-400 text-[10px] block font-bold">
                        SAN Subdomains Discovered ({reconResult.tls.sans.length}):
                      </span>
                      <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                        {reconResult.tls.sans.map((san, idx) => (
                          <span key={idx} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 text-[10px]">
                            {san}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-MODE 3: REAL RATE-LIMITED ENDPOINT & ROUTE FUZZER                     */}
      {/* ========================================================================= */}
      {activeSubTab === 'fuzzer' && (
        <div className="space-y-4">
          <form onSubmit={handleRunFuzzer} className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white font-mono-code uppercase flex items-center gap-1.5">
                <FileSearch className="w-3.5 h-3.5 text-amber-400" />
                Live Endpoint & Hidden Route Fuzzer
              </span>
            </div>

            {fuzzError && (
              <div className="p-2.5 rounded-lg bg-rose-950/80 border border-rose-800 text-rose-300 text-xs font-mono-code">
                {fuzzError}
              </div>
            )}

            <div className="space-y-1">
              <label className="text-[11px] text-slate-400 font-mono-code">Base Target URL</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={fuzzTarget}
                  onChange={e => setFuzzTarget(e.target.value)}
                  placeholder="http://localhost:3000"
                  className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-amber-500"
                  required
                />
                <button
                  type="submit"
                  disabled={isFuzzing || emergencyStop}
                  className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-450 text-slate-950 font-bold font-mono-code text-xs flex items-center gap-1.5 shrink-0 transition-all active:scale-98"
                >
                  {isFuzzing ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                  <span>{isFuzzing ? 'Fuzzing...' : 'Start Fuzzing'}</span>
                </button>
              </div>
            </div>
          </form>

          {/* Fuzzer Results Grid */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white font-mono-code uppercase">Fuzzer Response Stream</span>
              <span className="text-[10px] text-slate-500 font-mono-code">
                {fuzzResults.filter(r => r.isInteresting).length} active / {fuzzResults.length} probed
              </span>
            </div>

            {fuzzResults.length === 0 ? (
              <div className="py-8 text-center text-slate-500 font-mono-code text-xs">
                No active fuzzing session. Press "Start Fuzzing" to probe 20 high-value paths.
              </div>
            ) : (
              <div className="space-y-1.5 max-h-96 overflow-y-auto">
                {fuzzResults.map((row, idx) => (
                  <div
                    key={idx}
                    className={`p-2 rounded-lg border flex items-center justify-between gap-2 text-xs font-mono-code transition-all ${
                      row.findingCreated ? 'bg-rose-950/40 border-rose-600' :
                      row.isInteresting ? 'bg-slate-950 border-slate-700' :
                      'bg-slate-950/60 border-slate-900 opacity-60'
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                        row.statusCode >= 200 && row.statusCode < 300 ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                        row.statusCode >= 300 && row.statusCode < 400 ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' :
                        row.statusCode === 403 ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {row.statusCode || 'ERR'}
                      </span>

                      <span className="text-white font-bold truncate">{row.path}</span>

                      {row.findingCreated && (
                        <span className="text-[9px] px-1 py-0.2 rounded bg-rose-600 text-white font-bold uppercase">
                          CONFIRMED LEAK
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-[10px] text-slate-500">{row.durationMs}ms</span>
                      <span className="text-[10px] text-slate-400">{row.contentLength} B</span>
                      <button
                        onClick={() => handleCopy(`curl -s -I "${row.url}"`, `fuzz-curl-${idx}`)}
                        className="p-1 rounded bg-slate-900 text-slate-400 hover:text-white"
                        title="Copy curl repro command"
                      >
                        {copiedKey === `fuzz-curl-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

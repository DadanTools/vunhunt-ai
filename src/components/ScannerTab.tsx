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
  Zap
} from 'lucide-react';
import { ScanJob, ScopeRule } from '../types.ts';

interface ScannerTabProps {
  scans: ScanJob[];
  scopes: ScopeRule[];
  emergencyStop: boolean;
  onStartScan: (target: string, scanType: string) => Promise<any>;
  onCancelScan: (scanId: string) => Promise<any>;
}

export const ScannerTab: React.FC<ScannerTabProps> = ({
  scans,
  scopes,
  emergencyStop,
  onStartScan,
  onCancelScan
}) => {
  const activeScopes = scopes.filter(s => s.is_active === 1);
  const [targetUrl, setTargetUrl] = useState(
    activeScopes.length > 0 ? `http://${activeScopes[0].target}/api/lab/headers` : 'http://localhost:3000/api/lab/headers'
  );
  const [scanType, setScanType] = useState('exposure');
  const [isStarting, setIsStarting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
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

  return (
    <div className="space-y-4 pb-20">
      {/* Scan Dispatcher Form */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
            <Crosshair className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white font-mono-code">Vulnerability Scanner</h2>
            <p className="text-[11px] text-slate-400">Rate-limited, non-destructive audit engine</p>
          </div>
        </div>

        {errorMsg && (
          <div className="p-3 rounded-lg bg-rose-950 border border-rose-800 text-rose-300 text-xs font-mono-code">
            {errorMsg}
          </div>
        )}

        {emergencyStop && (
          <div className="p-3 rounded-lg bg-rose-950 border border-rose-800 text-rose-200 text-xs font-mono-code flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            Scanner locked: Global Emergency Stop is engaged.
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
              Target URL (Must be within Authorized Scope)
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              placeholder="http://localhost:3000/api/lab/headers"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-emerald-500"
              required
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
              Scan Type / Module
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setScanType('exposure')}
                className={`py-2 px-2 rounded-lg border text-xs font-mono-code text-center transition-all ${
                  scanType === 'exposure'
                    ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                Exposure
              </button>
              <button
                type="button"
                onClick={() => setScanType('injection')}
                className={`py-2 px-2 rounded-lg border text-xs font-mono-code text-center transition-all ${
                  scanType === 'injection'
                    ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                Injection
              </button>
              <button
                type="button"
                onClick={() => setScanType('full')}
                className={`py-2 px-2 rounded-lg border text-xs font-mono-code text-center transition-all ${
                  scanType === 'full'
                    ? 'bg-purple-950/80 border-purple-500 text-purple-300 font-bold'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                Full Audit
              </button>
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 text-[11px] text-slate-400">
            {scanType === 'exposure' && (
              <span>Audits HTTP headers, TLS attributes, cookie flags, and low-impact sensitive paths (.env, .git) with 150ms rate-limiting.</span>
            )}
            {scanType === 'injection' && (
              <span>Safe reflected canary string check & CORS origin reflection heuristics. Strictly non-destructive.</span>
            )}
            {scanType === 'full' && (
              <span>Combines Fast Exposure and Safe Injection heuristics sequentially into a single unified audit.</span>
            )}
          </div>

          <button
            type="submit"
            disabled={isStarting || emergencyStop || !targetUrl.trim()}
            className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono-code text-xs transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-1.5"
          >
            <Play className="w-4 h-4 fill-slate-950" />
            <span>{isStarting ? 'Dispatching...' : 'Launch Authorized Scan'}</span>
          </button>
        </form>
      </div>

      {/* Scans History & Live Progress */}
      <div className="space-y-2">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono-code flex items-center justify-between">
          <span>Scan Jobs History ({scans.length})</span>
          <span className="text-[10px] text-slate-500 font-mono-code">SQLite persisted</span>
        </h3>

        {scans.length === 0 ? (
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400 font-mono-code">
            No scan jobs dispatched yet.
          </div>
        ) : (
          <div className="space-y-2">
            {scans.map(scan => {
              const isRunning = scan.status === 'running' || scan.status === 'queued';
              return (
                <div key={scan.id} className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="font-mono-code font-bold text-white break-all">{scan.target}</span>
                        <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono-code font-bold ${
                          scan.status === 'completed'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : scan.status === 'running'
                            ? 'bg-cyan-950 text-cyan-400 border border-cyan-800 animate-pulse'
                            : scan.status === 'cancelled'
                            ? 'bg-slate-800 text-slate-400'
                            : 'bg-rose-950 text-rose-400 border border-rose-800'
                        }`}>
                          {scan.status.toUpperCase()}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono-code">
                          {scan.scan_type}
                        </span>
                      </div>

                      {scan.error_message && (
                        <p className="mt-1 text-[11px] text-rose-300 font-mono-code break-all">
                          {scan.error_message}
                        </p>
                      )}

                      <div className="mt-1 flex items-center gap-2 text-[10px] text-slate-500 font-mono-code">
                        <span>Started: {new Date(scan.started_at).toLocaleTimeString()}</span>
                        {scan.completed_at && (
                          <>
                            <span>•</span>
                            <span>Finished: {new Date(scan.completed_at).toLocaleTimeString()}</span>
                          </>
                        )}
                      </div>
                    </div>

                    {isRunning && (
                      <button
                        onClick={() => onCancelScan(scan.id)}
                        className="px-2 py-1 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 text-[10px] font-mono-code shrink-0"
                      >
                        Cancel
                      </button>
                    )}
                  </div>

                  {isRunning && (
                    <div className="mt-2.5 flex items-center gap-2">
                      <div className="flex-1 bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                        <div 
                          className="bg-cyan-400 h-full transition-all duration-300"
                          style={{ width: `${Math.max(scan.progress, 5)}%` }}
                        />
                      </div>
                      <span className="font-mono-code text-[10px] text-cyan-400">{scan.progress}%</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

import React, { useState } from 'react';
import { 
  Terminal, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  Sliders, 
  ShieldCheck, 
  Copy,
  Info
} from 'lucide-react';
import { ToolHealth, ScopeRule } from '../types.ts';

interface TemplatesTabProps {
  scopes: ScopeRule[];
  tools: Record<string, ToolHealth>;
  onStartTemplateScan: (target: string, rateLimit: number) => Promise<any>;
}

export const TemplatesTab: React.FC<TemplatesTabProps> = ({
  scopes,
  tools,
  onStartTemplateScan
}) => {
  const activeScopes = scopes.filter(s => s.is_active === 1);
  const [targetUrl, setTargetUrl] = useState(
    activeScopes.length > 0 ? `http://${activeScopes[0].target}` : 'http://localhost:3000'
  );
  const [rateLimit, setRateLimit] = useState(10);
  const [isRunning, setIsRunning] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  const nucleiReady = tools.nuclei?.isAvailable;

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsRunning(true);
    setFeedback(null);

    try {
      await onStartTemplateScan(targetUrl.trim(), rateLimit);
      setFeedback('Template scan queued successfully. Track execution in Scanner tab.');
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-4 pb-20">
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-purple-950 border border-purple-500/40 flex items-center justify-center text-purple-400">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white font-mono-code">Known CVE / Template Engine</h2>
              <p className="text-[11px] text-slate-400">Nuclei adapter with controlled concurrency & rate limits</p>
            </div>
          </div>

          <span className={`text-[10px] px-2 py-0.5 rounded font-mono-code font-bold ${
            nucleiReady ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
          }`}>
            {nucleiReady ? 'INSTALLED & READY' : 'NOT INSTALLED'}
          </span>
        </div>

        <p className="text-[11px] text-slate-300 leading-relaxed">
          Executes community-vetted, non-destructive security templates against authorized targets. Version matches are treated as leads, not verified exploitability.
        </p>
      </div>

      {feedback && (
        <div className="p-3 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono-code text-slate-200">
          {feedback}
        </div>
      )}

      {!nucleiReady ? (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 space-y-3">
          <div className="flex items-center gap-2 text-amber-300 font-bold font-mono-code">
            <AlertTriangle className="w-4 h-4" />
            Nuclei Binary Not Detected in PATH
          </div>

          <p className="leading-relaxed">
            As per VulnHunter AI design rules, missing tools report honest unavailable status instead of simulated success. You can continue using native VulnHunter exposure and injection detectors.
          </p>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <p className="text-[11px] font-semibold text-slate-200 font-mono-code">
              To install Nuclei locally in Android Termux:
            </p>
            <pre className="p-2 rounded bg-slate-900 text-slate-200 text-[10px] font-mono-code overflow-x-auto">
pkg install -y golang
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:~/go/bin
            </pre>
          </div>
        </div>
      ) : (
        <form onSubmit={handleLaunch} className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div>
            <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
              Authorized Target URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-purple-500"
              required
            />
          </div>

          <div>
            <div className="flex items-center justify-between text-[11px] font-mono-code text-slate-400 mb-1">
              <span>Rate Limit (Requests / Sec)</span>
              <span className="text-purple-400 font-bold">{rateLimit} req/s</span>
            </div>
            <input
              type="range"
              min="1"
              max="25"
              value={rateLimit}
              onChange={e => setRateLimit(parseInt(e.target.value, 10))}
              className="w-full accent-purple-500"
            />
            <div className="flex justify-between text-[10px] text-slate-500 font-mono-code mt-0.5">
              <span>1 (Conservative)</span>
              <span>10 (Default)</span>
              <span>25 (Max)</span>
            </div>
          </div>

          <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400">
            Selected safe tags: <code>tech, exposure, misconfig</code>. Destructive exploit templates are strictly filtered out.
          </div>

          <button
            type="submit"
            disabled={isRunning || !targetUrl.trim()}
            className="w-full py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold font-mono-code text-xs transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-1.5"
          >
            <Play className="w-4 h-4 fill-white" />
            <span>{isRunning ? 'Queuing Scan...' : 'Launch Controlled Nuclei Scan'}</span>
          </button>
        </form>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import { 
  FlaskConical, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  ShieldCheck, 
  Layers, 
  ExternalLink,
  RefreshCw,
  Bug
} from 'lucide-react';

interface LocalLabTabProps {
  onRunTest: (targetUrl: string, scanType: string) => Promise<any>;
}

export const LocalLabTab: React.FC<LocalLabTabProps> = ({ onRunTest }) => {
  const [runningTarget, setRunningTarget] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ target: string; message: string } | null>(null);

  const labEndpoints = [
    {
      title: 'Insecure Headers & Cookie Fixture',
      path: '/api/lab/headers',
      scanType: 'exposure',
      category: 'Security Headers',
      expected: 'Missing CSP, missing X-Frame-Options, insecure Set-Cookie attributes',
      type: 'vulnerable'
    },
    {
      title: 'Hardened Baseline Fixture (Negative Control)',
      path: '/api/lab/secure-endpoint',
      scanType: 'exposure',
      category: 'Negative Test',
      expected: 'Zero findings! Demonstrates scanner does NOT produce false positives when hardened',
      type: 'hardened'
    },
    {
      title: 'Safe Reflected Input Canary Fixture',
      path: '/api/lab/reflected?q=test',
      scanType: 'injection',
      category: 'XSS Canary',
      expected: 'Safe non-destructive canary reflection indicator',
      type: 'vulnerable'
    },
    {
      title: 'Permissive CORS Misconfiguration Fixture',
      path: '/api/lab/cors',
      scanType: 'injection',
      category: 'CORS Origin Reflection',
      expected: 'Permissive origin reflection with credentials',
      type: 'vulnerable'
    },
    {
      title: 'Sensitive Path Exposure Fixture',
      path: '/api/lab/sensitive-path/.env',
      scanType: 'exposure',
      category: 'Information Disclosure',
      expected: 'Exposed dotfile configuration indicator (.env / git)',
      type: 'vulnerable'
    }
  ];

  const handleTestEndpoint = async (path: string, scanType: string) => {
    const fullUrl = `http://localhost:3000${path}`;
    setRunningTarget(path);
    setLastResult(null);

    try {
      await onRunTest(fullUrl, scanType);
      setLastResult({
        target: path,
        message: `Scan successfully queued against local lab fixture "${path}". Check the Findings and Scanners tabs to inspect results.`
      });
    } catch (err: any) {
      setLastResult({
        target: path,
        message: `Lab test error: ${err.message}`
      });
    } finally {
      setRunningTarget(null);
    }
  };

  return (
    <div className="space-y-4 pb-20">
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <FlaskConical className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white font-mono-code">Local Security Test Lab</h2>
            <p className="text-[11px] text-slate-400">Deterministic, zero-risk local vulnerability fixtures</p>
          </div>
        </div>
        <p className="text-[11px] text-slate-300 leading-relaxed">
          These built-in fixtures let you test and verify every detector locally in Android Termux or this browser session with <strong>zero external network traffic</strong> and <strong>zero risk</strong> to production systems.
        </p>
      </div>

      {lastResult && (
        <div className="p-3 rounded-xl bg-slate-900 border border-emerald-500/40 text-xs font-mono-code text-slate-200">
          <div className="flex items-center gap-2 text-emerald-400 font-bold mb-1">
            <CheckCircle className="w-4 h-4" /> Lab Dispatch Result
          </div>
          <p className="text-[11px] text-slate-300">{lastResult.message}</p>
        </div>
      )}

      <div className="space-y-2">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono-code">
          Available Lab Targets ({labEndpoints.length})
        </h3>

        {labEndpoints.map((item, idx) => (
          <div key={idx} className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs space-y-2">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-bold text-white font-mono-code text-xs">{item.title}</span>
                  <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono-code font-bold ${
                    item.type === 'vulnerable'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {item.type.toUpperCase()}
                  </span>
                </div>
                <div className="mt-1 font-mono-code text-[11px] text-slate-400 break-all">
                  <code>{item.path}</code>
                </div>
              </div>

              <button
                onClick={() => handleTestEndpoint(item.path, item.scanType)}
                disabled={runningTarget === item.path}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono-code text-xs flex items-center gap-1.5 transition-all shrink-0 active:scale-95 disabled:opacity-50"
              >
                {runningTarget === item.path ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5 fill-slate-950" />
                )}
                <span>Test</span>
              </button>
            </div>

            <div className="p-2 rounded bg-slate-950 border border-slate-800/80 text-[10px] font-mono-code text-slate-400">
              <span className="text-slate-500">Expected Outcome: </span>
              <span className="text-slate-300">{item.expected}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

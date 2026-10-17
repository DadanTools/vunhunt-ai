import React, { useState } from 'react';
import { 
  Layers, 
  Send, 
  CheckCircle2, 
  AlertTriangle, 
  Lock, 
  ShieldCheck, 
  Key, 
  FileText,
  UserCheck
} from 'lucide-react';

interface AuthIdorTabProps {
  onRunComparison: (data: {
    userAToken: string;
    userBToken: string;
    targetUrlPattern: string;
    objectAId: string;
    objectBId: string;
  }) => Promise<any>;
}

export const AuthIdorTab: React.FC<AuthIdorTabProps> = ({ onRunComparison }) => {
  const [userAToken, setUserAToken] = useState('token-alice');
  const [userBToken, setUserBToken] = useState('token-bob');
  const [targetUrlPattern, setTargetUrlPattern] = useState('http://localhost:3000/api/lab/idor/document/{ID}');
  const [objectAId, setObjectAId] = useState('doc_a_101');
  const [objectBId, setObjectBId] = useState('doc_b_202');
  const [isRunning, setIsRunning] = useState(false);
  const [comparisonResult, setComparisonResult] = useState<any>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsRunning(true);
    setErrorMsg(null);
    setComparisonResult(null);

    try {
      const res = await onRunComparison({
        userAToken,
        userBToken,
        targetUrlPattern,
        objectAId,
        objectBId
      });
      setComparisonResult(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Comparison failed.');
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-4 pb-20">
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-orange-950 border border-orange-500/40 flex items-center justify-center text-orange-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white font-mono-code">Auth & IDOR / BOLA Workbench</h2>
            <p className="text-[11px] text-slate-400">Safe multi-tenant object access comparison</p>
          </div>
        </div>
        <p className="text-[11px] text-slate-300 leading-relaxed">
          Provides safe, authorized BOLA (Broken Object Level Authorization) detection by comparing dual user tokens against owner-controlled test objects. <strong>Never tests unauthorized third-party accounts.</strong>
        </p>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-lg bg-rose-950 border border-rose-800 text-rose-300 text-xs font-mono-code">
          {errorMsg}
        </div>
      )}

      <form onSubmit={handleSubmit} className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <h3 className="text-xs font-bold text-slate-300 font-mono-code uppercase tracking-wider">
          Dual-Account Test Configuration
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <span className="text-xs font-bold text-cyan-400 font-mono-code flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5" /> Tenant A (Alice)
            </span>
            <div>
              <label className="block text-[10px] font-mono-code text-slate-400 mb-0.5">Authorization Token</label>
              <input
                type="text"
                value={userAToken}
                onChange={e => setUserAToken(e.target.value)}
                placeholder="Bearer token-alice"
                className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>
            <div>
              <label className="block text-[10px] font-mono-code text-slate-400 mb-0.5">Owned Object ID</label>
              <input
                type="text"
                value={objectAId}
                onChange={e => setObjectAId(e.target.value)}
                placeholder="doc_a_101"
                className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <span className="text-xs font-bold text-purple-400 font-mono-code flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5" /> Tenant B (Bob)
            </span>
            <div>
              <label className="block text-[10px] font-mono-code text-slate-400 mb-0.5">Authorization Token</label>
              <input
                type="text"
                value={userBToken}
                onChange={e => setUserBToken(e.target.value)}
                placeholder="Bearer token-bob"
                className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-purple-500"
                required
              />
            </div>
            <div>
              <label className="block text-[10px] font-mono-code text-slate-400 mb-0.5">Owned Object ID</label>
              <input
                type="text"
                value={objectBId}
                onChange={e => setObjectBId(e.target.value)}
                placeholder="doc_b_202"
                className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-purple-500"
                required
              />
            </div>
          </div>
        </div>

        <div>
          <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
            Endpoint URL Template (with <code>{'{ID}'}</code> placeholder)
          </label>
          <input
            type="text"
            value={targetUrlPattern}
            onChange={e => setTargetUrlPattern(e.target.value)}
            placeholder="http://localhost:3000/api/lab/idor/document/{ID}"
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-emerald-500"
            required
          />
        </div>

        <button
          type="submit"
          disabled={isRunning}
          className="w-full py-2.5 rounded-lg bg-orange-600 hover:bg-orange-500 text-slate-950 font-bold font-mono-code text-xs transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-1.5"
        >
          <Send className="w-3.5 h-3.5" />
          <span>{isRunning ? 'Executing Comparison Matrix...' : 'Run Safe IDOR Comparison'}</span>
        </button>
      </form>

      {/* Comparison Results */}
      {comparisonResult && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 font-mono-code text-xs">
          <div className="flex items-center justify-between">
            <span className="font-bold text-white text-xs">BOLA / IDOR Analysis Outcome</span>
            <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
              comparisonResult.comparison.vulnerable_idor_detected
                ? 'bg-rose-950 text-rose-300 border border-rose-800 animate-pulse'
                : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
            }`}>
              {comparisonResult.comparison.vulnerable_idor_detected ? 'VULNERABILITY CONFIRMED' : 'ACCESS PROPERLY RESTRICTED'}
            </span>
          </div>

          <div className="grid grid-cols-3 gap-2 text-center text-[10px]">
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-400 block">User A Own Doc</span>
              <span className="text-emerald-400 font-bold text-xs mt-0.5 block">
                HTTP {comparisonResult.comparison.user_a_own_object_status}
              </span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-400 block">User B Own Doc</span>
              <span className="text-emerald-400 font-bold text-xs mt-0.5 block">
                HTTP {comparisonResult.comparison.user_b_own_object_status}
              </span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-400 block">A → B Cross-Read</span>
              <span className={`font-bold text-xs mt-0.5 block ${
                comparisonResult.comparison.vulnerable_idor_detected ? 'text-rose-400' : 'text-slate-300'
              }`}>
                HTTP {comparisonResult.comparison.user_a_cross_read_status}
              </span>
            </div>
          </div>

          {comparisonResult.comparison.vulnerable_idor_detected && (
            <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-200 text-[11px] leading-relaxed">
              <strong>Observation:</strong> Tenant A provided valid credentials for Tenant A, requested Tenant B's private object (<code>{objectBId}</code>), and received HTTP 200 with object payload. A high-severity finding has been automatically recorded in Findings.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

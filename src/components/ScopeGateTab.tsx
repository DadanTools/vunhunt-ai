import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Plus, 
  Trash2, 
  ToggleLeft, 
  ToggleRight, 
  AlertTriangle, 
  Check, 
  Lock, 
  AlertOctagon,
  Info
} from 'lucide-react';
import { ScopeRule } from '../types.ts';

interface ScopeGateTabProps {
  scopes: ScopeRule[];
  onAddScope: (target: string, type: string, allowPrivate: boolean, notes: string) => Promise<void>;
  onDeleteScope: (id: string) => Promise<void>;
  onToggleScope: (id: string) => Promise<void>;
  emergencyStop: boolean;
  onToggleEmergencyStop: () => void;
}

export const ScopeGateTab: React.FC<ScopeGateTabProps> = ({
  scopes,
  onAddScope,
  onDeleteScope,
  onToggleScope,
  emergencyStop,
  onToggleEmergencyStop
}) => {
  const [newTarget, setNewTarget] = useState('');
  const [targetType, setTargetType] = useState('host');
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [notes, setNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) return;

    setIsSubmitting(true);
    setFeedback(null);

    try {
      await onAddScope(newTarget.trim(), targetType, allowPrivate, notes.trim());
      setNewTarget('');
      setNotes('');
      setFeedback({ type: 'success', msg: `Successfully added ${newTarget} to authorized scope.` });
    } catch (err: any) {
      setFeedback({ type: 'error', msg: err.message || 'Failed to add target.' });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-4 pb-20">
      {/* Scope Gate Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white font-mono-code">Scope & Safety Gate</h2>
              <p className="text-[11px] text-slate-400">Server-side strict target authorization</p>
            </div>
          </div>
          <button
            onClick={onToggleEmergencyStop}
            className={`px-2.5 py-1 rounded text-[11px] font-mono-code font-bold transition-all ${
              emergencyStop
                ? 'bg-rose-600 text-white animate-pulse'
                : 'bg-rose-950/60 text-rose-300 border border-rose-800'
            }`}
          >
            {emergencyStop ? 'STOPPED' : 'ENGAGE STOP'}
          </button>
        </div>

        <div className="mt-3 p-3 rounded-lg bg-slate-950 border border-slate-800/80 text-xs text-slate-300 space-y-1.5">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold font-mono-code text-[11px]">
            <Check className="w-3.5 h-3.5" /> Zero-Trust Outbound Request Enforcement
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Every active scan, crawler request, template probe, and proxy replay is verified server-side. Out-of-scope destinations and internal cloud metadata (169.254.169.254) are permanently blocked.
          </p>
        </div>
      </div>

      {/* Add New Scope Target Form */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono-code mb-3 flex items-center gap-1.5">
          <Plus className="w-3.5 h-3.5 text-emerald-400" /> Add Authorized Target
        </h3>

        {feedback && (
          <div className={`p-2.5 mb-3 rounded-lg text-xs font-mono-code ${
            feedback.type === 'success' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
          }`}>
            {feedback.msg}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
              Target (Domain, Host, or Wildcard)
            </label>
            <input
              type="text"
              value={newTarget}
              onChange={e => setNewTarget(e.target.value)}
              placeholder="e.g. localhost:3000, target.com, *.target.com"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-emerald-500"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
                Target Type
              </label>
              <select
                value={targetType}
                onChange={e => setTargetType(e.target.value)}
                className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-emerald-500"
              >
                <option value="host">Exact Host</option>
                <option value="domain">Wildcard Domain (*.domain)</option>
                <option value="ip">IP Address</option>
                <option value="lab">Local Test Lab</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
                Private / Local IP Access
              </label>
              <button
                type="button"
                onClick={() => setAllowPrivate(!allowPrivate)}
                className={`w-full py-2 px-2.5 rounded-lg border text-xs font-mono-code flex items-center justify-between ${
                  allowPrivate
                    ? 'bg-amber-950/60 border-amber-600/70 text-amber-300'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                <span>{allowPrivate ? 'Allowed (Lab)' : 'Blocked'}</span>
                {allowPrivate ? <ToggleRight className="w-4 h-4 text-amber-400" /> : <ToggleLeft className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
              Scope Authorization Notes (Program, Rules of Engagement)
            </label>
            <input
              type="text"
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="e.g. Authorized Bug Bounty program, Lab sandbox"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-emerald-500"
            />
          </div>

          <button
            type="submit"
            disabled={isSubmitting || !newTarget.trim()}
            className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono-code text-xs transition-all active:scale-95 disabled:opacity-50 disabled:pointer-events-none"
          >
            {isSubmitting ? 'Verifying & Adding...' : 'Add To Authorized Scope'}
          </button>
        </form>
      </div>

      {/* Configured Scopes List */}
      <div className="space-y-2">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono-code flex items-center justify-between">
          <span>Configured Scope Rules ({scopes.length})</span>
          <span className="text-[10px] text-slate-500">{scopes.filter(s => s.is_active === 1).length} active</span>
        </h3>

        {scopes.length === 0 ? (
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400">
            No scope rules defined. Add a target above to begin security assessment.
          </div>
        ) : (
          <div className="space-y-2">
            {scopes.map(rule => (
              <div
                key={rule.id}
                className={`p-3 rounded-xl border transition-all ${
                  rule.is_active === 1
                    ? 'bg-slate-900 border-slate-800'
                    : 'bg-slate-950/60 border-slate-800/60 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono-code text-xs font-bold text-white break-all">
                        {rule.target}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-mono-code">
                        {rule.target_type}
                      </span>
                      {rule.allow_private_ip === 1 && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono-code">
                          lab-private
                        </span>
                      )}
                    </div>
                    {rule.notes && (
                      <p className="mt-1 text-[11px] text-slate-400 truncate">{rule.notes}</p>
                    )}
                    <span className="text-[10px] text-slate-500 font-mono-code">
                      Added: {new Date(rule.created_at).toLocaleDateString()}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      onClick={() => onToggleScope(rule.id)}
                      className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
                      title={rule.is_active === 1 ? 'Disable Rule' : 'Enable Rule'}
                    >
                      {rule.is_active === 1 ? (
                        <ToggleRight className="w-5 h-5 text-emerald-400" />
                      ) : (
                        <ToggleLeft className="w-5 h-5 text-slate-500" />
                      )}
                    </button>
                    <button
                      onClick={() => onDeleteScope(rule.id)}
                      className="p-1.5 rounded-lg hover:bg-rose-950/80 text-slate-500 hover:text-rose-400"
                      title="Delete Rule"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

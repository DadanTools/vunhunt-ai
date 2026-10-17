import React from 'react';
import { Shield, AlertOctagon, Terminal, CheckCircle2, ShieldAlert } from 'lucide-react';

interface NavbarProps {
  emergencyStop: boolean;
  onToggleEmergencyStop: () => void;
  activeScopesCount: number;
  findingsCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  emergencyStop,
  onToggleEmergencyStop,
  activeScopesCount,
  findingsCount
}) => {
  return (
    <header className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur-md border-b border-slate-800 px-3 py-2.5 sm:px-6">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-2">
        {/* Brand */}
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 text-emerald-400 shrink-0">
            <Shield className="w-5 h-5" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${emergencyStop ? 'bg-rose-400' : 'bg-emerald-400'}`}></span>
              <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${emergencyStop ? 'bg-rose-500' : 'bg-emerald-500'}`}></span>
            </span>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-base tracking-tight text-white font-mono-code truncate">
                VulnHunter<span className="text-emerald-400">.AI</span>
              </span>
              <span className="text-[10px] font-mono-code px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 hidden sm:inline-block">
                termux-native
              </span>
            </div>
            <div className="text-[11px] text-slate-400 flex items-center gap-1.5 font-mono-code">
              {emergencyStop ? (
                <span className="text-rose-400 font-semibold flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3" /> STOP ENGAGED
                </span>
              ) : (
                <span className="text-emerald-400/90 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-emerald-500" /> Scope Gate: {activeScopesCount} target{activeScopesCount === 1 ? '' : 's'}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Right Actions: Quick stats & Emergency Stop */}
        <div className="flex items-center gap-2 shrink-0">
          <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs font-mono-code">
            <span className="text-slate-400">Findings:</span>
            <span className="text-emerald-400 font-semibold">{findingsCount}</span>
          </div>

          <button
            onClick={onToggleEmergencyStop}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono-code font-bold transition-all shadow-sm active:scale-95 ${
              emergencyStop
                ? 'bg-rose-600 hover:bg-rose-500 text-white animate-pulse border border-rose-400'
                : 'bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/80'
            }`}
            title="Global Emergency Stop: Aborts all running tasks and prevents outgoing requests"
          >
            <AlertOctagon className="w-4 h-4 shrink-0" />
            <span>{emergencyStop ? 'RESUME TESTING' : 'EMERGENCY STOP'}</span>
          </button>
        </div>
      </div>
    </header>
  );
};

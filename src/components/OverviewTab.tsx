import React, { useState } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  Bug, 
  Globe, 
  Terminal, 
  Play, 
  ArrowRight, 
  FlaskConical, 
  FileText, 
  Layers, 
  Clock, 
  CheckCircle, 
  XCircle, 
  AlertOctagon, 
  ArrowLeftRight,
  Network,
  Flame,
  Activity,
  Target,
  Sparkles
} from 'lucide-react';
import { ScopeRule, ScanJob, Finding, ToolHealth, Asset } from '../types.ts';
import { TabId } from './BottomNav.tsx';
import { VulnerabilityHeatmap } from './VulnerabilityHeatmap.tsx';
import { AttackSurfaceGraph } from './AttackSurfaceGraph.tsx';

interface OverviewTabProps {
  scopes: ScopeRule[];
  scans: ScanJob[];
  findings: Finding[];
  assets: Asset[];
  tools: Record<string, ToolHealth>;
  emergencyStop: boolean;
  onNavigate: (tab: TabId) => void;
  onQuickScan: (target: string, scanType: string) => void;
  onCancelScan: (scanId: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  scopes,
  scans,
  findings,
  assets,
  tools,
  emergencyStop,
  onNavigate,
  onQuickScan,
  onCancelScan
}) => {
  const [activeVisual, setActiveVisual] = useState<'heatmap' | 'attack_surface'>('heatmap');
  const activeScopes = scopes.filter(s => s.is_active === 1);
  const activeScans = scans.filter(s => s.status === 'running' || s.status === 'queued');

  const severityCounts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };

  const defaultTarget = activeScopes.length > 0 ? activeScopes[0].target : 'http://localhost:3000/api/lab/headers';

  return (
    <div className="space-y-4 pb-20">
      {/* Banner / Security Policy Alert */}
      {emergencyStop ? (
        <div className="p-3.5 rounded-xl bg-rose-950/80 border border-rose-600/70 text-rose-200 flex items-start gap-3 animate-pulse">
          <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="text-xs">
            <span className="font-bold uppercase tracking-wider block text-rose-300">
              Emergency Killswitch Activated
            </span>
            <span>All outgoing network traffic, proxy repeaters, and scanner engines are strictly disabled.</span>
          </div>
        </div>
      ) : activeScopes.length === 0 ? (
        <div className="p-3.5 rounded-xl bg-amber-950/60 border border-amber-600/60 text-amber-200 flex items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Scope Gate Empty: You must authorize a test target before scanning.</span>
          </div>
          <button
            onClick={() => onNavigate('scope')}
            className="px-2.5 py-1 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold font-mono-code text-[11px] shrink-0"
          >
            Configure Scope
          </button>
        </div>
      ) : (
        <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="font-semibold">Scope Gate Active:</span>
            <span className="text-[11px] text-slate-400 font-mono-code">{activeScopes.length} targets locked</span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono-code truncate max-w-[200px]">
            {activeScopes.map(s => s.target).join(', ')}
          </span>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <div 
          onClick={() => onNavigate('scope')}
          className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Scope Targets</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 font-mono-code text-2xl font-bold text-white">
            {activeScopes.length}
          </div>
          <div className="mt-1 text-[10px] text-slate-400">Authorized for testing</div>
        </div>

        <div 
          onClick={() => onNavigate('findings')}
          className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Total Findings</span>
            <Bug className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 font-mono-code text-2xl font-bold text-white">
            {findings.length}
          </div>
          <div className="mt-1 text-[10px] text-slate-400">
            {severityCounts.high + severityCounts.critical} high / crit
          </div>
        </div>

        <div 
          onClick={() => onNavigate('assets')}
          className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Attack Surface</span>
            <Network className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 font-mono-code text-2xl font-bold text-white">
            {assets.length || activeScopes.length}
          </div>
          <div className="mt-1 text-[10px] text-slate-400">Hosts & Subdomains</div>
        </div>

        <div 
          onClick={() => onNavigate('tools')}
          className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Tool Engine</span>
            <Terminal className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 font-mono-code text-xs font-semibold text-emerald-400 truncate">
            {tools.python?.isAvailable ? 'Python 3 Ready' : 'Node Ready'}
          </div>
          <div className="mt-1 text-[10px] text-slate-400">Termux & CLI native</div>
        </div>
      </div>

      {/* #1 AI Bug Hunter Co-Pilot Callout Banner */}
      <div 
        onClick={() => onNavigate('copilot')}
        className="p-3.5 sm:p-4 rounded-2xl bg-gradient-to-r from-emerald-950 via-slate-900 to-cyan-950 border border-emerald-500/40 hover:border-emerald-400 cursor-pointer transition-all shadow-xl space-y-2 group"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <span className="font-bold text-white text-xs group-hover:text-emerald-300 transition-colors flex items-center gap-1.5 flex-wrap">
                #1 AI Bug Bounty Co-Pilot & 1-Click Vulnerability Finder
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-500 text-slate-950 font-black">NEW</span>
              </span>
              <p className="text-[10px] text-slate-400 mt-0.5">
                Launch automated multi-stage hunts, triage P1-P4 bounty payouts, and ask AI bug hunting questions.
              </p>
            </div>
          </div>
          <button className="px-3 py-1.5 rounded-lg bg-emerald-500 group-hover:bg-emerald-400 text-slate-950 font-black text-xs flex items-center gap-1 shadow-sm shrink-0 self-start sm:self-auto">
            <span>Launch Hunt</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Severity Breakdown Bar */}
      <div 
        onClick={() => onNavigate('findings')} 
        className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 cursor-pointer hover:border-slate-700 transition-all"
      >
        <div className="flex items-center justify-between text-xs mb-2">
          <span className="font-semibold text-slate-300">Vulnerability Distribution</span>
          <span className="text-[11px] text-slate-400 font-mono-code">{findings.length} findings recorded</span>
        </div>
        <div className="flex items-center gap-1.5 h-3 w-full bg-slate-950 rounded-full overflow-hidden p-0.5 border border-slate-800">
          {findings.length === 0 ? (
            <div className="w-full h-full bg-slate-800 rounded-full text-center text-[8px] text-slate-500 font-mono-code">No findings</div>
          ) : (
            <>
              {severityCounts.critical > 0 && (
                <div style={{ width: `${(severityCounts.critical / findings.length) * 100}%` }} className="h-full bg-rose-600 rounded-sm" title={`Critical: ${severityCounts.critical}`} />
              )}
              {severityCounts.high > 0 && (
                <div style={{ width: `${(severityCounts.high / findings.length) * 100}%` }} className="h-full bg-orange-500 rounded-sm" title={`High: ${severityCounts.high}`} />
              )}
              {severityCounts.medium > 0 && (
                <div style={{ width: `${(severityCounts.medium / findings.length) * 100}%` }} className="h-full bg-amber-400 rounded-sm" title={`Medium: ${severityCounts.medium}`} />
              )}
              {severityCounts.low > 0 && (
                <div style={{ width: `${(severityCounts.low / findings.length) * 100}%` }} className="h-full bg-blue-400 rounded-sm" title={`Low: ${severityCounts.low}`} />
              )}
              {severityCounts.info > 0 && (
                <div style={{ width: `${(severityCounts.info / findings.length) * 100}%` }} className="h-full bg-slate-400 rounded-sm" title={`Info: ${severityCounts.info}`} />
              )}
            </>
          )}
        </div>
        <div className="flex items-center justify-between text-[10px] font-mono-code mt-2 text-slate-400">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-600"></span> Crit: {severityCounts.critical}</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500"></span> High: {severityCounts.high}</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-400"></span> Med: {severityCounts.medium}</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-400"></span> Low: {severityCounts.low}</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-slate-400"></span> Info: {severityCounts.info}</span>
        </div>
      </div>

      {/* D3.js Visual Analytics Segmented Switcher */}
      <div className="space-y-3">
        <div className="flex rounded-xl bg-slate-900 p-1 border border-slate-800 text-xs font-mono-code">
          <button
            onClick={() => setActiveVisual('heatmap')}
            className={`flex-1 py-1.5 px-3 rounded-lg font-bold transition-all flex items-center justify-center gap-1.5 ${
              activeVisual === 'heatmap' ? 'bg-slate-800 text-rose-400 shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>Vulnerability Heatmap (D3)</span>
          </button>
          <button
            onClick={() => setActiveVisual('attack_surface')}
            className={`flex-1 py-1.5 px-3 rounded-lg font-bold transition-all flex items-center justify-center gap-1.5 ${
              activeVisual === 'attack_surface' ? 'bg-slate-800 text-cyan-400 shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Network className="w-3.5 h-3.5 text-cyan-400" />
            <span>Attack Surface & Exploit Chains (D3)</span>
          </button>
        </div>

        {activeVisual === 'heatmap' ? (
          <VulnerabilityHeatmap
            findings={findings}
            scopes={scopes}
            onSelectFindingFilter={(_category, _asset) => {
              onNavigate('findings');
            }}
          />
        ) : (
          <AttackSurfaceGraph
            assets={assets}
            findings={findings}
            scopes={scopes}
          />
        )}
      </div>

      {/* Active Jobs Section */}
      {activeScans.length > 0 && (
        <div className="p-3.5 rounded-xl bg-slate-900 border border-cyan-500/40">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5 font-mono-code">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              Active Scan Execution ({activeScans.length})
            </span>
          </div>
          <div className="space-y-2">
            {activeScans.map(scan => (
              <div key={scan.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono-code text-slate-200 font-medium truncate max-w-[200px]">
                    {scan.target}
                  </span>
                  <button
                    onClick={() => onCancelScan(scan.id)}
                    className="px-2 py-0.5 rounded bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800 text-[10px] font-mono-code"
                  >
                    Cancel
                  </button>
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <div className="flex-1 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div 
                      className="bg-cyan-400 h-full transition-all duration-300"
                      style={{ width: `${Math.max(scan.progress, 5)}%` }}
                    />
                  </div>
                  <span className="font-mono-code text-[10px] text-cyan-400">{scan.progress}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Fast Action Quick Launchers */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-white font-mono-code uppercase">Quick Security Actions</span>
          <span className="text-[10px] text-slate-500 font-mono-code">Deterministic modules</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <button
            onClick={() => onQuickScan(defaultTarget, 'exposure')}
            disabled={emergencyStop || activeScopes.length === 0}
            className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/60 text-left transition-all group disabled:opacity-50"
          >
            <div className="flex items-center justify-between text-emerald-400 mb-1">
              <span className="font-mono-code text-xs font-semibold flex items-center gap-1.5">
                <Play className="w-3.5 h-3.5 fill-current" /> Fast Exposure Audit
              </span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </div>
            <p className="text-[11px] text-slate-400">
              Scans target headers, cookies, and sensitive dotfile exposures.
            </p>
          </button>

          <button
            onClick={() => onQuickScan(defaultTarget, 'heuristics')}
            disabled={emergencyStop || activeScopes.length === 0}
            className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/60 text-left transition-all group disabled:opacity-50"
          >
            <div className="flex items-center justify-between text-cyan-400 mb-1">
              <span className="font-mono-code text-xs font-semibold flex items-center gap-1.5">
                <FlaskConical className="w-3.5 h-3.5" /> Canary & CORS Probe
              </span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </div>
            <p className="text-[11px] text-slate-400">
              Safe canary reflection tests and cross-origin origin trust validation.
            </p>
          </button>

          <button
            onClick={() => onNavigate('proxy')}
            className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-purple-500/60 text-left transition-all group"
          >
            <div className="flex items-center justify-between text-purple-400 mb-1">
              <span className="font-mono-code text-xs font-semibold flex items-center gap-1.5">
                <ArrowLeftRight className="w-3.5 h-3.5" /> Proxy Repeater
              </span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </div>
            <p className="text-[11px] text-slate-400">
              Intercept, modify, and replay HTTP requests with raw byte view.
            </p>
          </button>

          <button
            onClick={() => onNavigate('reports')}
            className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-blue-500/60 text-left transition-all group"
          >
            <div className="flex items-center justify-between text-blue-400 mb-1">
              <span className="font-mono-code text-xs font-semibold flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" /> Report Center
              </span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </div>
            <p className="text-[11px] text-slate-400">
              Generate HackerOne, Bugcrowd, ISO audit, and SARIF exports.
            </p>
          </button>
        </div>
      </div>
    </div>
  );
};

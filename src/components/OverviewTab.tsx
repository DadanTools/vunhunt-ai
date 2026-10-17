import React from 'react';
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
  ArrowLeftRight
} from 'lucide-react';
import { ScopeRule, ScanJob, Finding, ToolHealth } from '../types.ts';
import { TabId } from './BottomNav.tsx';

interface OverviewTabProps {
  scopes: ScopeRule[];
  scans: ScanJob[];
  findings: Finding[];
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
  tools,
  emergencyStop,
  onNavigate,
  onQuickScan,
  onCancelScan
}) => {
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
            <p className="font-bold font-mono-code text-white">EMERGENCY STOP IS ENGAGED</p>
            <p className="mt-0.5 text-rose-300">
              All active security scans have been cancelled and outgoing HTTP requests are locked. Use the button in the top navigation bar to disengage when safe.
            </p>
          </div>
        </div>
      ) : activeScopes.length === 0 ? (
        <div className="p-3.5 rounded-xl bg-amber-950/60 border border-amber-600/60 text-amber-200 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs flex-1">
            <p className="font-bold font-mono-code text-white">NO TARGETS IN AUTHORIZED SCOPE</p>
            <p className="mt-0.5 text-amber-300">
              Active testing is restricted until you configure an authorized domain or host in Scope Gate.
            </p>
            <button
              onClick={() => onNavigate('scope')}
              className="mt-2 inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 font-mono-code text-[11px] font-semibold"
            >
              Configure Scope Gate <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      ) : (
        <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/30 flex items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span className="font-mono-code text-emerald-300 font-semibold">Scope Gate Active</span>
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
          onClick={() => onNavigate('scanners')}
          className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Active Jobs</span>
            <Clock className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 font-mono-code text-2xl font-bold text-white">
            {activeScans.length}
          </div>
          <div className="mt-1 text-[10px] text-slate-400">Running / queued</div>
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
                <div className="mt-1 flex items-center justify-between text-[10px] text-slate-500 font-mono-code">
                  <span>Type: {scan.scan_type}</span>
                  <span>Status: {scan.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quick Launchpad Buttons */}
      <div className="space-y-2">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono-code">
          Quick Launchpad
        </h3>
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={() => onQuickScan(defaultTarget, 'exposure')}
            disabled={emergencyStop || activeScopes.length === 0}
            className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/50 hover:bg-slate-850 text-left transition-all disabled:opacity-50 disabled:pointer-events-none group"
          >
            <div className="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-2 group-hover:scale-105 transition-transform">
              <Play className="w-4 h-4 fill-emerald-400" />
            </div>
            <div className="text-xs font-semibold text-white">Fast Exposure Scan</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Headers, TLS, paths</div>
          </button>

          <button
            onClick={() => onNavigate('lab')}
            className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-850 text-left transition-all group"
          >
            <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-2 group-hover:scale-105 transition-transform">
              <FlaskConical className="w-4 h-4" />
            </div>
            <div className="text-xs font-semibold text-white">Local Test Lab</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Zero-risk test fixtures</div>
          </button>

          <button
            onClick={() => onNavigate('proxy')}
            className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-purple-500/50 hover:bg-slate-850 text-left transition-all group"
          >
            <div className="w-8 h-8 rounded-lg bg-purple-950/80 border border-purple-500/30 flex items-center justify-center text-purple-400 mb-2 group-hover:scale-105 transition-transform">
              <ArrowLeftRight className="w-4 h-4" />
            </div>
            <div className="text-xs font-semibold text-white">Proxy & Repeater</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Burp-style HTTP replay</div>
          </button>

          <button
            onClick={() => onNavigate('reports')}
            className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-amber-500/50 hover:bg-slate-850 text-left transition-all group"
          >
            <div className="w-8 h-8 rounded-lg bg-amber-950/80 border border-amber-500/30 flex items-center justify-center text-amber-400 mb-2 group-hover:scale-105 transition-transform">
              <FileText className="w-4 h-4" />
            </div>
            <div className="text-xs font-semibold text-white">Export Report</div>
            <div className="text-[10px] text-slate-400 mt-0.5">JSON & Markdown</div>
          </button>
        </div>
      </div>

      {/* Module Navigation Grid */}
      <div className="space-y-2 pt-2">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono-code">
          Security Modules
        </h3>
        <div className="space-y-1.5">
          {[
            { id: 'assets' as TabId, label: 'Asset Discovery & Subfinder', desc: 'Passive import, DNS resolve, HTTP probing', icon: Globe },
            { id: 'idor' as TabId, label: 'Auth & IDOR / BOLA Workbench', desc: 'Dual-tenant token comparison on object fixtures', icon: Layers },
            { id: 'templates' as TabId, label: 'Known CVE / Nuclei Engine', desc: 'Safe template runner with controlled rate limits', icon: Terminal },
            { id: 'tools' as TabId, label: 'Tool Health & Local Audit Trail', desc: 'Subfinder/Nuclei status & immutable audit log', icon: Clock }
          ].map(item => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className="w-full p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 hover:bg-slate-900 flex items-center justify-between text-left transition-all"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-7 h-7 rounded-lg bg-slate-800 flex items-center justify-center text-slate-300 shrink-0">
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-slate-200 truncate">{item.label}</div>
                    <div className="text-[10px] text-slate-400 truncate">{item.desc}</div>
                  </div>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-500 shrink-0" />
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};

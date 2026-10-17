import React, { useState } from 'react';
import { 
  Terminal, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Cpu, 
  ShieldCheck, 
  FileText,
  Search
} from 'lucide-react';
import { ToolHealth, AuditLog } from '../types.ts';

interface ToolsAuditTabProps {
  tools: Record<string, ToolHealth>;
  auditLogs: AuditLog[];
}

export const ToolsAuditTab: React.FC<ToolsAuditTabProps> = ({ tools, auditLogs }) => {
  const [activeSubTab, setActiveSubTab] = useState<'tools' | 'audit'>('tools');
  const [auditQuery, setAuditQuery] = useState('');

  const toolList = Object.values(tools || {});

  const filteredLogs = auditLogs.filter(l =>
    l.action.toLowerCase().includes(auditQuery.toLowerCase()) ||
    (l.target && l.target.toLowerCase().includes(auditQuery.toLowerCase())) ||
    l.details.toLowerCase().includes(auditQuery.toLowerCase())
  );

  return (
    <div className="space-y-4 pb-20">
      {/* Tab Switcher */}
      <div className="flex rounded-xl bg-slate-900 p-1 border border-slate-800 text-xs font-mono-code">
        <button
          onClick={() => setActiveSubTab('tools')}
          className={`flex-1 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'tools' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Tool Engine Health
        </button>
        <button
          onClick={() => setActiveSubTab('audit')}
          className={`flex-1 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'audit' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Audit Trail ({auditLogs.length})
        </button>
      </div>

      {/* Subtab 1: Tool Health Matrix */}
      {activeSubTab === 'tools' && (
        <div className="space-y-3">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
            <h3 className="text-xs font-bold text-white font-mono-code">Runtime & Binary Readiness</h3>
            <p className="text-[11px] text-slate-400">
              Live checks verifying which security CLI tools and runtimes are genuinely installed in PATH.
            </p>
          </div>

          <div className="space-y-2">
            {toolList.map(t => (
              <div key={t.name} className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
                      t.isAvailable ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-500'
                    }`}>
                      <Terminal className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white font-mono-code text-xs">{t.name}</span>
                        <span className="text-[10px] text-slate-500 font-mono-code">({t.binary})</span>
                      </div>
                      {t.version && (
                        <p className="text-[10px] text-emerald-400 font-mono-code mt-0.5 truncate max-w-[220px]">
                          {t.version}
                        </p>
                      )}
                    </div>
                  </div>

                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono-code font-bold shrink-0 ${
                    t.isAvailable ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {t.isAvailable ? 'ONLINE' : 'MISSING'}
                  </span>
                </div>

                <div className="p-2 rounded bg-slate-950 border border-slate-800/80 text-[10px] font-mono-code text-slate-400">
                  {t.notes}
                  {t.path && <div className="text-slate-500 mt-0.5 truncate">Binary: {t.path}</div>}
                </div>
              </div>
            ))}
          </div>

          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-[11px] text-slate-400 space-y-1 font-mono-code">
            <span className="text-slate-200 font-bold block">Android Termux Tooling Strategy:</span>
            <p className="leading-relaxed">
              VulnHunter AI operates fully with zero external tools. To optionally augment asset discovery and CVE scanning with Subfinder and Nuclei, install Go in Termux:
            </p>
            <code className="text-emerald-400 text-[10px] block mt-1">
              pkg install -y golang && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            </code>
          </div>
        </div>
      )}

      {/* Subtab 2: Audit Log */}
      {activeSubTab === 'audit' && (
        <div className="space-y-3">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={auditQuery}
              onChange={e => setAuditQuery(e.target.value)}
              placeholder="Search audit trail by action, target, actor..."
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white font-mono-code focus:outline-none focus:border-emerald-500"
            />
          </div>

          {filteredLogs.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400 font-mono-code">
              No audit records found.
            </div>
          ) : (
            <div className="space-y-1.5 font-mono-code text-[11px]">
              {filteredLogs.map(log => (
                <div key={log.id} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
                  <div className="flex items-center justify-between text-[10px] text-slate-400">
                    <span className="text-emerald-400 font-bold">{log.action}</span>
                    <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div className="mt-1 text-slate-200 text-xs">{log.details}</div>
                  <div className="mt-1 flex items-center gap-2 text-[10px] text-slate-500">
                    <span>Target: {log.target || 'None'}</span>
                    <span>•</span>
                    <span>Actor: {log.actor}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

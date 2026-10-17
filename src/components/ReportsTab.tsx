import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Copy, 
  Check, 
  ShieldCheck, 
  CheckCircle2, 
  ExternalLink,
  Code
} from 'lucide-react';
import { Finding, ScopeRule } from '../types.ts';

interface ReportsTabProps {
  findings: Finding[];
  scopes: ScopeRule[];
  onDownloadJson: () => void;
  onDownloadMarkdown: () => void;
}

export const ReportsTab: React.FC<ReportsTabProps> = ({
  findings,
  scopes,
  onDownloadJson,
  onDownloadMarkdown
}) => {
  const [copied, setCopied] = useState(false);

  const activeScopes = scopes.filter(s => s.is_active === 1);
  const severityCounts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };

  const statusCounts = {
    verified: findings.filter(f => f.verification_status === 'verified-in-authorized-lab').length,
    needsReview: findings.filter(f => f.verification_status === 'needs-review').length,
    candidate: findings.filter(f => f.verification_status === 'candidate').length,
    falsePositive: findings.filter(f => f.verification_status === 'false-positive').length,
  };

  return (
    <div className="space-y-4 pb-20">
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-amber-950 border border-amber-500/40 flex items-center justify-center text-amber-400">
            <FileText className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white font-mono-code">Report Generator & Exporter</h2>
            <p className="text-[11px] text-slate-400">Sanitized, structured vulnerability deliverables</p>
          </div>
        </div>
        <p className="text-[11px] text-slate-300 leading-relaxed">
          Export comprehensive assessment findings with redacted credentials, complete reproduction steps, impact breakdowns, and defensive remediation instructions.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <h3 className="text-xs font-bold text-slate-300 font-mono-code uppercase tracking-wider">
          Assessment Scope & Deliverable Posture
        </h3>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs font-mono-code">
          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 text-[10px] block">Active Targets</span>
            <span className="text-white font-bold text-base mt-1 block">{activeScopes.length}</span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 text-[10px] block">Total Findings</span>
            <span className="text-amber-400 font-bold text-base mt-1 block">{findings.length}</span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 text-[10px] block">Verified in Lab</span>
            <span className="text-emerald-400 font-bold text-base mt-1 block">{statusCounts.verified}</span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 text-[10px] block">High / Critical</span>
            <span className="text-rose-400 font-bold text-base mt-1 block">
              {severityCounts.critical + severityCounts.high}
            </span>
          </div>
        </div>
      </div>

      {/* Download Action Buttons */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <button
          onClick={onDownloadMarkdown}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/50 hover:bg-slate-850 text-left transition-all active:scale-95 group"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:scale-105 transition-transform">
              <Download className="w-4 h-4" />
            </div>
            <span className="text-[10px] font-mono-code px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
              .MD
            </span>
          </div>
          <div className="text-xs font-bold text-white font-mono-code">Download Markdown Report</div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            Formatted with executive tables, reproduction commands, and remediation guide.
          </div>
        </button>

        <button
          onClick={onDownloadJson}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-850 text-left transition-all active:scale-95 group"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
              <Code className="w-4 h-4" />
            </div>
            <span className="text-[10px] font-mono-code px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              .JSON
            </span>
          </div>
          <div className="text-xs font-bold text-white font-mono-code">Download Structured JSON</div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            Machine-readable deliverable with raw evidence and audit logs.
          </div>
        </button>
      </div>
    </div>
  );
};

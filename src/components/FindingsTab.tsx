import React, { useState } from 'react';
import { 
  Bug, 
  Search, 
  Filter, 
  CheckCircle2, 
  AlertCircle, 
  ShieldCheck, 
  Copy, 
  Check, 
  ChevronDown, 
  ChevronUp, 
  Terminal, 
  Sparkles,
  Info
} from 'lucide-react';
import { Finding } from '../types.ts';

interface FindingsTabProps {
  findings: Finding[];
  onUpdateStatus: (findingId: string, status: Finding['verification_status']) => Promise<any>;
  onAnalyzeWithAi: (finding: Finding, forceDeterministic?: boolean) => Promise<any>;
}

export const FindingsTab: React.FC<FindingsTabProps> = ({
  findings,
  onUpdateStatus,
  onAnalyzeWithAi
}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Remediation analysis state
  const [analysisText, setAnalysisText] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleAnalyze = async (finding: Finding, forceDeterministic = false) => {
    setIsAnalyzing(true);
    setAnalysisText(null);
    try {
      const res = await onAnalyzeWithAi(finding, forceDeterministic);
      setAnalysisText(res.analysis);
    } catch (err: any) {
      setAnalysisText(`Analysis error: ${err.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const filtered = findings.filter(f => {
    const matchesQuery = 
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.affected_asset.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.remediation.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || f.verification_status === statusFilter;

    return matchesQuery && matchesSeverity && matchesStatus;
  });

  return (
    <div className="space-y-4 pb-20">
      {/* Header & Filter Controls */}
      <div className="space-y-3">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search findings by title, asset, category..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white font-mono-code focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div className="flex gap-2 text-xs font-mono-code">
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="flex-1 py-1.5 px-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="flex-1 py-1.5 px-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="all">All Statuses</option>
            <option value="candidate">Candidate</option>
            <option value="needs-review">Needs Review</option>
            <option value="verified-in-authorized-lab">Verified in Lab</option>
            <option value="false-positive">False Positive</option>
          </select>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400">
          <Bug className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p>No findings match your criteria.</p>
          <p className="text-[11px] text-slate-500 mt-1">
            Execute a scan or use the Local Test Lab to generate assessment items.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(f => {
            const isExpanded = selectedFinding?.id === f.id;
            let parsedEvidence = {};
            try {
              parsedEvidence = JSON.parse(f.evidence_json);
            } catch (_e) {
              parsedEvidence = { raw: f.evidence_json };
            }

            return (
              <div 
                key={f.id} 
                className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs hover:border-slate-700 transition-all space-y-2"
              >
                <div 
                  className="flex items-start justify-between gap-2 cursor-pointer"
                  onClick={() => {
                    setSelectedFinding(isExpanded ? null : f);
                    setAnalysisText(null);
                  }}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono-code font-bold uppercase ${
                        f.severity === 'critical' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                        f.severity === 'high' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                        f.severity === 'medium' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                        f.severity === 'low' ? 'bg-blue-950 text-blue-400 border border-blue-800' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {f.severity}
                      </span>
                      <span className="font-mono-code font-bold text-white break-all text-xs">
                        {f.title}
                      </span>
                    </div>

                    <div className="mt-1 flex items-center gap-2 text-[10px] text-slate-400 font-mono-code flex-wrap">
                      <span className="truncate max-w-[200px] text-slate-300">{f.affected_asset}</span>
                      <span>•</span>
                      <span className="text-slate-400">{f.category}</span>
                      <span>•</span>
                      <span className={`px-1 rounded ${
                        f.verification_status === 'verified-in-authorized-lab' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold' :
                        f.verification_status === 'false-positive' ? 'bg-slate-800 text-slate-400 line-through' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {f.verification_status}
                      </span>
                    </div>
                  </div>

                  <div className="shrink-0 text-slate-400">
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </div>
                </div>

                {/* Expanded Details Accordion */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-slate-800 space-y-3 font-mono-code text-[11px]">
                    {/* Status Changer Buttons */}
                    <div>
                      <span className="text-slate-400 text-[10px] block mb-1">Set Verification Status:</span>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
                        {(['candidate', 'needs-review', 'verified-in-authorized-lab', 'false-positive'] as const).map(st => (
                          <button
                            key={st}
                            onClick={() => onUpdateStatus(f.id, st)}
                            className={`px-2 py-1 rounded text-[10px] font-bold border transition-all ${
                              f.verification_status === st
                                ? 'bg-emerald-600 text-slate-950 border-emerald-500'
                                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                            }`}
                          >
                            {st}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Impact & Remediation */}
                    <div>
                      <span className="text-slate-400 text-[10px] block">Impact:</span>
                      <p className="mt-0.5 text-slate-200 font-sans text-xs leading-relaxed">{f.impact}</p>
                    </div>

                    <div>
                      <span className="text-slate-400 text-[10px] block">Remediation:</span>
                      <p className="mt-0.5 text-emerald-300 font-sans text-xs leading-relaxed">{f.remediation}</p>
                    </div>

                    {/* Reproduction Steps */}
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400 text-[10px]">Reproduction Command:</span>
                        <button
                          onClick={() => handleCopy(f.reproduction_steps, `repro-${f.id}`)}
                          className="text-[10px] text-slate-400 hover:text-white flex items-center gap-1"
                        >
                          {copiedKey === `repro-${f.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedKey === `repro-${f.id}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre className="mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-slate-200 text-[10px] overflow-x-auto whitespace-pre-wrap">
                        {f.reproduction_steps}
                      </pre>
                    </div>

                    {/* Evidence with redacted secrets */}
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400 text-[10px]">Sanitized Evidence (Secrets Redacted):</span>
                        <button
                          onClick={() => handleCopy(JSON.stringify(parsedEvidence, null, 2), `evid-${f.id}`)}
                          className="text-[10px] text-slate-400 hover:text-white flex items-center gap-1"
                        >
                          {copiedKey === `evid-${f.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedKey === `evid-${f.id}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre className="mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-cyan-300 text-[10px] overflow-x-auto max-h-40">
                        {JSON.stringify(parsedEvidence, null, 2)}
                      </pre>
                    </div>

                    {/* Optional Remediation Breakdown Button */}
                    <div className="pt-2 border-t border-slate-850">
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleAnalyze(f, true)}
                          disabled={isAnalyzing}
                          className="flex-1 py-1.5 px-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-bold flex items-center justify-center gap-1.5 transition-all"
                        >
                          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Deterministic Rule Analysis</span>
                        </button>

                        <button
                          onClick={() => handleAnalyze(f, false)}
                          disabled={isAnalyzing}
                          className="flex-1 py-1.5 px-2 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-500/30 text-emerald-300 text-[10px] font-bold flex items-center justify-center gap-1.5 transition-all"
                        >
                          <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                          <span>AI Remediation Breakdown</span>
                        </button>
                      </div>

                      {isAnalyzing && (
                        <div className="mt-2 text-center text-[10px] text-slate-400 font-mono-code animate-pulse">
                          Generating defensive remediation analysis...
                        </div>
                      )}

                      {analysisText && (
                        <div className="mt-2 p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap font-sans">
                          {analysisText}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

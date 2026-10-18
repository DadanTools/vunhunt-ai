import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  Copy, 
  Check, 
  ShieldCheck, 
  Terminal, 
  Code, 
  ExternalLink,
  Sliders,
  CheckCircle2,
  ChevronRight,
  Eye,
  Layers,
  Sparkles
} from 'lucide-react';
import { Finding, ScopeRule } from '../types.ts';

interface ReportsTabProps {
  findings: Finding[];
  scopes: ScopeRule[];
  onDownloadJson: () => void;
  onDownloadMarkdown: () => void;
}

type ReportTemplate = 'hackerone' | 'bugcrowd' | 'enterprise' | 'sarif';

interface CvssState {
  av: 'N' | 'A' | 'L' | 'P';
  ac: 'L' | 'H';
  pr: 'N' | 'L' | 'H';
  ui: 'N' | 'R';
  s: 'U' | 'C';
  c: 'N' | 'L' | 'H';
  i: 'N' | 'L' | 'H';
  a: 'N' | 'L' | 'H';
}

export const ReportsTab: React.FC<ReportsTabProps> = ({
  findings,
  scopes,
  onDownloadJson,
  onDownloadMarkdown
}) => {
  const [activeTemplate, setActiveTemplate] = useState<ReportTemplate>('hackerone');
  const [selectedFindingId, setSelectedFindingId] = useState<string>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [previewContent, setPreviewContent] = useState<string>('');
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);
  const [reproTab, setReproTab] = useState<'curl' | 'raw' | 'python'>('curl');

  // Interactive CVSS Calculator State
  const [cvss, setCvss] = useState<CvssState>({
    av: 'N',
    ac: 'L',
    pr: 'N',
    ui: 'N',
    s: 'U',
    c: 'H',
    i: 'N',
    a: 'N'
  });
  const [cvssResult, setCvssResult] = useState<{ score: number; vector: string; severity: string }>({
    score: 7.5,
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    severity: 'High'
  });

  const activeScopes = scopes.filter(s => s.is_active === 1);

  // Fetch report preview from backend
  const fetchPreview = async () => {
    setIsLoadingPreview(true);
    try {
      const url = selectedFindingId !== 'all'
        ? `/api/reports/preview?format=${activeTemplate}&findingId=${selectedFindingId}`
        : `/api/reports/preview?format=${activeTemplate}`;
      const res = await fetch(url);
      const data = await res.json();
      setPreviewContent(data.content || '');
    } catch (_err) {
      setPreviewContent('Failed to load report preview.');
    } finally {
      setIsLoadingPreview(false);
    }
  };

  useEffect(() => {
    fetchPreview();
  }, [activeTemplate, selectedFindingId]);

  // Recalculate CVSS
  useEffect(() => {
    const calc = async () => {
      try {
        const res = await fetch('/api/cvss/calculate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(cvss)
        });
        const data = await res.json();
        setCvssResult(data);
      } catch (_e) {
        // Fallback
      }
    };
    calc();
  }, [cvss]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const selectedFinding = findings.find(f => f.id === selectedFindingId);

  // Build client-side reproduction variations for selected finding
  const getReproVariations = (f: Finding) => {
    const curl = f.reproduction_steps || `curl -s -I "${f.endpoint}"`;
    let parsed: URL;
    try {
      parsed = new URL(f.endpoint.startsWith('http') ? f.endpoint : `http://${f.endpoint}`);
    } catch {
      parsed = new URL('http://localhost:3000');
    }

    const rawHttp = [
      `GET ${parsed.pathname}${parsed.search} HTTP/1.1`,
      `Host: ${parsed.host}`,
      `User-Agent: VulnHunter-Security-Auditor/1.0 (+AuthorizedLab)`,
      `Accept: */*`,
      `Connection: close`,
      ``
    ].join('\r\n');

    const pythonScript = [
      `import urllib.request, ssl`,
      `ctx = ssl.create_default_context()`,
      `ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE`,
      `req = urllib.request.Request("${f.endpoint}", headers={"User-Agent": "VulnHunter-PoC/1.0"})`,
      `with urllib.request.urlopen(req, timeout=10, context=ctx) as res:`,
      `    print(f"Status: {res.status}")`,
      `    print("Headers:", dict(res.headers))`
    ].join('\n');

    return { curl, rawHttp, pythonScript };
  };

  return (
    <div className="space-y-4 pb-24">
      {/* Header Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-start justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white font-mono-code">Bug Bounty & Audit Report Suite</h2>
              <span className="text-[10px] px-1.5 py-0.2 rounded font-mono-code font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                PRO BUILDER
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Interactive report compiler for HackerOne, Bugcrowd VRT, and ISO/OWASP compliance
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => handleCopy(previewContent, 'full-report')}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono-code font-semibold flex items-center gap-1.5 transition-all"
            title="Copy compiled report to clipboard"
          >
            {copiedKey === 'full-report' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedKey === 'full-report' ? 'Copied!' : 'Copy Report'}</span>
          </button>
        </div>
      </div>

      {/* Template Selector Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono-code">
        {[
          { id: 'hackerone' as ReportTemplate, label: 'HackerOne', desc: 'Bug Bounty Standard' },
          { id: 'bugcrowd' as ReportTemplate, label: 'Bugcrowd', desc: 'VRT P1-P5 Taxonomy' },
          { id: 'enterprise' as ReportTemplate, label: 'Enterprise', desc: 'ISO 27001 / OWASP' },
          { id: 'sarif' as ReportTemplate, label: 'SARIF / JSON', desc: 'CI/CD & Machine Data' }
        ].map(tpl => (
          <button
            key={tpl.id}
            onClick={() => setActiveTemplate(tpl.id)}
            className={`p-2.5 rounded-xl border text-left transition-all ${
              activeTemplate === tpl.id
                ? 'bg-slate-850 border-emerald-500 shadow-sm'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            <div className={`font-bold ${activeTemplate === tpl.id ? 'text-emerald-400' : 'text-slate-200'}`}>
              {tpl.label}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">{tpl.desc}</div>
          </button>
        ))}
      </div>

      {/* Target Finding Selector (All vs Specific) */}
      <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between gap-2 text-xs font-mono-code">
        <span className="text-slate-400 text-[11px] shrink-0">Select Target Scope / Finding:</span>
        <select
          value={selectedFindingId}
          onChange={e => setSelectedFindingId(e.target.value)}
          className="flex-1 max-w-md px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-emerald-500 truncate"
        >
          <option value="all">Full Program Assessment ({findings.length} findings)</option>
          {findings.map(f => (
            <option key={f.id} value={f.id}>
              [{f.severity.toUpperCase()}] {f.title} ({f.affected_asset})
            </option>
          ))}
        </select>
      </div>

      {/* Interactive CVSS v3.1 Calculator Widget */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold text-white font-mono-code uppercase">Interactive CVSS v3.1 Calculator</span>
          </div>

          <div className="flex items-center gap-2">
            <span className={`px-2 py-0.5 rounded font-mono-code font-bold text-xs ${
              cvssResult.severity === 'Critical' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
              cvssResult.severity === 'High' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
              cvssResult.severity === 'Medium' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
              'bg-blue-950 text-blue-400 border border-blue-800'
            }`}>
              {cvssResult.score} {cvssResult.severity.toUpperCase()}
            </span>
            <button
              onClick={() => handleCopy(cvssResult.vector, 'cvss-vector')}
              className="text-[10px] text-slate-400 hover:text-white font-mono-code flex items-center gap-1"
            >
              {copiedKey === 'cvss-vector' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedKey === 'cvss-vector' ? 'Copied' : 'Copy Vector'}</span>
            </button>
          </div>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[10px] font-mono-code text-cyan-300 truncate">
          {cvssResult.vector}
        </div>

        {/* Metric Radio Matrix */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono-code">
          {/* AV */}
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-bold">Attack Vector (AV)</span>
            <div className="flex gap-1">
              {(['N', 'A', 'L', 'P'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setCvss({ ...cvss, av: v })}
                  className={`flex-1 py-1 rounded text-center font-bold ${cvss.av === v ? 'bg-cyan-600 text-slate-950' : 'bg-slate-900 text-slate-400'}`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* AC */}
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-bold">Complexity (AC)</span>
            <div className="flex gap-1">
              {(['L', 'H'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setCvss({ ...cvss, ac: v })}
                  className={`flex-1 py-1 rounded text-center font-bold ${cvss.ac === v ? 'bg-cyan-600 text-slate-950' : 'bg-slate-900 text-slate-400'}`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* PR */}
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-bold">Privileges (PR)</span>
            <div className="flex gap-1">
              {(['N', 'L', 'H'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setCvss({ ...cvss, pr: v })}
                  className={`flex-1 py-1 rounded text-center font-bold ${cvss.pr === v ? 'bg-cyan-600 text-slate-950' : 'bg-slate-900 text-slate-400'}`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* UI */}
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-bold">User Inter. (UI)</span>
            <div className="flex gap-1">
              {(['N', 'R'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setCvss({ ...cvss, ui: v })}
                  className={`flex-1 py-1 rounded text-center font-bold ${cvss.ui === v ? 'bg-cyan-600 text-slate-950' : 'bg-slate-900 text-slate-400'}`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* Scope */}
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-bold">Scope (S)</span>
            <div className="flex gap-1">
              {(['U', 'C'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setCvss({ ...cvss, s: v })}
                  className={`flex-1 py-1 rounded text-center font-bold ${cvss.s === v ? 'bg-purple-600 text-white' : 'bg-slate-900 text-slate-400'}`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* Conf */}
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-bold">Confidentiality (C)</span>
            <div className="flex gap-1">
              {(['N', 'L', 'H'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setCvss({ ...cvss, c: v })}
                  className={`flex-1 py-1 rounded text-center font-bold ${cvss.c === v ? 'bg-rose-600 text-white' : 'bg-slate-900 text-slate-400'}`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* Integ */}
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-bold">Integrity (I)</span>
            <div className="flex gap-1">
              {(['N', 'L', 'H'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setCvss({ ...cvss, i: v })}
                  className={`flex-1 py-1 rounded text-center font-bold ${cvss.i === v ? 'bg-rose-600 text-white' : 'bg-slate-900 text-slate-400'}`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* Avail */}
          <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-bold">Availability (A)</span>
            <div className="flex gap-1">
              {(['N', 'L', 'H'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setCvss({ ...cvss, a: v })}
                  className={`flex-1 py-1 rounded text-center font-bold ${cvss.a === v ? 'bg-rose-600 text-white' : 'bg-slate-900 text-slate-400'}`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* One-Click HackerOne Submission Field Copy Shortcuts */}
      {selectedFinding && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white font-mono-code uppercase flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              HackerOne / Bugcrowd Field Copy Shortcuts
            </span>
            <span className="text-[10px] text-slate-500 font-mono-code">{selectedFinding.title}</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono-code">
            <button
              onClick={() => handleCopy(selectedFinding.title, 'field-title')}
              className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center justify-between transition-all"
            >
              <span>Title</span>
              {copiedKey === 'field-title' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            </button>

            <button
              onClick={() => handleCopy(selectedFinding.reproduction_steps, 'field-repro')}
              className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center justify-between transition-all"
            >
              <span>Repro Steps</span>
              {copiedKey === 'field-repro' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            </button>

            <button
              onClick={() => handleCopy(selectedFinding.impact, 'field-impact')}
              className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center justify-between transition-all"
            >
              <span>Impact</span>
              {copiedKey === 'field-impact' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            </button>

            <button
              onClick={() => handleCopy(selectedFinding.remediation, 'field-fix')}
              className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center justify-between transition-all"
            >
              <span>Remediation</span>
              {copiedKey === 'field-fix' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            </button>
          </div>

          {/* Multi-Method Reproduction Viewer */}
          <div className="pt-2 border-t border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono-code">
              <span className="text-slate-400 text-[11px]">Multi-Method PoC Verification:</span>
              <div className="flex gap-1">
                {(['curl', 'raw', 'python'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setReproTab(tab)}
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase transition-all ${
                      reproTab === tab ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'text-slate-500 hover:text-white'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>
            </div>

            <div className="relative">
              <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-cyan-300 font-mono-code text-[10px] overflow-x-auto max-h-40">
                {reproTab === 'curl' && getReproVariations(selectedFinding).curl}
                {reproTab === 'raw' && getReproVariations(selectedFinding).rawHttp}
                {reproTab === 'python' && getReproVariations(selectedFinding).pythonScript}
              </pre>
              <button
                onClick={() => {
                  const content = reproTab === 'curl' 
                    ? getReproVariations(selectedFinding).curl
                    : reproTab === 'raw' 
                    ? getReproVariations(selectedFinding).rawHttp
                    : getReproVariations(selectedFinding).pythonScript;
                  handleCopy(content, `poc-${reproTab}`);
                }}
                className="absolute top-2 right-2 p-1 rounded bg-slate-900 border border-slate-700 text-slate-400 hover:text-white"
                title="Copy reproduction code"
              >
                {copiedKey === `poc-${reproTab}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Live Preview Container */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Eye className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-bold text-white font-mono-code uppercase">
              Live Deliverable Preview ({activeTemplate.toUpperCase()})
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchPreview}
              className="text-[11px] text-slate-400 hover:text-white font-mono-code"
            >
              Refresh
            </button>
          </div>
        </div>

        {isLoadingPreview ? (
          <div className="py-12 text-center text-slate-500 font-mono-code text-xs">
            Compiling deliverable preview...
          </div>
        ) : (
          <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 font-mono-code text-[11px] overflow-x-auto max-h-96 whitespace-pre-wrap leading-relaxed">
            {previewContent}
          </pre>
        )}
      </div>

      {/* Instant Download Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono-code text-xs">
        <button
          onClick={() => window.location.href = '/api/reports/hackerone'}
          className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/50 hover:bg-slate-850 text-left transition-all active:scale-95 group"
        >
          <div className="w-7 h-7 rounded-lg bg-emerald-950 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-1.5 group-hover:scale-105 transition-transform">
            <Download className="w-3.5 h-3.5" />
          </div>
          <div className="font-bold text-white text-[11px]">HackerOne Report</div>
          <div className="text-[9px] text-slate-400 mt-0.5">.md markdown</div>
        </button>

        <button
          onClick={() => window.location.href = '/api/reports/bugcrowd'}
          className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-orange-500/50 hover:bg-slate-850 text-left transition-all active:scale-95 group"
        >
          <div className="w-7 h-7 rounded-lg bg-orange-950 border border-orange-500/30 flex items-center justify-center text-orange-400 mb-1.5 group-hover:scale-105 transition-transform">
            <Download className="w-3.5 h-3.5" />
          </div>
          <div className="font-bold text-white text-[11px]">Bugcrowd VRT</div>
          <div className="text-[9px] text-slate-400 mt-0.5">.md markdown</div>
        </button>

        <button
          onClick={() => window.location.href = '/api/reports/enterprise'}
          className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-purple-500/50 hover:bg-slate-850 text-left transition-all active:scale-95 group"
        >
          <div className="w-7 h-7 rounded-lg bg-purple-950 border border-purple-500/30 flex items-center justify-center text-purple-400 mb-1.5 group-hover:scale-105 transition-transform">
            <Download className="w-3.5 h-3.5" />
          </div>
          <div className="font-bold text-white text-[11px]">Enterprise Audit</div>
          <div className="text-[9px] text-slate-400 mt-0.5">ISO/OWASP .md</div>
        </button>

        <button
          onClick={() => window.location.href = '/api/reports/sarif'}
          className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-850 text-left transition-all active:scale-95 group"
        >
          <div className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-1.5 group-hover:scale-105 transition-transform">
            <Download className="w-3.5 h-3.5" />
          </div>
          <div className="font-bold text-white text-[11px]">SARIF / JSON</div>
          <div className="text-[9px] text-slate-400 mt-0.5">Machine format</div>
        </button>
      </div>
    </div>
  );
};

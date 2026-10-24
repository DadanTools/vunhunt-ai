import React, { useState, useEffect } from 'react';
import { 
  Sparkles, 
  Target, 
  ShieldCheck, 
  Bug, 
  Zap, 
  ArrowRight, 
  CheckCircle2, 
  AlertTriangle, 
  ExternalLink, 
  Copy, 
  Check, 
  RefreshCw, 
  Send, 
  Award, 
  DollarSign, 
  FileText, 
  HelpCircle,
  MessageSquare,
  Globe,
  ChevronDown,
  ChevronUp,
  Layers,
  Terminal,
  Activity,
  Code2,
  Lock,
  Search,
  Filter,
  FileCode,
  Key,
  Flame,
  Radio,
  FileSearch
} from 'lucide-react';
import { ScopeRule } from '../types.ts';
import { TabId } from './BottomNav.tsx';

interface AiCopilotTabProps {
  scopes: ScopeRule[];
  onNavigateToTab: (tab: TabId) => void;
  onRefreshFindings: () => void;
}

export const AiCopilotTab: React.FC<AiCopilotTabProps> = ({ 
  scopes, 
  onNavigateToTab,
  onRefreshFindings 
}) => {
  // Navigation & View Mode
  const [huntMode, setHuntMode] = useState<'single' | 'batch'>('single');
  const [auditDepth, setAuditDepth] = useState<'deep' | 'quick'>('deep');

  // Single Target Input
  const [targetInput, setTargetInput] = useState('http://localhost:3000');
  const [customHeaderKey, setCustomHeaderKey] = useState('X-Bug-Bounty');
  const [customHeaderVal, setCustomHeaderVal] = useState('vulnhunter-researcher');
  const [useCustomHeader, setUseCustomHeader] = useState(false);

  // Batch Targets Input
  const [batchTargetsText, setBatchTargetsText] = useState('http://localhost:3000\nhttp://127.0.0.1:3000');
  const [batchResults, setBatchResults] = useState<any[] | null>(null);
  const [isBatchRunning, setIsBatchRunning] = useState(false);

  // Single Hunt Execution State
  const [isHunting, setIsHunting] = useState(false);
  const [huntResult, setHuntResult] = useState<any | null>(null);
  const [huntError, setHuntError] = useState<string | null>(null);

  // Standalone JavaScript Extraction State
  const [isJsExtracting, setIsJsExtracting] = useState(false);
  const [standaloneJsResult, setStandaloneJsResult] = useState<any | null>(null);
  const [jsActiveTab, setJsActiveTab] = useState<'endpoints' | 'secrets' | 'sinks' | 'sourcemaps' | 'scripts'>('endpoints');
  const [jsSearchFilter, setJsSearchFilter] = useState('');

  // Termux Supercharge Toolbox
  const [showTermuxToolbox, setShowTermuxToolbox] = useState(false);
  const [termuxData, setTermuxData] = useState<any | null>(null);

  // Finding Deep Explainer State
  const [explainingFinding, setExplainingFinding] = useState<any | null>(null);
  const [isExplaining, setIsExplaining] = useState(false);
  const [explanationText, setExplanationText] = useState<string | null>(null);

  // HackerOne Report Modal State
  const [selectedFindingForReport, setSelectedFindingForReport] = useState<any | null>(null);

  // Copy Feedback
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Chat / Ask AI State
  const [question, setQuestion] = useState('');
  const [isAsking, setIsAsking] = useState(false);
  const [chatMessages, setChatMessages] = useState<Array<{ sender: 'user' | 'ai'; text: string; time: string }>>([
    {
      sender: 'ai',
      text: 'Salam & Welcome to VulnHunter AI! I am your #1 Bug Bounty Hunting Co-Pilot. I make finding all vulnerability types, scraping JavaScript files for hidden API links, and hunting public/critical secrets effortless. Launch a 1-click hunt or extract JS links below!',
      time: new Date().toLocaleTimeString()
    }
  ]);

  // Load Termux Toolbox data
  useEffect(() => {
    fetch('/api/termux/toolbox')
      .then(r => r.json())
      .then(d => { if (d.success) setTermuxData(d); })
      .catch(() => {});
  }, []);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Launch Single Target Hunt
  const handleRunHunt = async () => {
    if (!targetInput.trim()) return;
    setIsHunting(true);
    setHuntError(null);
    setHuntResult(null);

    try {
      const payload: any = { 
        target: targetInput.trim(),
        mode: auditDepth
      };

      if (useCustomHeader && customHeaderKey.trim() && customHeaderVal.trim()) {
        payload.customHeader = { key: customHeaderKey.trim(), value: customHeaderVal.trim() };
      }

      const res = await fetch('/api/ai/hunter-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'AI Hunt execution failed.');
      }

      setHuntResult(data);
      if (data.jsRecon) {
        setStandaloneJsResult(data.jsRecon);
      }
      onRefreshFindings();
    } catch (err: any) {
      setHuntError(err.message || 'Failed to complete AI hunt.');
    } finally {
      setIsHunting(false);
    }
  };

  // Standalone JavaScript & Hidden Link Scraping
  const handleRunJsExtraction = async () => {
    if (!targetInput.trim()) return;
    setIsJsExtracting(true);
    setHuntError(null);

    try {
      const res = await fetch('/api/recon/js-extract', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          targetUrl: targetInput.trim(),
          customHeaders: useCustomHeader ? { [customHeaderKey]: customHeaderVal } : undefined
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'JavaScript extraction failed.');
      setStandaloneJsResult(data.result);
      onRefreshFindings();
    } catch (err: any) {
      setHuntError(err.message || 'Failed to extract JavaScript endpoints.');
    } finally {
      setIsJsExtracting(false);
    }
  };

  // Launch Multi-Target Batch Hunt
  const handleRunBatchHunt = async () => {
    const list = batchTargetsText
      .split('\n')
      .map(t => t.trim())
      .filter(Boolean);

    if (list.length === 0) return;

    setIsBatchRunning(true);
    setHuntError(null);
    setBatchResults(null);

    try {
      const res = await fetch('/api/ai/batch-hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          targets: list,
          mode: auditDepth,
          customHeader: useCustomHeader ? { key: customHeaderKey, value: customHeaderVal } : undefined
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Batch hunt failed.');
      setBatchResults(data.results);
      onRefreshFindings();
    } catch (err: any) {
      setHuntError(err.message || 'Batch hunt encountered an error.');
    } finally {
      setIsBatchRunning(false);
    }
  };

  // Explain Finding with Gemini 3.8 Flash
  const handleExplainFinding = async (finding: any) => {
    setExplainingFinding(finding);
    setIsExplaining(true);
    setExplanationText(null);

    try {
      const res = await fetch('/api/ai/explain-finding', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findingId: finding.id })
      });
      const data = await res.json();
      setExplanationText(data.explanation || 'No detailed explanation generated.');
    } catch (err: any) {
      setExplanationText(`Error retrieving explanation: ${err.message}`);
    } finally {
      setIsExplaining(false);
    }
  };

  // Interactive Mentor Chat
  const handleAskAi = async (customPrompt?: string) => {
    const q = (customPrompt || question).trim();
    if (!q) return;

    const userMsg = { sender: 'user' as const, text: q, time: new Date().toLocaleTimeString() };
    setChatMessages(prev => [...prev, userMsg]);
    setQuestion('');
    setIsAsking(true);

    try {
      const res = await fetch('/api/ai/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          question: q,
          context: huntResult ? {
            target: huntResult.target,
            findingsCount: huntResult.totalFindings,
            technologies: huntResult.recon?.technologies,
            jsScriptsCount: standaloneJsResult?.totalScriptsAnalyzed,
            secretsCount: standaloneJsResult?.discoveredSecrets?.length
          } : undefined
        })
      });

      const data = await res.json();
      const aiMsg = {
        sender: 'ai' as const,
        text: data.answer || 'No response returned from AI.',
        time: new Date().toLocaleTimeString()
      };
      setChatMessages(prev => [...prev, aiMsg]);
    } catch (err: any) {
      setChatMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: `AI Assistant Error: ${err.message}`,
          time: new Date().toLocaleTimeString()
        }
      ]);
    } finally {
      setIsAsking(false);
    }
  };

  // Formats professional HackerOne markdown report
  const generateH1ReportText = (finding: any, target: string) => {
    return `# Bug Bounty Vulnerability Report: ${finding.title}

## Summary
A security vulnerability classified under **${finding.vrtCategory || 'VRT'}** was identified on **${target}**.
- **Severity**: ${finding.severity.toUpperCase()} (${finding.priority})
- **Estimated Bounty Potential**: ${finding.estimatedBounty || '$500 - $2,500'}
- **Vulnerable Asset**: \`${finding.affected_asset}\`
- **Verification Status**: Validated in Authorized Lab Environment

## Description & Technical Mechanism
${finding.impact || 'During authorized security assessment, anomalous response behaviors were confirmed indicating an insecure configuration or input reflection.'}

## Step-by-Step Reproduction
1. Navigate to target endpoint: \`${finding.affected_asset}\`
2. Send the non-destructive verification request:
\`\`\`bash
${finding.reproduction_steps || `curl -s "${target}"`}
\`\`\`
3. Observe that the response confirms the vulnerability:
\`\`\`json
${finding.evidence_json || '{}'}
\`\`\`

## Business & Security Impact
An external untrusted researcher or attacker can leverage this weakness to compromise data integrity, bypass authorization boundaries, or leak internal configuration.

## Remediation Guidance
${finding.remediation || 'Enforce strict input validation, proper context-aware encoding, and adhere to the principle of least privilege.'}

---
*Report auto-generated by VulnHunter AI — World-Class Bug Bounty Co-Pilot.*`;
  };

  // Cumulative bounty pool calculation
  const cumulativeBountyEstimate = huntResult ? (() => {
    const min = (huntResult.p1Count * 3000) + (huntResult.p2Count * 1200) + (huntResult.p3Count * 400) + (huntResult.p4Count * 100);
    const max = (huntResult.p1Count * 10000) + (huntResult.p2Count * 3000) + (huntResult.p3Count * 1200) + (huntResult.p4Count * 300);
    return min > 0 ? `$${min.toLocaleString()} – $${max.toLocaleString()}+` : '$0';
  })() : null;

  // Filtered Endpoints
  const filteredEndpoints = (standaloneJsResult?.hiddenEndpoints || []).filter((ep: any) => {
    if (!jsSearchFilter) return true;
    return ep.endpoint.toLowerCase().includes(jsSearchFilter.toLowerCase()) ||
           ep.category.toLowerCase().includes(jsSearchFilter.toLowerCase());
  });

  return (
    <div className="space-y-4 animate-in fade-in duration-200">
      {/* Top Banner: #1 Bug Bounty AI Co-Pilot */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-emerald-950/80 via-slate-900 to-cyan-950/80 border border-emerald-500/40 shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/20 border border-emerald-400/40 flex items-center justify-center text-emerald-400 shrink-0">
              <Sparkles className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-black text-white uppercase tracking-wider">
                  #1 AI Bug Bounty Vulnerability Hunter & JS Spy
                </h2>
                <span className="text-[10px] bg-emerald-500 text-slate-950 font-black px-1.5 py-0.5 rounded shadow">
                  ULTIMATE
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Discover all vulnerability classes, parse JavaScript bundles for hidden API endpoints, and triage public/critical severity leaks.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setShowTermuxToolbox(!showTermuxToolbox)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-cyan-500/40 text-cyan-300 text-xs font-bold flex items-center gap-1.5 transition-all"
            >
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>Termux Toolbox</span>
              {showTermuxToolbox ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          </div>
        </div>

        {/* Termux Supercharge Quick-Script Drawer */}
        {showTermuxToolbox && termuxData && (
          <div className="p-3.5 rounded-lg bg-slate-950 border border-cyan-500/30 space-y-3 animate-in fade-in">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-cyan-400 flex items-center gap-1.5">
                <Terminal className="w-4 h-4" />
                Termux Supercharge Mobile Automation
              </span>
              <button
                onClick={() => handleCopy(termuxData.termuxSetupScript, 'termux_script')}
                className="px-2 py-0.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-black text-[10px] flex items-center gap-1"
              >
                {copiedKey === 'termux_script' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'termux_script' ? 'Copied Script!' : 'Copy Termux Setup Script'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10px] font-mono-code">
              {termuxData.cliShortcuts?.map((item: any, idx: number) => (
                <div key={idx} className="p-2 rounded bg-slate-900 border border-slate-800 space-y-1">
                  <div className="text-slate-300 font-bold flex items-center justify-between">
                    <span>{item.name}</span>
                    <button
                      onClick={() => handleCopy(item.cmd, `shortcut_${idx}`)}
                      className="text-cyan-400 hover:text-cyan-300 text-[9px]"
                    >
                      {copiedKey === `shortcut_${idx}` ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="text-slate-400 truncate text-[9px] bg-slate-950 p-1 rounded">
                    {item.cmd}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* View Mode Switcher: Single Target vs Multi-Target Batch */}
        <div className="flex items-center gap-2 pt-1 border-t border-slate-800 text-xs flex-wrap">
          <button
            onClick={() => setHuntMode('single')}
            className={`px-3 py-1.5 rounded-lg font-bold flex items-center gap-1.5 transition-all ${
              huntMode === 'single'
                ? 'bg-emerald-500 text-slate-950 shadow-md'
                : 'bg-slate-900 text-slate-400 hover:text-white'
            }`}
          >
            <Target className="w-3.5 h-3.5" />
            <span>Single Target Hunt</span>
          </button>

          <button
            onClick={() => setHuntMode('batch')}
            className={`px-3 py-1.5 rounded-lg font-bold flex items-center gap-1.5 transition-all ${
              huntMode === 'batch'
                ? 'bg-emerald-500 text-slate-950 shadow-md'
                : 'bg-slate-900 text-slate-400 hover:text-white'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Multi-Target Scope Sweep (Batch)</span>
          </button>

          {/* Audit Depth Toggle */}
          <div className="ml-auto flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-[10px]">
            <span className="text-slate-500 px-1 font-bold">DEPTH:</span>
            <button
              onClick={() => setAuditDepth('deep')}
              className={`px-2 py-0.5 rounded font-black transition-all ${
                auditDepth === 'deep' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'
              }`}
            >
              Deep Multi-Vector
            </button>
            <button
              onClick={() => setAuditDepth('quick')}
              className={`px-2 py-0.5 rounded font-black transition-all ${
                auditDepth === 'quick' ? 'bg-amber-500 text-slate-950' : 'text-slate-400 hover:text-white'
              }`}
            >
              Fast Triage (30s)
            </button>
          </div>
        </div>
      </div>

      {/* Mode A: Single Target Hunter Control Card */}
      {huntMode === 'single' && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <label className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
              <Target className="w-4 h-4 text-emerald-400" />
              <span>Target Asset URL or Host</span>
            </label>
            <button
              onClick={() => setTargetInput('http://localhost:3000')}
              className="text-cyan-400 hover:text-cyan-300 text-[10px] underline"
            >
              Use Local Test Lab (Safe Baseline)
            </button>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-2">
            <input
              type="text"
              value={targetInput}
              onChange={e => setTargetInput(e.target.value)}
              placeholder="e.g. http://localhost:3000 or https://authorized-domain.com"
              className="w-full px-3 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-white text-xs focus:outline-none focus:border-emerald-500 font-mono-code"
            />

            <div className="flex items-center gap-2 w-full sm:w-auto shrink-0">
              <button
                onClick={handleRunHunt}
                disabled={isHunting || !targetInput.trim()}
                className="flex-1 sm:flex-initial px-5 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-black text-xs flex items-center justify-center gap-2 transition-all shadow-lg active:scale-95 disabled:opacity-50"
              >
                {isHunting ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Zap className="w-4 h-4 fill-slate-950" />
                )}
                <span>{isHunting ? 'AI Hunting...' : 'Launch AI Bug Hunt'}</span>
              </button>

              <button
                onClick={handleRunJsExtraction}
                disabled={isJsExtracting || !targetInput.trim()}
                className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-black text-xs flex items-center justify-center gap-1.5 transition-all shadow-lg active:scale-95 disabled:opacity-50"
                title="Extract JavaScript files, hidden API links, and hardcoded secrets"
              >
                {isJsExtracting ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <FileCode className="w-3.5 h-3.5" />
                )}
                <span>{isJsExtracting ? 'Parsing JS...' : 'JS Spy'}</span>
              </button>
            </div>
          </div>

          {/* Optional Custom Bug Bounty Program Header */}
          <div className="pt-2 border-t border-slate-800/80">
            <button
              onClick={() => setUseCustomHeader(!useCustomHeader)}
              className="text-[10px] text-slate-400 hover:text-emerald-400 flex items-center gap-1 font-bold"
            >
              <span>{useCustomHeader ? '[-]' : '[+]'}</span>
              <span>Program Rules of Engagement Custom Header (e.g. X-Bug-Bounty)</span>
            </button>

            {useCustomHeader && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2 p-2.5 rounded bg-slate-950 border border-slate-800 text-xs">
                <div>
                  <label className="text-[10px] text-slate-400 block mb-1">Header Name</label>
                  <input
                    type="text"
                    value={customHeaderKey}
                    onChange={e => setCustomHeaderKey(e.target.value)}
                    className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 text-white text-xs"
                    placeholder="X-Bug-Bounty"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-slate-400 block mb-1">Header Value / Researcher Handle</label>
                  <input
                    type="text"
                    value={customHeaderVal}
                    onChange={e => setCustomHeaderVal(e.target.value)}
                    className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 text-white text-xs"
                    placeholder="hacker1-handle"
                  />
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Mode B: Multi-Target Batch Scope Sweep */}
      {huntMode === 'batch' && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Multi-Target Subdomain List (One URL or host per line, max 10)</span>
            </label>
            <span className="text-[10px] text-slate-500">Auto-verifies Scope Gate</span>
          </div>

          <textarea
            value={batchTargetsText}
            onChange={e => setBatchTargetsText(e.target.value)}
            rows={4}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-white text-xs font-mono-code focus:outline-none focus:border-cyan-500"
            placeholder="http://localhost:3000&#10;http://127.0.0.1:3000"
          />

          <div className="flex items-center justify-between">
            <span className="text-[10px] text-slate-400">
              Targets queued: {batchTargetsText.split('\n').filter(t => t.trim()).length}
            </span>
            <button
              onClick={handleRunBatchHunt}
              disabled={isBatchRunning}
              className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black text-xs flex items-center gap-2 transition-all shadow active:scale-95 disabled:opacity-50"
            >
              {isBatchRunning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5 fill-slate-950" />}
              <span>{isBatchRunning ? 'Scanning Queue...' : 'Execute Scope Sweep'}</span>
            </button>
          </div>

          {/* Batch Results Table */}
          {batchResults && (
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2 mt-3">
              <h4 className="text-xs font-bold text-white uppercase">Scope Sweep Results</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[11px]">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-800">
                      <th className="pb-1">Target</th>
                      <th className="pb-1">Status</th>
                      <th className="pb-1">Bugs Found</th>
                      <th className="pb-1">P1 Critical</th>
                      <th className="pb-1">P2 High</th>
                      <th className="pb-1">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-850">
                    {batchResults.map((r, i) => (
                      <tr key={i} className="hover:bg-slate-900/50">
                        <td className="py-2 font-mono-code text-white">{r.target}</td>
                        <td className="py-2">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            r.status === 'completed' ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'
                          }`}>
                            {r.status}
                          </span>
                        </td>
                        <td className="py-2 font-bold text-amber-400">{r.findingsCount || 0}</td>
                        <td className="py-2 text-rose-400 font-bold">{r.criticalCount || 0}</td>
                        <td className="py-2 text-orange-400 font-bold">{r.highCount || 0}</td>
                        <td className="py-2">
                          <button
                            onClick={() => {
                              setTargetInput(r.target);
                              setHuntMode('single');
                              handleRunHunt();
                            }}
                            className="text-cyan-400 hover:text-cyan-300 text-[10px] font-bold"
                          >
                            Deep Triage &rarr;
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Hunt Error Banner */}
      {huntError && (
        <div className="p-3 rounded-xl bg-rose-950/80 border border-rose-700 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{huntError}</span>
        </div>
      )}

      {/* Active Hunt Running Animation State */}
      {isHunting && (
        <div className="p-6 rounded-xl bg-slate-900 border border-emerald-500/40 text-center space-y-3 animate-pulse">
          <RefreshCw className="w-6 h-6 text-emerald-400 animate-spin mx-auto" />
          <h3 className="text-sm font-bold text-white">Autonomous AI Bug Hunt in Progress ({auditDepth.toUpperCase()} MODE)...</h3>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-[10px] text-slate-400 max-w-2xl mx-auto pt-2">
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              1. Scope Gate
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              2. Fast Exposure
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              3. Deep Multi-Vector
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              4. JS Link & Secret Spy
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              5. Gemini 3.8 Triage
            </div>
          </div>
        </div>
      )}

      {/* Single Hunt Results Dashboard */}
      {huntResult && (
        <div className="space-y-4">
          {/* Top Triage Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300">
              <span className="text-[10px] uppercase font-bold block">P1 Critical</span>
              <span className="text-2xl font-black text-rose-400">{huntResult.p1Count}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">$3k – $10k+</span>
            </div>

            <div className="p-3 rounded-xl bg-orange-950/40 border border-orange-800/80 text-orange-300">
              <span className="text-[10px] uppercase font-bold block">P2 High</span>
              <span className="text-2xl font-black text-orange-400">{huntResult.p2Count}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">$1.2k – $3k</span>
            </div>

            <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-800/80 text-amber-300">
              <span className="text-[10px] uppercase font-bold block">P3 Medium</span>
              <span className="text-2xl font-black text-amber-400">{huntResult.p3Count}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">$400 – $1.2k</span>
            </div>

            <div className="p-3 rounded-xl bg-blue-950/40 border border-blue-800/80 text-blue-300">
              <span className="text-[10px] uppercase font-bold block">P4 Low / Info</span>
              <span className="text-2xl font-black text-blue-400">{huntResult.p4Count}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">$100 – $300</span>
            </div>

            <div className="col-span-2 sm:col-span-1 p-3 rounded-xl bg-emerald-950/40 border border-emerald-800/80 text-emerald-300">
              <span className="text-[10px] uppercase font-bold block">Est. Bounty Pool</span>
              <span className="text-base font-black text-emerald-400 truncate block mt-1">
                {cumulativeBountyEstimate || '$0'}
              </span>
              <span className="text-[10px] text-slate-400 block mt-0.5">Aggregated Value</span>
            </div>
          </div>

          {/* AI Executive Assessment Narrative Card */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5 uppercase">
                <Sparkles className="w-3.5 h-3.5" />
                AI Triager Intelligence Analysis for {huntResult.target}
              </span>
              <span className="text-[10px] text-slate-500 font-mono-code">Model: Gemini 3.8 Flash</span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800/90 text-slate-300 text-[11px] leading-relaxed whitespace-pre-line font-mono-code">
              {huntResult.aiExecutiveSummary}
            </div>
          </div>

          {/* Discovered Bug Bounty Findings List */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                <Bug className="w-3.5 h-3.5 text-amber-400" />
                Discovered Bounty Findings ({huntResult.findings?.length || 0})
              </h3>
              <span className="text-[10px] text-slate-400">1-Click HackerOne Report & Exploitability Analysis</span>
            </div>

            {huntResult.findings?.length === 0 ? (
              <div className="py-8 text-center text-slate-500 text-xs">
                Target is hardened! No obvious exposure vectors detected.
              </div>
            ) : (
              <div className="space-y-2">
                {huntResult.findings.map((f: any) => (
                  <div
                    key={f.id}
                    className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 transition-all space-y-2"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
                            f.priority === 'P1' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                            f.priority === 'P2' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                            f.priority === 'P3' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                            'bg-blue-950 text-blue-300 border border-blue-800'
                          }`}>
                            {f.priority} &bull; {f.severity.toUpperCase()}
                          </span>
                          <span className="font-bold text-white text-xs">{f.title}</span>
                          <span className="text-[10px] text-emerald-400 font-bold bg-emerald-950/60 px-1 rounded">
                            {f.estimatedBounty}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">{f.impact || f.remediation}</p>
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          onClick={() => handleExplainFinding(f)}
                          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-emerald-400 border border-emerald-500/40 text-[10px] font-bold flex items-center gap-1 transition-all"
                        >
                          <Code2 className="w-3 h-3" />
                          <span>AI PoC</span>
                        </button>

                        <button
                          onClick={() => setSelectedFindingForReport(f)}
                          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-cyan-500/40 text-[10px] font-bold flex items-center gap-1 transition-all"
                        >
                          <FileText className="w-3 h-3" />
                          <span>H1 Report</span>
                        </button>
                      </div>
                    </div>

                    <div className="text-[10px] text-slate-500 font-mono-code truncate flex items-center gap-1">
                      <span>Endpoint:</span>
                      <code className="text-slate-300">{f.endpoint || f.affected_asset}</code>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* JAVASCRIPT & HIDDEN ENDPOINTS / SECRETS SPY CARD (User Requested) */}
      {standaloneJsResult && (
        <div className="p-4 rounded-xl bg-slate-900 border border-cyan-500/40 space-y-3 shadow-xl animate-in fade-in">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <FileCode className="w-5 h-5 text-cyan-400" />
              <div>
                <h3 className="text-xs font-bold text-white uppercase flex items-center gap-2">
                  <span>JavaScript & Hidden Endpoint Extractor (LinkFinder & Secret Spy)</span>
                  <span className="text-[9px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.5 rounded font-black">
                    {standaloneJsResult.totalScriptsAnalyzed} JS Bundles Scraped
                  </span>
                </h3>
                <p className="text-[10px] text-slate-400">
                  Target: <code className="text-cyan-300">{standaloneJsResult.targetUrl}</code> &bull; Extracted endpoints, leaked keys, and DOM XSS sinks
                </p>
              </div>
            </div>

            {/* Quick Metrics */}
            <div className="flex items-center gap-2 text-[10px] font-bold">
              <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                Endpoints: <b className="text-cyan-400">{standaloneJsResult.hiddenEndpoints?.length || 0}</b>
              </span>
              <span className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300">
                Secrets: <b className="text-rose-400">{standaloneJsResult.discoveredSecrets?.length || 0}</b>
              </span>
              <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300">
                DOM Sinks: <b className="text-amber-400">{standaloneJsResult.domXssSinks?.length || 0}</b>
              </span>
            </div>
          </div>

          {/* Sub-Tabs: Endpoints, Secrets, Sinks, Source Maps, Scripts */}
          <div className="flex items-center gap-1 border-b border-slate-800 text-[11px] overflow-x-auto pb-1">
            <button
              onClick={() => setJsActiveTab('endpoints')}
              className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                jsActiveTab === 'endpoints' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'
              }`}
            >
              <Radio className="w-3 h-3" />
              <span>Hidden Endpoints ({standaloneJsResult.hiddenEndpoints?.length || 0})</span>
            </button>

            <button
              onClick={() => setJsActiveTab('secrets')}
              className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                jsActiveTab === 'secrets' ? 'bg-rose-500 text-slate-950' : 'text-slate-400 hover:text-white'
              }`}
            >
              <Key className="w-3 h-3" />
              <span>Exposed Secrets ({standaloneJsResult.discoveredSecrets?.length || 0})</span>
            </button>

            <button
              onClick={() => setJsActiveTab('sinks')}
              className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                jsActiveTab === 'sinks' ? 'bg-amber-500 text-slate-950' : 'text-slate-400 hover:text-white'
              }`}
            >
              <Flame className="w-3 h-3" />
              <span>DOM XSS Sinks ({standaloneJsResult.domXssSinks?.length || 0})</span>
            </button>

            <button
              onClick={() => setJsActiveTab('sourcemaps')}
              className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                jsActiveTab === 'sourcemaps' ? 'bg-emerald-500 text-slate-950' : 'text-slate-400 hover:text-white'
              }`}
            >
              <FileSearch className="w-3 h-3" />
              <span>Source Maps ({standaloneJsResult.sourceMaps?.length || 0})</span>
            </button>

            <button
              onClick={() => setJsActiveTab('scripts')}
              className={`px-3 py-1 rounded-lg font-bold flex items-center gap-1 transition-all ${
                jsActiveTab === 'scripts' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              <FileCode className="w-3 h-3" />
              <span>JS Files ({standaloneJsResult.scripts?.length || 0})</span>
            </button>
          </div>

          {/* Sub-Tab 1: Hidden Endpoints View */}
          {jsActiveTab === 'endpoints' && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                  <input
                    type="text"
                    value={jsSearchFilter}
                    onChange={e => setJsSearchFilter(e.target.value)}
                    placeholder="Filter endpoints (e.g. admin, auth, graphql, v1)..."
                    className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <span className="text-[10px] text-slate-500 shrink-0">
                  Showing {filteredEndpoints.length} of {standaloneJsResult.hiddenEndpoints?.length || 0}
                </span>
              </div>

              {filteredEndpoints.length === 0 ? (
                <div className="py-6 text-center text-slate-500 text-xs font-mono-code">
                  No hidden endpoints matching filter.
                </div>
              ) : (
                <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
                  {filteredEndpoints.map((ep: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 flex items-center justify-between gap-2 text-xs font-mono-code transition-all"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span className={`text-[9px] px-1.5 py-0.5 rounded font-black uppercase ${
                          ep.severity === 'critical' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          ep.severity === 'high' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                          ep.severity === 'medium' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-slate-800 text-slate-300'
                        }`}>
                          {ep.category}
                        </span>
                        <code className="text-white font-bold truncate">{ep.endpoint}</code>
                      </div>

                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => handleCopy(ep.endpoint, `ep_${idx}`)}
                          className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-[10px] flex items-center gap-1 border border-slate-700"
                        >
                          {copiedKey === `ep_${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedKey === `ep_${idx}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Sub-Tab 2: Discovered Secrets & API Keys View */}
          {jsActiveTab === 'secrets' && (
            <div className="space-y-2">
              {(!standaloneJsResult.discoveredSecrets || standaloneJsResult.discoveredSecrets.length === 0) ? (
                <div className="py-6 text-center text-slate-500 text-xs font-mono-code">
                  No hardcoded secrets or API keys detected in scraped JavaScript files.
                </div>
              ) : (
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {standaloneJsResult.discoveredSecrets.map((sec: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950 border border-rose-900/60 space-y-1.5 font-mono-code text-xs"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] px-2 py-0.5 rounded font-black ${
                            sec.priority === 'P1' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                            sec.priority === 'P2' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                            'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}>
                            {sec.priority} &bull; {sec.severity.toUpperCase()}
                          </span>
                          <span className="font-bold text-white text-xs">{sec.title}</span>
                        </div>

                        <button
                          onClick={() => handleCopy(sec.secret, `sec_${idx}`)}
                          className="px-2 py-0.5 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 text-[10px] font-bold border border-rose-800 flex items-center gap-1"
                        >
                          {copiedKey === `sec_${idx}` ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedKey === `sec_${idx}` ? 'Copied' : 'Copy Secret'}</span>
                        </button>
                      </div>

                      <div className="p-2 rounded bg-slate-900 text-slate-300 text-[11px] truncate border border-slate-800">
                        Evidence snippet: <span className="text-rose-400 font-bold">{sec.evidence}</span>
                      </div>

                      <div className="text-[10px] text-slate-500 truncate">
                        Found in: <code className="text-slate-400">{sec.foundInScript}</code>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Sub-Tab 3: DOM XSS Sinks View */}
          {jsActiveTab === 'sinks' && (
            <div className="space-y-2">
              {(!standaloneJsResult.domXssSinks || standaloneJsResult.domXssSinks.length === 0) ? (
                <div className="py-6 text-center text-slate-500 text-xs font-mono-code">
                  No dangerous DOM sinks detected in analyzed scripts.
                </div>
              ) : (
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {standaloneJsResult.domXssSinks.map((sink: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950 border border-amber-900/40 text-xs font-mono-code space-y-1"
                    >
                      <div className="flex items-center justify-between text-amber-400 font-bold">
                        <span className="flex items-center gap-1.5">
                          <Flame className="w-3.5 h-3.5" />
                          <span>{sink.sink}</span>
                        </span>
                        <span className="text-[10px] text-slate-500">DOM Execution Sink</span>
                      </div>
                      <div className="p-1.5 rounded bg-slate-900 text-slate-300 text-[10px] truncate border border-slate-800">
                        {sink.snippet}
                      </div>
                      <div className="text-[9px] text-slate-500 truncate">
                        Script: <code className="text-slate-400">{sink.foundInScript}</code>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Sub-Tab 4: Source Maps View */}
          {jsActiveTab === 'sourcemaps' && (
            <div className="space-y-2">
              {(!standaloneJsResult.sourceMaps || standaloneJsResult.sourceMaps.length === 0) ? (
                <div className="py-6 text-center text-slate-500 text-xs font-mono-code">
                  No client-side source maps (.map) referenced.
                </div>
              ) : (
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {standaloneJsResult.sourceMaps.map((sm: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono-code flex items-center justify-between gap-2"
                    >
                      <div className="truncate">
                        <div className="flex items-center gap-2">
                          <span className={`text-[9px] px-1.5 py-0.2 rounded font-black ${
                            sm.isAccessible ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-800 text-slate-400'
                          }`}>
                            {sm.isAccessible ? 'EXPOSED (200 OK)' : 'PROTECTED'}
                          </span>
                          <code className="text-white font-bold truncate">{sm.mapUrl}</code>
                        </div>
                      </div>
                      {sm.isAccessible && (
                        <button
                          onClick={() => handleCopy(sm.mapUrl, `map_${idx}`)}
                          className="px-2 py-0.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-[10px] font-bold shrink-0"
                        >
                          {copiedKey === `map_${idx}` ? 'Copied' : 'Copy URL'}
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Sub-Tab 5: Scraped Scripts List View */}
          {jsActiveTab === 'scripts' && (
            <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
              {standaloneJsResult.scripts?.map((s: any, idx: number) => (
                <div
                  key={idx}
                  className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono-code flex items-center justify-between gap-2"
                >
                  <div className="truncate">
                    <code className="text-slate-300 font-bold truncate block">{s.url}</code>
                    <span className="text-[10px] text-slate-500">
                      Size: {(s.sizeBytes / 1024).toFixed(1)} KB &bull; SourceMap: {s.hasSourceMap ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopy(s.url, `script_${idx}`)}
                    className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-[10px] border border-slate-700 shrink-0"
                  >
                    {copiedKey === `script_${idx}` ? 'Copied' : 'Copy'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Modal: Exploitability & Proof-of-Concept Explainer */}
      {explainingFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-2xl p-4 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl space-y-3 font-mono-code text-xs max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="font-bold text-white text-sm flex items-center gap-1.5">
                <Code2 className="w-4 h-4 text-emerald-400" />
                AI Exploitability & PoC Builder: {explainingFinding.title}
              </span>
              <button
                onClick={() => setExplainingFinding(null)}
                className="text-slate-400 hover:text-white text-base"
              >
                &times;
              </button>
            </div>

            {isExplaining ? (
              <div className="py-8 text-center space-y-2">
                <RefreshCw className="w-5 h-5 text-emerald-400 animate-spin mx-auto" />
                <p className="text-slate-400 text-xs">Formulating root-cause analysis and reproducible PoC steps...</p>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-emerald-400 font-bold">Deep Triager Breakdown:</span>
                    <button
                      onClick={() => handleCopy(explanationText || '', 'explain_text')}
                      className="px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold flex items-center gap-1"
                    >
                      {copiedKey === 'explain_text' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === 'explain_text' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3 rounded bg-slate-900 text-slate-200 text-[11px] overflow-x-auto whitespace-pre-wrap border border-slate-800 leading-relaxed max-h-96">
                    {explanationText}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modal: 1-Click HackerOne Ready Submission Report */}
      {selectedFindingForReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-2xl p-4 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl space-y-3 font-mono-code text-xs max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="font-bold text-white text-sm flex items-center gap-1.5">
                <FileText className="w-4 h-4 text-cyan-400" />
                HackerOne / Bugcrowd Ready Submission Report
              </span>
              <button
                onClick={() => setSelectedFindingForReport(null)}
                className="text-slate-400 hover:text-white text-base"
              >
                &times;
              </button>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Pre-formatted submission Markdown:</span>
                <button
                  onClick={() => handleCopy(generateH1ReportText(selectedFindingForReport, targetInput), 'h1_modal')}
                  className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold flex items-center gap-1"
                >
                  {copiedKey === 'h1_modal' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'h1_modal' ? 'Copied to Clipboard!' : 'Copy HackerOne Markdown'}</span>
                </button>
              </div>

              <pre className="p-3 rounded bg-slate-900 text-slate-200 text-[11px] overflow-x-auto whitespace-pre-wrap border border-slate-800 max-h-80 leading-relaxed">
                {generateH1ReportText(selectedFindingForReport, targetInput)}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Interactive AI Bug Bounty Mentor Chat ("Ask VulnHunter AI") */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MessageSquare className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-bold text-white uppercase">Ask VulnHunter AI (Bug Bounty Mentor)</span>
          </div>
          <span className="text-[10px] text-slate-500">English, Urdu & Roman Urdu supported</span>
        </div>

        {/* Suggested Quick Questions */}
        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="text-[10px] text-slate-500 uppercase font-bold mr-1">Ask:</span>
          {[
            'How to find hidden API routes in JavaScript files?',
            'How to find leaked cloud keys and tokens?',
            'How to report P1 Critical bugs on HackerOne?',
            'What is the best way to bypass 403 Forbidden endpoints?'
          ].map(q => (
            <button
              key={q}
              onClick={() => handleAskAi(q)}
              disabled={isAsking}
              className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-emerald-300 text-[10px] transition-all"
            >
              {q}
            </button>
          ))}
        </div>

        {/* Chat History Messages */}
        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2 max-h-64 overflow-y-auto">
          {chatMessages.map((msg, idx) => (
            <div
              key={idx}
              className={`p-2.5 rounded-lg text-[11px] leading-relaxed ${
                msg.sender === 'user'
                  ? 'bg-emerald-950/40 border border-emerald-500/30 text-emerald-200 ml-6'
                  : 'bg-slate-900 border border-slate-800 text-slate-300 mr-6'
              }`}
            >
              <div className="flex items-center justify-between text-[9px] text-slate-500 mb-1">
                <span className="font-bold uppercase text-slate-400">
                  {msg.sender === 'user' ? 'Bug Hunter' : 'VulnHunter AI'}
                </span>
                <span>{msg.time}</span>
              </div>
              <div className="whitespace-pre-line font-mono-code">{msg.text}</div>
            </div>
          ))}

          {isAsking && (
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 text-[11px] flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 text-emerald-400 animate-spin" />
              <span>VulnHunter AI is formulating your bug hunting advice...</span>
            </div>
          )}
        </div>

        {/* Question Input */}
        <form
          onSubmit={e => {
            e.preventDefault();
            handleAskAi();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={question}
            onChange={e => setQuestion(e.target.value)}
            disabled={isAsking}
            placeholder="Ask anything about finding vulnerabilities or writing bug bounty reports..."
            className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs focus:outline-none focus:border-emerald-500 font-mono-code"
          />
          <button
            type="submit"
            disabled={isAsking || !question.trim()}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold flex items-center gap-1 transition-all active:scale-95 disabled:opacity-50"
          >
            <Send className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Ask AI</span>
          </button>
        </form>
      </div>
    </div>
  );
};

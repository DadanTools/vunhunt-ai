import React, { useState, useRef, useEffect } from 'react';
import { 
  Terminal as TerminalIcon, 
  Play, 
  Trash2, 
  Copy, 
  Check, 
  BatteryCharging, 
  Zap, 
  Layers, 
  ShieldAlert, 
  Globe2, 
  Maximize2,
  ChevronRight,
  ExternalLink,
  Smartphone
} from 'lucide-react';
import { ScopeRule } from '../types.ts';
import { TabId } from './BottomNav.tsx';

interface TerminalTabProps {
  scopes: ScopeRule[];
  onNavigateToTab?: (tab: TabId) => void;
}

interface CommandLog {
  id: string;
  command: string;
  timestamp: string;
  lines: string[];
  isError?: boolean;
}

const DEFAULT_BANNER = [
  '======================================================================',
  '       VULNHUNTER AI (v2.0) - ADVANCED ANDROID TERMUX WORKBENCH       ',
  '======================================================================',
  '[*] Environment: Android Termux (Linux ARM64/x86_64)',
  '[*] Scope Gate: Active (Zero un-authorized network traffic)',
  '[*] Engine: Native SQLite + Node.js/Python 3 Standard Library',
  '',
  'Type "help" to view all available commands or tap any quick-action below.',
  '======================================================================'
];

const QUICK_COMMANDS = [
  'help',
  'scope list',
  'recon localhost:3000',
  'fuzz http://localhost:3000',
  'permute localhost',
  'findings',
  'wake-lock',
  'system'
];

export const TerminalTab: React.FC<TerminalTabProps> = ({ scopes }) => {
  const [inputVal, setInputVal] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [logs, setLogs] = useState<CommandLog[]>([
    {
      id: 'init-banner',
      command: 'vulnhunter --init',
      timestamp: new Date().toLocaleTimeString(),
      lines: DEFAULT_BANNER
    }
  ]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const bottomRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Auto-scroll to bottom on new output
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const executeCommand = async (cmdToRun: string) => {
    const trimmed = cmdToRun.trim();
    if (!trimmed) return;

    // Handle local 'clear' command immediately
    if (trimmed.toLowerCase() === 'clear') {
      setLogs([]);
      setInputVal('');
      return;
    }

    setHistory(prev => [trimmed, ...prev.filter(c => c !== trimmed)]);
    setHistoryIndex(-1);
    setIsExecuting(true);
    setInputVal('');

    try {
      const res = await fetch('/api/termux/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: trimmed })
      });
      const data = await res.json();

      const newLog: CommandLog = {
        id: `cmd-${Date.now()}`,
        command: trimmed,
        timestamp: new Date().toLocaleTimeString(),
        lines: data.lines || [data.error || 'Execution completed.'],
        isError: !res.ok
      };

      setLogs(prev => [...prev, newLog]);
    } catch (err: any) {
      setLogs(prev => [
        ...prev,
        {
          id: `cmd-${Date.now()}`,
          command: trimmed,
          timestamp: new Date().toLocaleTimeString(),
          lines: [`[-] Network/Execution Error: ${err.message}`],
          isError: true
        }
      ]);
    } finally {
      setIsExecuting(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeCommand(inputVal);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length > 0 && historyIndex < history.length - 1) {
        const nextIdx = historyIndex + 1;
        setHistoryIndex(nextIdx);
        setInputVal(history[nextIdx]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const nextIdx = historyIndex - 1;
        setHistoryIndex(nextIdx);
        setInputVal(history[nextIdx]);
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setInputVal('');
      }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      setLogs([]);
    }
  };

  return (
    <div className="space-y-4 pb-20">
      {/* Top Header Card */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <TerminalIcon className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white font-mono-code">Android Termux Power Shell</h2>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-emerald-400 font-mono-code border border-slate-700">
                  CLI Native
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Direct command terminal with real reconnaissance and fuzzing engines</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setLogs([])}
              className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white text-xs font-mono-code flex items-center gap-1 transition-all"
              title="Clear terminal buffer (Ctrl+L)"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear</span>
            </button>
          </div>
        </div>

        {/* Quick Command Chips (Mobile Termux Touch Optimized) */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-[10px] text-slate-500 uppercase font-mono-code font-bold mr-1">Tap:</span>
          {QUICK_COMMANDS.map(q => (
            <button
              key={q}
              onClick={() => executeCommand(q)}
              className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-emerald-500/50 text-slate-300 hover:text-emerald-300 text-[11px] font-mono-code transition-all active:scale-95"
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {/* Main Terminal Window */}
      <div 
        onClick={() => inputRef.current?.focus()}
        className="w-full rounded-xl bg-slate-950 border border-slate-800 shadow-2xl p-3 sm:p-4 font-mono-code text-xs space-y-3 min-h-[440px] max-h-[600px] overflow-y-auto cursor-text"
      >
        {/* Terminal Logs */}
        {logs.map(log => (
          <div key={log.id} className="space-y-1">
            {/* Command Prompt Line */}
            <div className="flex items-center gap-1.5 text-slate-400">
              <span className="text-emerald-400 font-bold">u0_a241@termux</span>
              <span className="text-slate-600">:</span>
              <span className="text-cyan-400 font-semibold">~/vulnhunter</span>
              <span className="text-slate-400">$</span>
              <span className="text-white font-semibold">{log.command}</span>
              <span className="text-slate-600 text-[10px] ml-auto">{log.timestamp}</span>
            </div>

            {/* Output Lines */}
            <div className="pl-2 border-l border-slate-800/80 space-y-0.5 leading-relaxed">
              {log.lines.map((line, idx) => {
                let colorClass = 'text-slate-300';
                if (line.startsWith('[+]') || line.includes('[200 OK]')) colorClass = 'text-emerald-400';
                else if (line.startsWith('[-]') || line.includes('Error')) colorClass = 'text-rose-400';
                else if (line.startsWith('[*]')) colorClass = 'text-cyan-400';
                else if (line.includes('===') || line.includes('VULNHUNTER')) colorClass = 'text-amber-400 font-bold';

                return (
                  <div key={idx} className={`${colorClass} break-all whitespace-pre-wrap font-mono-code text-[11px]`}>
                    {line}
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        {/* Live Input Prompt */}
        <form onSubmit={handleSubmit} className="flex items-center gap-2 pt-2 border-t border-slate-900">
          <span className="text-emerald-400 font-bold shrink-0">u0_a241@termux</span>
          <span className="text-slate-600 shrink-0">:</span>
          <span className="text-cyan-400 font-semibold shrink-0">~/vulnhunter</span>
          <span className="text-slate-400 shrink-0">$</span>
          <input
            ref={inputRef}
            type="text"
            value={inputVal}
            onChange={e => setInputVal(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isExecuting}
            placeholder={isExecuting ? 'Executing command in background...' : 'Type command (e.g. recon, fuzz, help)...'}
            className="flex-1 bg-transparent text-white text-xs font-mono-code focus:outline-none placeholder:text-slate-600"
            autoFocus
          />
          {isExecuting && (
            <div className="w-3.5 h-3.5 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin shrink-0" />
          )}
        </form>

        <div ref={bottomRef} />
      </div>

      {/* Android Termux Power User Guide Card */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 font-mono-code text-xs">
        <div className="flex items-center gap-2 text-white font-bold">
          <Smartphone className="w-4 h-4 text-emerald-400" />
          <span>Termux Native CLI & Background Daemon Setup</span>
        </div>

        <p className="text-[11px] text-slate-300 leading-relaxed">
          Run VulnHunter natively in your Android Termux app without needing a computer. To prevent Android from terminating scans when the screen turns off:
        </p>

        <div className="space-y-2">
          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2">
            <code className="text-emerald-400 text-[11px] truncate">
              pkg update && pkg install -y python sqlite curl git && termux-wake-lock
            </code>
            <button
              onClick={() => handleCopy('pkg update && pkg install -y python sqlite curl git && termux-wake-lock', 'wake_lock')}
              className="p-1 rounded bg-slate-900 text-slate-400 hover:text-white shrink-0"
              title="Copy Termux wake-lock command"
            >
              {copiedKey === 'wake_lock' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2">
            <code className="text-cyan-300 text-[11px] truncate">
              python3 vulnhunter.py serve --port 8080
            </code>
            <button
              onClick={() => handleCopy('python3 vulnhunter.py serve --port 8080', 'serve')}
              className="p-1 rounded bg-slate-900 text-slate-400 hover:text-white shrink-0"
              title="Copy background serve command"
            >
              {copiedKey === 'serve' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950/80 border border-emerald-500/30 text-[10px] text-slate-400 flex items-start gap-2">
          <BatteryCharging className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <span>
            <strong>Battery Optimization Tip:</strong> Go to Android Settings &rarr; Apps &rarr; Termux &rarr; Battery &rarr; select <strong>Unrestricted</strong>. This enables uninterrupted 24/7 scanning.
          </span>
        </div>
      </div>
    </div>
  );
};

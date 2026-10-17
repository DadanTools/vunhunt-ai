import React, { useState } from 'react';
import { 
  ArrowLeftRight, 
  Play, 
  Trash2, 
  Search, 
  Send, 
  Clock, 
  Check, 
  Copy, 
  ShieldCheck, 
  AlertTriangle,
  Info,
  Power
} from 'lucide-react';
import { ProxyLog } from '../types.ts';

interface ProxyRepeaterTabProps {
  logs: ProxyLog[];
  proxyStatus: { isRunning: boolean; port: number; host: string; note: string };
  onStartProxy: (port?: number) => Promise<any>;
  onStopProxy: () => Promise<any>;
  onClearLogs: () => Promise<any>;
  onReplayRequest: (method: string, url: string, headers: Record<string, string>, body?: string) => Promise<any>;
}

export const ProxyRepeaterTab: React.FC<ProxyRepeaterTabProps> = ({
  logs,
  proxyStatus,
  onStartProxy,
  onStopProxy,
  onClearLogs,
  onReplayRequest
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'history' | 'repeater' | 'android-https'>('history');
  const [searchQuery, setSearchQuery] = useState('');
  
  // Repeater State
  const [repMethod, setRepMethod] = useState('GET');
  const [repUrl, setRepUrl] = useState('http://localhost:3000/api/lab/headers');
  const [repHeaders, setRepHeaders] = useState('Accept: application/json\nUser-Agent: VulnHunter-Repeater/1.0');
  const [repBody, setRepBody] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [repResponse, setRepResponse] = useState<any>(null);
  const [repError, setRepError] = useState<string | null>(null);

  const [selectedLog, setSelectedLog] = useState<ProxyLog | null>(null);

  const handleSendRepeater = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repUrl.trim()) return;

    setIsSending(true);
    setRepError(null);

    // Parse header lines
    const parsedHeaders: Record<string, string> = {};
    repHeaders.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx + 1).trim();
        if (k && v) parsedHeaders[k] = v;
      }
    });

    try {
      const res = await onReplayRequest(repMethod, repUrl.trim(), parsedHeaders, repBody || undefined);
      setRepResponse(res.response);
    } catch (err: any) {
      setRepError(err.message || 'Repeater request failed.');
    } finally {
      setIsSending(false);
    }
  };

  const loadLogIntoRepeater = (log: ProxyLog) => {
    setRepMethod(log.method);
    setRepUrl(log.url);
    try {
      const hdrs = JSON.parse(log.request_headers);
      const lines = Object.entries(hdrs).map(([k, v]) => `${k}: ${v}`).join('\n');
      setRepHeaders(lines);
    } catch (_e) {
      setRepHeaders('User-Agent: VulnHunter-Repeater/1.0');
    }
    setRepBody(log.request_body || '');
    setActiveSubTab('repeater');
  };

  const filteredLogs = logs.filter(l =>
    l.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
    l.method.toLowerCase().includes(searchQuery.toLowerCase()) ||
    l.host.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-4 pb-20">
      {/* Proxy Server Controller Bar */}
      <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-bold ${
            proxyStatus.isRunning ? 'bg-emerald-950 border border-emerald-500/40 text-emerald-400' : 'bg-slate-800 text-slate-500'
          }`}>
            <ArrowLeftRight className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-white font-mono-code">Local HTTP Proxy</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono-code font-bold ${
                proxyStatus.isRunning ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400'
              }`}>
                {proxyStatus.isRunning ? `127.0.0.1:${proxyStatus.port}` : 'STOPPED'}
              </span>
            </div>
            <p className="text-[10px] text-slate-400">Enforces scope on all forwarded HTTP traffic</p>
          </div>
        </div>

        <button
          onClick={() => proxyStatus.isRunning ? onStopProxy() : onStartProxy()}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono-code font-bold flex items-center gap-1.5 transition-all ${
            proxyStatus.isRunning
              ? 'bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800'
              : 'bg-emerald-600 hover:bg-emerald-500 text-slate-950'
          }`}
        >
          <Power className="w-3.5 h-3.5" />
          <span>{proxyStatus.isRunning ? 'Stop' : 'Start'}</span>
        </button>
      </div>

      {/* Mode Navigation */}
      <div className="flex rounded-xl bg-slate-900 p-1 border border-slate-800 text-xs font-mono-code">
        <button
          onClick={() => setActiveSubTab('history')}
          className={`flex-1 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'history' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          HTTP History ({logs.length})
        </button>
        <button
          onClick={() => setActiveSubTab('repeater')}
          className={`flex-1 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'repeater' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Repeater Editor
        </button>
        <button
          onClick={() => setActiveSubTab('android-https')}
          className={`py-1.5 px-3 rounded-lg font-semibold transition-all ${
            activeSubTab === 'android-https' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          Android HTTPS
        </button>
      </div>

      {/* Subtab 1: History */}
      {activeSubTab === 'history' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search requests by host, path, method..."
                className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white font-mono-code focus:outline-none focus:border-emerald-500"
              />
            </div>
            {logs.length > 0 && (
              <button
                onClick={onClearLogs}
                className="px-2.5 py-2 rounded-xl bg-slate-900 border border-slate-800 hover:bg-rose-950/80 text-slate-400 hover:text-rose-400 text-xs font-mono-code"
                title="Clear Traffic Log"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>

          {filteredLogs.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400">
              <ArrowLeftRight className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              <p>No proxy requests recorded yet.</p>
              <p className="text-[11px] text-slate-500 mt-1">
                Configure your mobile browser or curl to use HTTP proxy <code>127.0.0.1:{proxyStatus.port}</code>, or send requests via Repeater.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredLogs.map(log => (
                <div 
                  key={log.id} 
                  className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs hover:border-slate-700 transition-all cursor-pointer"
                  onClick={() => setSelectedLog(selectedLog?.id === log.id ? null : log)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono-code font-bold ${
                        log.method === 'GET' ? 'bg-blue-950 text-blue-400 border border-blue-800' :
                        log.method === 'POST' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                        'bg-purple-950 text-purple-400 border border-purple-800'
                      }`}>
                        {log.method}
                      </span>
                      <span className="font-mono-code text-white font-semibold truncate text-[11px]">
                        {log.path || '/'}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {log.status_code && (
                        <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono-code font-bold ${
                          log.status_code >= 200 && log.status_code < 300 ? 'text-emerald-400' :
                          log.status_code >= 400 && log.status_code < 500 ? 'text-amber-400' : 'text-rose-400'
                        }`}>
                          {log.status_code}
                        </span>
                      )}
                      <span className="text-[10px] text-slate-500 font-mono-code">
                        {log.duration_ms}ms
                      </span>
                    </div>
                  </div>

                  <div className="mt-1 flex items-center justify-between text-[10px] text-slate-400 font-mono-code">
                    <span className="truncate max-w-[200px]">{log.host}</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        loadLogIntoRepeater(log);
                      }}
                      className="text-emerald-400 hover:text-emerald-300 font-semibold"
                    >
                      Send to Repeater →
                    </button>
                  </div>

                  {selectedLog?.id === log.id && (
                    <div className="mt-3 pt-3 border-t border-slate-800 space-y-2 text-[11px] font-mono-code">
                      <div>
                        <span className="text-slate-400">Request Headers:</span>
                        <pre className="mt-1 p-2 rounded bg-slate-950 text-slate-300 overflow-x-auto text-[10px]">
                          {log.request_headers}
                        </pre>
                      </div>
                      {log.request_body && (
                        <div>
                          <span className="text-slate-400">Request Body:</span>
                          <pre className="mt-1 p-2 rounded bg-slate-950 text-slate-300 overflow-x-auto text-[10px]">
                            {log.request_body}
                          </pre>
                        </div>
                      )}
                      <div>
                        <span className="text-slate-400">Response Sample:</span>
                        <pre className="mt-1 p-2 rounded bg-slate-950 text-slate-300 overflow-x-auto text-[10px] max-h-32">
                          {log.response_body || 'No response body'}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Subtab 2: Repeater */}
      {activeSubTab === 'repeater' && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-white font-mono-code flex items-center gap-1.5">
              <Send className="w-3.5 h-3.5 text-emerald-400" />
              Repeater Request Editor
            </h3>
            <span className="text-[10px] text-slate-500 font-mono-code">Safe authorized replay</span>
          </div>

          {repError && (
            <div className="p-3 rounded-lg bg-rose-950 border border-rose-800 text-rose-300 text-xs font-mono-code">
              {repError}
            </div>
          )}

          <form onSubmit={handleSendRepeater} className="space-y-3">
            <div className="flex gap-2">
              <select
                value={repMethod}
                onChange={e => setRepMethod(e.target.value)}
                className="w-24 px-2 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs font-bold focus:outline-none focus:border-emerald-500"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
                <option value="OPTIONS">OPTIONS</option>
                <option value="HEAD">HEAD</option>
              </select>

              <input
                type="text"
                value={repUrl}
                onChange={e => setRepUrl(e.target.value)}
                placeholder="http://localhost:3000/api/lab/headers"
                className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-emerald-500"
                required
              />
            </div>

            <div>
              <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
                Headers (Key: Value per line)
              </label>
              <textarea
                rows={3}
                value={repHeaders}
                onChange={e => setRepHeaders(e.target.value)}
                className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-mono-code text-slate-400 mb-1">
                Request Body (Optional)
              </label>
              <textarea
                rows={3}
                value={repBody}
                onChange={e => setRepBody(e.target.value)}
                placeholder='{"key": "value"}'
                className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono-code text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>

            <button
              type="submit"
              disabled={isSending || !repUrl.trim()}
              className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono-code text-xs transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{isSending ? 'Sending Request...' : 'Send Request (Repeater)'}</span>
            </button>
          </form>

          {/* Response Viewer */}
          {repResponse && (
            <div className="mt-4 pt-4 border-t border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-mono-code">Response Received</span>
                <div className="flex items-center gap-2 font-mono-code text-xs">
                  <span className={`font-bold ${
                    repResponse.statusCode >= 200 && repResponse.statusCode < 300 ? 'text-emerald-400' : 'text-amber-400'
                  }`}>
                    HTTP {repResponse.statusCode} {repResponse.statusMessage}
                  </span>
                  <span className="text-slate-500">•</span>
                  <span className="text-slate-400">{repResponse.durationMs}ms</span>
                </div>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 font-mono-code">Headers:</span>
                <pre className="mt-1 p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 font-mono-code text-[10px] overflow-x-auto max-h-32">
                  {JSON.stringify(repResponse.headers, null, 2)}
                </pre>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 font-mono-code">Body:</span>
                <pre className="mt-1 p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 font-mono-code text-[10px] overflow-x-auto max-h-48 whitespace-pre-wrap">
                  {repResponse.body || '<Empty Body>'}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Subtab 3: Android HTTPS Documentation & Trust Guidance */}
      {activeSubTab === 'android-https' && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs text-slate-300">
          <div className="flex items-center gap-2 text-white font-bold font-mono-code">
            <Info className="w-4 h-4 text-cyan-400" />
            Android HTTPS Interception Architecture & Trust Policy
          </div>

          <p className="leading-relaxed text-slate-400">
            In modern Android (Android 7.0 Nougat and later), the operating system intentionally does <strong>not trust user-installed CA certificates</strong> for third-party application traffic by default. This is a deliberate platform security boundary.
          </p>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <p className="font-semibold text-slate-200 font-mono-code text-[11px]">
              Supported Interception Strategies in Termux:
            </p>
            <ul className="list-disc pl-4 space-y-1 text-[11px] text-slate-400">
              <li>
                <strong>Plain HTTP:</strong> Fully functional immediately without certificate setup. All requests/responses are logged and replayable in Repeater.
              </li>
              <li>
                <strong>Firefox for Android (Fennec/Mull):</strong> Go to <code>about:config</code>, set <code>security.enterprise_roots.enabled = true</code>. This enables user CAs installed in Android Settings → Security → Certificates.
              </li>
              <li>
                <strong>Target Android App Auditing:</strong> Add <code>&lt;certificates src="user" /&gt;</code> in <code>network_security_config.xml</code> during authorized APK testing or use Magisk TrustUserCerts module on rooted test devices.
              </li>
            </ul>
          </div>

          <p className="text-[11px] text-slate-500">
            VulnHunter AI strictly respects device boundaries and never attempts silent or root certificate injection.
          </p>
        </div>
      )}
    </div>
  );
};

import React, { useState, useMemo, useEffect } from 'react';
import { 
  FlaskConical, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  ShieldCheck, 
  Layers, 
  ExternalLink, 
  RefreshCw, 
  Bug, 
  Code2, 
  Copy, 
  Check, 
  Shield, 
  FileCode, 
  ArrowRight, 
  Star, 
  Search, 
  Download, 
  Filter, 
  Bookmark,
  History,
  Gauge,
  FilePlus,
  FileText,
  X,
  Trash2,
  Zap,
  Clock
} from 'lucide-react';

interface LocalLabTabProps {
  onRunTest: (targetUrl: string, scanType: string) => Promise<any>;
}

type VulnerabilityCategory = 'xss' | 'sqli' | 'ssrf' | 'cors' | 'headers';

interface BenignTestPreset {
  id: string;
  name: string;
  category: VulnerabilityCategory;
  categoryLabel: string;
  rawInput: string;
  description: string;
  defensiveRemediation: string;
  codeSnippet: string;
  tags: string[];
  isCustom?: boolean;
}

interface BenchmarkResult {
  presetId: string;
  timestamp: string;
  avgLatency: number;
  minLatency: number;
  maxLatency: number;
  statusCode: number;
  contentLength: number;
  filterStatus: 'Reflected (Unfiltered)' | 'Sanitized / Encoded' | 'Blocked (403)' | 'Server Error (500)';
}

interface HistoryItem {
  id: string;
  timestamp: string;
  payload: string;
  name: string;
  category: string;
  latencyMs: number;
  statusCode: number;
  filterStatus: string;
}

const INITIAL_PRESETS: BenignTestPreset[] = [
  // XSS & Template Injection (SSTI)
  {
    id: 'xss-basic-tag',
    name: 'HTML Tag Delimiter Boundary',
    category: 'xss',
    categoryLabel: 'XSS & HTML',
    rawInput: '<div data-canary="vulnhunter">test</div>',
    description: 'Verifies whether HTML tag markup is properly escaped before DOM rendering.',
    defensiveRemediation: 'Use context-aware HTML entity escaping or modern frameworks that auto-escape (e.g. React JSX text content). Enforce CSP: default-src \'self\'.',
    codeSnippet: `// Secure React / Node pattern:
const safeHtml = DOMPurify.sanitize(userInput);
// Or standard text rendering (inherently safe):
return <div>{userInput}</div>;`,
    tags: ['html', 'dom', 'tag-breakout']
  },
  {
    id: 'xss-attribute-quote',
    name: 'Attribute Quote Context Boundary',
    category: 'xss',
    categoryLabel: 'XSS & HTML',
    rawInput: '" onfocus="console.log(1)" autofocus="',
    description: 'Tests if user input inserted inside an HTML attribute properly escapes double quotes.',
    defensiveRemediation: 'Escape quotes and attribute delimiters (&quot; and &#39;) and avoid dynamic inline event handlers.',
    codeSnippet: `// Secure HTML attribute escaping:
function escapeAttr(s) {
  return s.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}`,
    tags: ['attribute', 'event-handler', 'quotes']
  },
  {
    id: 'xss-js-context',
    name: 'JavaScript String Literal Breakout',
    category: 'xss',
    categoryLabel: 'XSS & HTML',
    rawInput: "'-alert(1)-'",
    description: 'Tests whether input injected into an inline script block breaks out of single-quoted string literals.',
    defensiveRemediation: 'Never place untrusted user input directly into inline JavaScript. Pass data via JSON data-attributes and JSON.parse().',
    codeSnippet: `// Safe JSON embedding in HTML:
<div id="data" data-user={JSON.stringify(userData)} />`,
    tags: ['script-context', 'single-quote']
  },
  {
    id: 'xss-template-ssti',
    name: 'Template Expression Canary (SSTI)',
    category: 'xss',
    categoryLabel: 'XSS & HTML',
    rawInput: '{{7*7}}',
    description: 'Safe mathematical expression canary used to detect if template engines (Jinja2, Twig, Angular) evaluate user input.',
    defensiveRemediation: 'Disable arbitrary template evaluation. Use sandboxed templating contexts or pass user content as variables, not template bodies.',
    codeSnippet: `// Python Jinja2:
template = env.from_string("Hello {{ name }}") # Safe: name passed in render()
template.render(name=user_input)`,
    tags: ['ssti', 'templates', 'canary']
  },

  // SQL Injection (SQLi)
  {
    id: 'sqli-quote-term',
    name: 'SQL String Literal Boundary Marker',
    category: 'sqli',
    categoryLabel: 'SQL Injection',
    rawInput: "' OR '1'='1",
    description: 'Validates that SQL string delimiters do not alter query logic.',
    defensiveRemediation: 'Always use parameterized queries (Prepared Statements). Never concatenate user variables directly into SQL strings.',
    codeSnippet: `// Secure Parameterized Query:
const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
const user = stmt.get(inputUsername); // Input is treated strictly as data`,
    tags: ['auth-bypass-test', 'quotes', 'boolean']
  },
  {
    id: 'sqli-comment-term',
    name: 'SQL Inline Comment Boundary',
    category: 'sqli',
    categoryLabel: 'SQL Injection',
    rawInput: "admin' --",
    description: 'Tests if inline SQL comment markers (--) are neutralized by the database driver.',
    defensiveRemediation: 'Parameterized queries completely isolate user inputs, rendering comment sequences harmless.',
    codeSnippet: `// In Python sqlite3:
cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))`,
    tags: ['comments', 'truncation']
  },
  {
    id: 'sqli-numeric-probe',
    name: 'SQL Numeric Identifier Boundary',
    category: 'sqli',
    categoryLabel: 'SQL Injection',
    rawInput: '1 OR 1=1',
    description: 'Tests if unquoted numeric parameters allow boolean logic injection.',
    defensiveRemediation: 'Cast inputs strictly to integers (parseInt/Number) and use parameter binding.',
    codeSnippet: `// Node.js integer validation:
const id = Number.parseInt(req.params.id, 10);
if (Number.isNaN(id)) throw new Error("Invalid integer ID");`,
    tags: ['numeric', 'integer-check']
  },
  {
    id: 'sqli-union-probe',
    name: 'SQL Union Null Column Probe',
    category: 'sqli',
    categoryLabel: 'SQL Injection',
    rawInput: "' UNION SELECT NULL, NULL--",
    description: 'Safe column count probe used to test whether database queries enforce type and column constraints.',
    defensiveRemediation: 'Use an ORM (e.g., Prisma, Drizzle, TypeORM) or parameterized queries to completely prevent UNION query stacking.',
    codeSnippet: `// Drizzle ORM:
await db.select().from(users).where(eq(users.id, inputId));`,
    tags: ['union', 'null-columns']
  },

  // SSRF & Egress
  {
    id: 'ssrf-localhost-v4',
    name: 'Loopback Localhost IP Boundary (IPv4)',
    category: 'ssrf',
    categoryLabel: 'SSRF & Egress',
    rawInput: 'http://127.0.0.1:8080/internal/metrics',
    description: 'Validates that the server-side HTTP client refuses requests to loopback addresses.',
    defensiveRemediation: 'Validate target IP before fetching: resolve hostname via DNS, check against private CIDR ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16), and disable redirects.',
    codeSnippet: `// Secure SSRF Validation:
const parsed = new URL(targetUrl);
const ip = await dns.lookup(parsed.hostname);
if (isPrivateOrLoopbackIP(ip.address)) {
  throw new Error("Access to internal network blocked.");
}`,
    tags: ['ipv4', 'loopback', 'internal-ports']
  },
  {
    id: 'ssrf-localhost-v6',
    name: 'Loopback Localhost IPv6 Notation',
    category: 'ssrf',
    categoryLabel: 'SSRF & Egress',
    rawInput: 'http://[::1]:8080/admin',
    description: 'Tests whether SSRF validation filters handle IPv6 bracketed loopback representations.',
    defensiveRemediation: 'Normalize and validate both IPv4 and IPv6 representations before issuing HTTP requests.',
    codeSnippet: `// IPv6 validation:
if (ip.family === 6 && (ip.address === '::1' || ip.address.startsWith('fe80:'))) {
  throw new Error("IPv6 loopback/link-local forbidden");
}`,
    tags: ['ipv6', 'bracket-notation']
  },
  {
    id: 'ssrf-cloud-metadata',
    name: 'Cloud Metadata IP Guard Check',
    category: 'ssrf',
    categoryLabel: 'SSRF & Egress',
    rawInput: 'http://169.254.169.254/latest/meta-data/',
    description: 'Tests whether the cloud instance metadata IP is barred from outbound requests.',
    defensiveRemediation: 'Hardcode firewall / egress rules blocking 169.254.169.254 and require IMDSv2 session tokens.',
    codeSnippet: `// VulnHunter Scope Gate rule:
if (ip.startsWith("169.254.")) {
  return { authorized: false, reason: "Cloud metadata link-local blocked" };
}`,
    tags: ['aws', 'metadata', 'link-local']
  },
  {
    id: 'ssrf-dns-rebind',
    name: 'DNS Rebinding Probe Domain',
    category: 'ssrf',
    categoryLabel: 'SSRF & Egress',
    rawInput: 'http://127.0.0.1.nip.io:3000/status',
    description: 'Tests whether DNS filters verify resolved IP addresses rather than just hostnames.',
    defensiveRemediation: 'Perform DNS resolution immediately before connection and bind socket directly to the validated IP address.',
    codeSnippet: `// Custom HTTP agent pinning to resolved IP:
const agent = new http.Agent({ lookup: safeCustomLookup });`,
    tags: ['dns-rebind', 'nip.io']
  },

  // CORS & Security Headers
  {
    id: 'cors-null-origin',
    name: 'CORS Null Origin Reflection',
    category: 'cors',
    categoryLabel: 'CORS & Origin',
    rawInput: 'null',
    description: 'Tests if Access-Control-Allow-Origin mistakenly reflects the untrusted "null" origin.',
    defensiveRemediation: 'Never trust or reflect Origin: null. Only whitelist explicit, trusted domains over HTTPS.',
    codeSnippet: `// Secure CORS Middleware:
const whitelist = ['https://trusted.app.com'];
if (whitelist.includes(req.headers.origin)) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
}`,
    tags: ['origin-null', 'sandboxed-iframe']
  },
  {
    id: 'cors-wildcard-cred',
    name: 'CORS Wildcard with Credentials',
    category: 'cors',
    categoryLabel: 'CORS & Origin',
    rawInput: '*',
    description: 'Tests whether the server misconfigures Access-Control-Allow-Origin: * alongside Allow-Credentials: true.',
    defensiveRemediation: 'Standard browsers reject wildcard origin with credentials. Ensure explicit origin verification.',
    codeSnippet: `// Correct CORS configuration:
res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');
res.setHeader('Access-Control-Allow-Credentials', 'true');`,
    tags: ['credentials', 'wildcard']
  },
  {
    id: 'crlf-header-injection',
    name: 'CR-LF Header Injection Boundary',
    category: 'headers',
    categoryLabel: 'Header Injection',
    rawInput: 'canary%0d%0aSet-Cookie: session=vulnhunter',
    description: 'Tests if newline characters (%0d%0a / \\r\\n) in user parameters can split HTTP response headers.',
    defensiveRemediation: 'Strip or reject CR/LF characters (\\r and \\n) from all header values before writing HTTP response.',
    codeSnippet: `// Node.js sanitize header value:
const safeValue = headerVal.replace(/[\\r\\n]/g, '');
res.setHeader('X-Custom-Header', safeValue);`,
    tags: ['crlf', 'header-splitting', 'cookies']
  }
];

const LOCAL_STORAGE_BOOKMARKS_KEY = 'vulnhunter_bookmarked_payloads';
const LOCAL_STORAGE_CUSTOM_PRESETS_KEY = 'vulnhunter_custom_payloads';
const LOCAL_STORAGE_HISTORY_KEY = 'vulnhunter_payload_history';

export const LocalLabTab: React.FC<LocalLabTabProps> = ({ onRunTest }) => {
  const [activeSubTab, setActiveSubTab] = useState<'fixtures' | 'matrix' | 'browser'>('browser');
  const [runningTarget, setRunningTarget] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ target: string; message: string } | null>(null);

  // Sanitization Matrix State
  const [selectedCategory, setSelectedCategory] = useState<VulnerabilityCategory>('xss');
  const [customInput, setCustomInput] = useState<string>('<div data-canary="test">canary</div>');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Searchable Browser State
  const [searchQuery, setSearchQuery] = useState('');
  const [browserCategory, setBrowserCategory] = useState<string>('all');
  const [showBookmarksOnly, setShowBookmarksOnly] = useState(false);

  // Custom Presets State (Add Payload to File/Library)
  const [customPresets, setCustomPresets] = useState<BenignTestPreset[]>(() => {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_CUSTOM_PRESETS_KEY);
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  });

  // Modal to add a new payload to file / library
  const [showAddModal, setShowAddModal] = useState(false);
  const [newPayloadName, setNewPayloadName] = useState('');
  const [newPayloadCategory, setNewPayloadCategory] = useState<VulnerabilityCategory>('xss');
  const [newPayloadInput, setNewPayloadInput] = useState('');
  const [newPayloadDesc, setNewPayloadDesc] = useState('');

  // Bookmarks State
  const [bookmarks, setBookmarks] = useState<string[]>(() => {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_BOOKMARKS_KEY);
      return stored ? JSON.parse(stored) : ['xss-basic-tag', 'sqli-quote-term', 'ssrf-localhost-v4'];
    } catch {
      return ['xss-basic-tag', 'sqli-quote-term', 'ssrf-localhost-v4'];
    }
  });

  // Benchmark Engine State
  const [benchmarkingId, setBenchmarkingId] = useState<string | null>(null);
  const [benchmarkResults, setBenchmarkResults] = useState<Record<string, BenchmarkResult>>({});

  // Payload History Sidebar State
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [historyItems, setHistoryItems] = useState<HistoryItem[]>(() => {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_HISTORY_KEY);
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  });

  // Sync to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(LOCAL_STORAGE_BOOKMARKS_KEY, JSON.stringify(bookmarks));
    } catch {}
  }, [bookmarks]);

  useEffect(() => {
    try {
      localStorage.setItem(LOCAL_STORAGE_CUSTOM_PRESETS_KEY, JSON.stringify(customPresets));
    } catch {}
  }, [customPresets]);

  useEffect(() => {
    try {
      localStorage.setItem(LOCAL_STORAGE_HISTORY_KEY, JSON.stringify(historyItems));
    } catch {}
  }, [historyItems]);

  const allPresets = useMemo(() => {
    return [...INITIAL_PRESETS, ...customPresets];
  }, [customPresets]);

  const toggleBookmark = (id: string) => {
    setBookmarks(prev => 
      prev.includes(id) ? prev.filter(b => b !== id) : [...prev, id]
    );
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // 1. BENCHMARK ENGINE
  const handleRunBenchmark = async (preset: BenignTestPreset) => {
    setBenchmarkingId(preset.id);
    const timings: number[] = [];
    let lastStatus = 0;
    let lastLength = 0;
    let reflected = false;

    try {
      // 3 rounds of measurement for latency stability
      for (let i = 0; i < 3; i++) {
        const start = performance.now();
        const res = await fetch(`/api/lab/reflected?q=${encodeURIComponent(preset.rawInput)}`, {
          method: 'GET',
          headers: { 'X-VulnHunter-Benchmark': 'true' }
        });
        const text = await res.text();
        const duration = Math.round(performance.now() - start);
        timings.push(duration);
        lastStatus = res.status;
        lastLength = text.length;
        if (text.includes(preset.rawInput)) {
          reflected = true;
        }
      }

      const avgLatency = Math.round(timings.reduce((a, b) => a + b, 0) / timings.length);
      const minLatency = Math.min(...timings);
      const maxLatency = Math.max(...timings);

      let filterStatus: BenchmarkResult['filterStatus'] = 'Sanitized / Encoded';
      if (lastStatus === 403) filterStatus = 'Blocked (403)';
      else if (lastStatus >= 500) filterStatus = 'Server Error (500)';
      else if (reflected) filterStatus = 'Reflected (Unfiltered)';

      const result: BenchmarkResult = {
        presetId: preset.id,
        timestamp: new Date().toLocaleTimeString(),
        avgLatency,
        minLatency,
        maxLatency,
        statusCode: lastStatus,
        contentLength: lastLength,
        filterStatus
      };

      setBenchmarkResults(prev => ({ ...prev, [preset.id]: result }));

      // Append to History Sidebar
      const newHistoryItem: HistoryItem = {
        id: `hist-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        payload: preset.rawInput,
        name: preset.name,
        category: preset.categoryLabel,
        latencyMs: avgLatency,
        statusCode: lastStatus,
        filterStatus
      };

      setHistoryItems(prev => [newHistoryItem, ...prev.slice(0, 49)]); // keep last 50
    } catch (err: any) {
      alert(`Benchmark error: ${err.message}`);
    } finally {
      setBenchmarkingId(null);
    }
  };

  // 2. ADD PAYLOAD TO FILE / WORDLIST EXPORT
  const handleSaveCustomPayload = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPayloadName.trim() || !newPayloadInput.trim()) return;

    const newPreset: BenignTestPreset = {
      id: `custom-${Date.now()}`,
      name: newPayloadName.trim(),
      category: newPayloadCategory,
      categoryLabel: newPayloadCategory.toUpperCase(),
      rawInput: newPayloadInput.trim(),
      description: newPayloadDesc.trim() || 'Custom user test vector.',
      defensiveRemediation: 'Apply context-specific sanitization and boundary validation.',
      codeSnippet: '// Validate input parameters strictly before parsing.',
      tags: ['custom', 'wordlist'],
      isCustom: true
    };

    setCustomPresets(prev => [newPreset, ...prev]);
    setBookmarks(prev => [...prev, newPreset.id]);
    setShowAddModal(false);
    setNewPayloadName('');
    setNewPayloadInput('');
    setNewPayloadDesc('');
  };

  const handleDownloadWordlist = (format: 'txt' | 'json') => {
    if (format === 'txt') {
      const lines = allPresets.map(p => p.rawInput).join('\n');
      const blob = new Blob([lines], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnhunter-payloads-${Date.now()}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const data = JSON.stringify(allPresets, null, 2);
      const blob = new Blob([data], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnhunter-test-suite-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const handleClearHistory = () => {
    if (confirm('Are you sure you want to clear all payload benchmark history?')) {
      setHistoryItems([]);
      localStorage.removeItem(LOCAL_STORAGE_HISTORY_KEY);
    }
  };

  const labEndpoints = [
    {
      title: 'Insecure Headers & Cookie Fixture',
      path: '/api/lab/headers',
      scanType: 'exposure',
      category: 'Security Headers',
      expected: 'Missing CSP, missing X-Frame-Options, insecure Set-Cookie attributes',
      type: 'vulnerable'
    },
    {
      title: 'Hardened Baseline Fixture (Negative Control)',
      path: '/api/lab/secure-endpoint',
      scanType: 'exposure',
      category: 'Negative Test',
      expected: 'Zero findings! Demonstrates scanner does NOT produce false positives when hardened',
      type: 'hardened'
    },
    {
      title: 'Safe Reflected Input Canary Fixture',
      path: '/api/lab/reflected?q=test',
      scanType: 'injection',
      category: 'XSS Canary',
      expected: 'Safe non-destructive canary reflection indicator',
      type: 'vulnerable'
    },
    {
      title: 'Permissive CORS Misconfiguration Fixture',
      path: '/api/lab/cors',
      scanType: 'injection',
      category: 'CORS Origin Reflection',
      expected: 'Permissive origin reflection with credentials',
      type: 'vulnerable'
    },
    {
      title: 'Sensitive Path Exposure Fixture',
      path: '/api/lab/sensitive-path/.env',
      scanType: 'exposure',
      category: 'Information Disclosure',
      expected: 'Exposed dotfile configuration indicator (.env / git)',
      type: 'vulnerable'
    }
  ];

  const handleTestEndpoint = async (path: string, scanType: string) => {
    const fullUrl = `http://localhost:3000${path}`;
    setRunningTarget(path);
    setLastResult(null);

    try {
      await onRunTest(fullUrl, scanType);
      setLastResult({
        target: path,
        message: `Scan successfully queued against local lab fixture "${path}". Check the Findings and Scanners tabs to inspect results.`
      });
    } catch (err: any) {
      setLastResult({
        target: path,
        message: `Lab test error: ${err.message}`
      });
    } finally {
      setRunningTarget(null);
    }
  };

  // Live Transformation Calculations for Matrix
  const transformations = useMemo(() => {
    const raw = customInput;
    let urlEncoded = '';
    try { urlEncoded = encodeURIComponent(raw); } catch { urlEncoded = 'Error'; }

    let doubleUrlEncoded = '';
    try { doubleUrlEncoded = encodeURIComponent(urlEncoded); } catch { doubleUrlEncoded = 'Error'; }

    let htmlDecimal = '';
    for (let i = 0; i < raw.length; i++) htmlDecimal += `&#${raw.charCodeAt(i)};`;

    let htmlHex = '';
    for (let i = 0; i < raw.length; i++) htmlHex += `&#x${raw.charCodeAt(i).toString(16)};`;

    let base64 = '';
    try { base64 = btoa(unescape(encodeURIComponent(raw))); } catch { base64 = 'N/A'; }

    let fullWidth = '';
    for (let i = 0; i < raw.length; i++) {
      const code = raw.charCodeAt(i);
      if (code >= 33 && code <= 126) fullWidth += String.fromCharCode(code + 65248);
      else fullWidth += raw[i];
    }

    return { raw, urlEncoded, doubleUrlEncoded, htmlDecimal, htmlHex, base64, fullWidth };
  }, [customInput]);

  const activePreset = useMemo(() => {
    return allPresets.find(p => p.category === selectedCategory) || allPresets[0];
  }, [selectedCategory, allPresets]);

  // Filtered Test Cases for the Browser
  const filteredBrowserPresets = useMemo(() => {
    return allPresets.filter(p => {
      const matchesSearch = 
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.rawInput.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesCat = browserCategory === 'all' || p.category === browserCategory;
      const matchesBookmarks = !showBookmarksOnly || bookmarks.includes(p.id);

      return matchesSearch && matchesCat && matchesBookmarks;
    });
  }, [searchQuery, browserCategory, showBookmarksOnly, bookmarks, allPresets]);

  return (
    <div className="relative space-y-4 pb-20">
      {/* Header & Subtab Switcher */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <FlaskConical className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white font-mono-code">Local Security Test Lab</h2>
              <p className="text-[11px] text-slate-400">Deterministic fixtures, live benchmarking & payload wordlists</p>
            </div>
          </div>

          {/* Quick Actions: History Sidebar Toggle & Bookmark counter */}
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setIsHistoryOpen(prev => !prev)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-mono-code transition-all ${
                isHistoryOpen
                  ? 'bg-cyan-950 border-cyan-500 text-cyan-300'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
              }`}
              title="Toggle Payload History Sidebar"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              <span>History</span>
              <span className="px-1 rounded bg-slate-800 text-[10px] text-cyan-300">{historyItems.length}</span>
            </button>

            <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono-code">
              <Star className="w-3.5 h-3.5 text-amber-400 fill-amber-400" />
              <span className="text-slate-300 font-bold">{bookmarks.length}</span>
            </div>
          </div>
        </div>

        {/* Sub-navigation buttons */}
        <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs font-mono-code">
          <button
            onClick={() => setActiveSubTab('browser')}
            className={`flex-1 py-1.5 rounded-md font-semibold transition-all flex items-center justify-center gap-1.5 ${
              activeSubTab === 'browser'
                ? 'bg-slate-800 text-amber-400 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Bookmark className="w-3.5 h-3.5" />
            <span>Payload Browser</span>
          </button>
          <button
            onClick={() => setActiveSubTab('matrix')}
            className={`flex-1 py-1.5 rounded-md font-semibold transition-all flex items-center justify-center gap-1.5 ${
              activeSubTab === 'matrix'
                ? 'bg-slate-800 text-cyan-400 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Encoder Matrix</span>
          </button>
          <button
            onClick={() => setActiveSubTab('fixtures')}
            className={`flex-1 py-1.5 rounded-md font-semibold transition-all ${
              activeSubTab === 'fixtures'
                ? 'bg-slate-800 text-emerald-400 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Lab Fixtures (5)
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SUBTAB 1: SEARCHABLE PAYLOAD BROWSER & BENCHMARKING ENGINE                */}
      {/* ========================================================================= */}
      {activeSubTab === 'browser' && (
        <div className="space-y-3">
          {/* Controls Bar: Search, Category Filters, Export File, Add to File */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Search payloads by name, raw string, tag..."
                  className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white font-mono-code focus:outline-none focus:border-amber-500"
                />
              </div>

              {/* Action Buttons: Add Custom & Export to File */}
              <div className="flex items-center gap-1.5 shrink-0 flex-wrap">
                <button
                  onClick={() => setShowAddModal(true)}
                  className="px-2.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono-code text-xs flex items-center gap-1.5 transition-all active:scale-95 shadow-sm"
                  title="Add custom payload to wordlist library"
                >
                  <FilePlus className="w-3.5 h-3.5" />
                  <span>Add Payload</span>
                </button>

                <button
                  onClick={() => handleDownloadWordlist('txt')}
                  className="px-2.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-mono-code text-xs font-bold flex items-center gap-1.5 transition-all active:scale-95 border border-slate-700"
                  title="Export all payloads to .txt wordlist file"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Save .txt</span>
                </button>

                <button
                  onClick={() => handleDownloadWordlist('json')}
                  className="px-2.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-mono-code text-xs font-bold flex items-center gap-1.5 transition-all active:scale-95 border border-slate-700"
                  title="Export test suite as .json file"
                >
                  <FileText className="w-3.5 h-3.5 text-amber-400" />
                  <span>Save .json</span>
                </button>

                <button
                  onClick={() => setShowBookmarksOnly(prev => !prev)}
                  className={`p-2 rounded-lg border transition-all ${
                    showBookmarksOnly
                      ? 'bg-amber-950 border-amber-500 text-amber-400'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                  title={showBookmarksOnly ? 'Show all' : 'Show starred only'}
                >
                  <Star className={`w-3.5 h-3.5 ${showBookmarksOnly ? 'fill-current' : ''}`} />
                </button>
              </div>
            </div>

            {/* Category Filter Pills */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono-code pt-1">
              <span className="text-[10px] text-slate-500 uppercase font-bold mr-1">Class:</span>
              {[
                { id: 'all', label: 'All Classes' },
                { id: 'xss', label: 'XSS & HTML' },
                { id: 'sqli', label: 'SQL Injection' },
                { id: 'ssrf', label: 'SSRF & Egress' },
                { id: 'cors', label: 'CORS & Origin' },
                { id: 'headers', label: 'CRLF & Headers' }
              ].map(c => (
                <button
                  key={c.id}
                  onClick={() => setBrowserCategory(c.id)}
                  className={`px-2.5 py-1 rounded-md text-[11px] transition-all font-semibold ${
                    browserCategory === c.id
                      ? 'bg-amber-500 text-slate-950 shadow-sm'
                      : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </div>

          {/* Results Count & Status */}
          <div className="flex items-center justify-between text-xs font-mono-code px-1 text-slate-400">
            <span>Showing {filteredBrowserPresets.length} of {allPresets.length} payloads & test vectors</span>
            {showBookmarksOnly && (
              <span className="text-amber-400 font-bold">Filtered by bookmarked favorites</span>
            )}
          </div>

          {/* Browser List Grid with Inline Benchmarking */}
          {filteredBrowserPresets.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs font-mono-code text-slate-500">
              No matching test vectors found. Try clearing your search or category filters.
            </div>
          ) : (
            <div className="space-y-2.5">
              {filteredBrowserPresets.map(preset => {
                const isBookmarked = bookmarks.includes(preset.id);
                const isBenchmarking = benchmarkingId === preset.id;
                const bench = benchmarkResults[preset.id];

                return (
                  <div
                    key={preset.id}
                    className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all space-y-2.5 text-xs font-mono-code"
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-bold text-white text-xs">{preset.name}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 font-bold border border-slate-700">
                            {preset.categoryLabel}
                          </span>
                          {preset.isCustom && (
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 font-bold border border-emerald-800">
                              CUSTOM
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
                          {preset.description}
                        </p>
                      </div>

                      {/* Bookmark Button */}
                      <button
                        onClick={() => toggleBookmark(preset.id)}
                        className={`p-1.5 rounded-lg border transition-all ${
                          isBookmarked 
                            ? 'bg-amber-950/80 border-amber-600 text-amber-400' 
                            : 'bg-slate-950 border-slate-800 text-slate-500 hover:text-slate-300'
                        }`}
                        title={isBookmarked ? 'Remove bookmark' : 'Bookmark this payload'}
                      >
                        <Star className={`w-4 h-4 ${isBookmarked ? 'fill-current' : ''}`} />
                      </button>
                    </div>

                    {/* Raw String with Benchmark, Copy & Encode Actions */}
                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2">
                      <code className="text-amber-300 text-[11px] truncate flex-1 font-mono-code">
                        {preset.rawInput}
                      </code>

                      <div className="flex items-center gap-1.5 shrink-0">
                        {/* Benchmark Button */}
                        <button
                          onClick={() => handleRunBenchmark(preset)}
                          disabled={isBenchmarking}
                          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-850 text-cyan-400 border border-cyan-500/30 text-[10px] font-bold flex items-center gap-1 transition-all disabled:opacity-50"
                          title="Run 3-round latency benchmark against test lab"
                        >
                          {isBenchmarking ? (
                            <RefreshCw className="w-3 h-3 animate-spin" />
                          ) : (
                            <Gauge className="w-3 h-3 text-cyan-400" />
                          )}
                          <span>{isBenchmarking ? 'Testing...' : 'Benchmark'}</span>
                        </button>

                        {/* Copy Button */}
                        <button
                          onClick={() => handleCopy(preset.rawInput, `browser-${preset.id}`)}
                          className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-[10px] flex items-center gap-1 transition-all"
                          title="Copy payload to clipboard"
                        >
                          {copiedKey === `browser-${preset.id}` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                          <span>{copiedKey === `browser-${preset.id}` ? 'Copied' : 'Copy'}</span>
                        </button>

                        {/* Encode Button */}
                        <button
                          onClick={() => {
                            setCustomInput(preset.rawInput);
                            setSelectedCategory(preset.category);
                            setActiveSubTab('matrix');
                          }}
                          className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white text-[10px] flex items-center gap-1 transition-all"
                          title="Open in Encoder Matrix"
                        >
                          <Code2 className="w-3 h-3" />
                          <span>Encode</span>
                        </button>
                      </div>
                    </div>

                    {/* Inline Benchmark Results Badge */}
                    {bench && (
                      <div className="p-2 rounded bg-slate-950/80 border border-cyan-500/40 flex items-center justify-between text-[11px] font-mono-code text-slate-300">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-white flex items-center gap-1">
                            <Gauge className="w-3.5 h-3.5 text-cyan-400" />
                            {bench.avgLatency}ms
                          </span>
                          <span className="text-slate-500 text-[10px]">({bench.minLatency}-{bench.maxLatency}ms)</span>
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-slate-800 text-emerald-400">
                            HTTP {bench.statusCode}
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-slate-500">{bench.contentLength} B</span>
                          <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
                            bench.filterStatus.startsWith('Reflected') ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                            bench.filterStatus.startsWith('Blocked') ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {bench.filterStatus}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUBTAB 2: SANITIZATION & ENCODER MATRIX                                  */}
      {/* ========================================================================= */}
      {activeSubTab === 'matrix' && (
        <div className="space-y-4">
          {/* Category Selector */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <span className="text-xs font-bold text-white font-mono-code uppercase block">
              1. Select Vulnerability Class for Input Validation Testing
            </span>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono-code">
              {[
                { id: 'xss' as const, label: 'XSS & HTML Injection', desc: 'Tag & quote escaping' },
                { id: 'sqli' as const, label: 'SQL Injection', desc: 'String boundary parameters' },
                { id: 'ssrf' as const, label: 'SSRF & Egress', desc: 'IP & CIDR filters' },
                { id: 'cors' as const, label: 'CORS & Origin', desc: 'Origin validation' }
              ].map(cat => (
                <button
                  key={cat.id}
                  onClick={() => {
                    setSelectedCategory(cat.id);
                    const preset = allPresets.find(p => p.category === cat.id);
                    if (preset) setCustomInput(preset.rawInput);
                  }}
                  className={`p-2.5 rounded-lg border text-left transition-all ${
                    selectedCategory === cat.id
                      ? 'bg-slate-850 border-cyan-500 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <div className="font-bold text-[11px] text-cyan-400">{cat.label}</div>
                  <div className="text-[9px] text-slate-500 mt-0.5">{cat.desc}</div>
                </button>
              ))}
            </div>

            {/* Custom Input Field */}
            <div className="space-y-1 pt-2">
              <label className="text-[11px] text-slate-400 font-mono-code flex items-center justify-between">
                <span>Input Test String:</span>
                <span className="text-[10px] text-slate-500">{customInput.length} chars</span>
              </label>
              <textarea
                value={customInput}
                onChange={e => setCustomInput(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs font-mono-code focus:outline-none focus:border-cyan-500"
                placeholder="Enter test string to generate encoding transforms..."
              />
            </div>
          </div>

          {/* Encoding Transforms Grid */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <span className="text-xs font-bold text-white font-mono-code uppercase block">
              2. Obfuscation & Encoding Transformations
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono-code">
              {[
                { title: 'Standard URL-Encoded', value: transformations.urlEncoded, key: 'url' },
                { title: 'Double URL-Encoded (%25)', value: transformations.doubleUrlEncoded, key: 'double_url' },
                { title: 'HTML Entity (Decimal)', value: transformations.htmlDecimal, key: 'html_dec' },
                { title: 'HTML Entity (Hex &#x..;)', value: transformations.htmlHex, key: 'html_hex' },
                { title: 'Base64 Encoded', value: transformations.base64, key: 'b64' },
                { title: 'Unicode Full-Width Mapping', value: transformations.fullWidth, key: 'unicode' }
              ].map(enc => (
                <div key={enc.key} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-slate-400 font-bold uppercase">{enc.title}</span>
                    <button
                      onClick={() => handleCopy(enc.value, enc.key)}
                      className="p-1 rounded bg-slate-900 text-slate-400 hover:text-white"
                      title="Copy string"
                    >
                      {copiedKey === enc.key ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <div className="text-[11px] text-cyan-300 font-mono-code break-all bg-slate-900/60 p-1.5 rounded max-h-16 overflow-y-auto">
                    {enc.value}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Defensive Remediation & Unit Test Snippet */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-bold text-white font-mono-code uppercase">
                3. Secure Remediation & Unit Test Blueprint
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono-code space-y-2">
              <div className="text-slate-300">
                <span className="text-emerald-400 font-bold">Defensive Pattern: </span>
                {activePreset.defensiveRemediation}
              </div>

              <div className="pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-slate-400 uppercase font-bold">Secure Code Implementation:</span>
                  <button
                    onClick={() => handleCopy(activePreset.codeSnippet, 'code')}
                    className="text-[10px] text-slate-400 hover:text-white flex items-center gap-1"
                  >
                    {copiedKey === 'code' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>Copy Code</span>
                  </button>
                </div>
                <pre className="p-2.5 rounded bg-slate-900 text-slate-200 text-[11px] font-mono-code overflow-x-auto border border-slate-800">
                  {activePreset.codeSnippet}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUBTAB 3: LOCAL FIXTURES                                                  */}
      {/* ========================================================================= */}
      {activeSubTab === 'fixtures' && (
        <div className="space-y-3">
          {lastResult && (
            <div className="p-3 rounded-xl bg-slate-900 border border-emerald-500/40 text-xs font-mono-code text-slate-200">
              <div className="flex items-center gap-2 text-emerald-400 font-bold mb-1">
                <CheckCircle className="w-4 h-4" /> Lab Dispatch Result
              </div>
              <p className="text-[11px] text-slate-300">{lastResult.message}</p>
            </div>
          )}

          <div className="space-y-2">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono-code">
              Available Lab Targets ({labEndpoints.length})
            </h3>

            {labEndpoints.map((item, idx) => (
              <div key={idx} className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-white font-mono-code text-xs">{item.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono-code font-bold ${
                        item.type === 'vulnerable'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      }`}>
                        {item.type.toUpperCase()}
                      </span>
                    </div>
                    <div className="mt-1 font-mono-code text-[11px] text-slate-400 break-all">
                      <code>{item.path}</code>
                    </div>
                  </div>

                  <button
                    onClick={() => handleTestEndpoint(item.path, item.scanType)}
                    disabled={runningTarget === item.path}
                    className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono-code text-xs flex items-center gap-1.5 transition-all shrink-0 active:scale-95 disabled:opacity-50"
                  >
                    {runningTarget === item.path ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Play className="w-3.5 h-3.5 fill-slate-950" />
                    )}
                    <span>Test</span>
                  </button>
                </div>

                <div className="p-2 rounded bg-slate-950 border border-slate-800/80 text-[10px] font-mono-code text-slate-400">
                  <span className="text-slate-500">Expected Outcome: </span>
                  <span className="text-slate-300">{item.expected}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL: ADD CUSTOM PAYLOAD TO FILE / WORDLIST LIBRARY                      */}
      {/* ========================================================================= */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-md p-4 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl space-y-3 font-mono-code text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="font-bold text-white text-sm flex items-center gap-1.5">
                <FilePlus className="w-4 h-4 text-emerald-400" />
                Add Payload to Library / File
              </span>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveCustomPayload} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[11px] text-slate-400">Payload Name / Identifier:</label>
                <input
                  type="text"
                  value={newPayloadName}
                  onChange={e => setNewPayloadName(e.target.value)}
                  placeholder="e.g. Polyglot Boundary Probe"
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs focus:outline-none focus:border-emerald-500"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] text-slate-400">Category / Class:</label>
                <select
                  value={newPayloadCategory}
                  onChange={e => setNewPayloadCategory(e.target.value as VulnerabilityCategory)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs focus:outline-none focus:border-emerald-500 cursor-pointer"
                >
                  <option value="xss">XSS & HTML Injection</option>
                  <option value="sqli">SQL Injection</option>
                  <option value="ssrf">SSRF & Egress</option>
                  <option value="cors">CORS & Origin</option>
                  <option value="headers">CRLF & Headers</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] text-slate-400">Raw Payload String:</label>
                <textarea
                  value={newPayloadInput}
                  onChange={e => setNewPayloadInput(e.target.value)}
                  placeholder="e.g. ' OR 1=1--"
                  rows={2}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs focus:outline-none focus:border-emerald-500"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] text-slate-400">Description / Test Intent:</label>
                <input
                  type="text"
                  value={newPayloadDesc}
                  onChange={e => setNewPayloadDesc(e.target.value)}
                  placeholder="e.g. Tests parameter boundary validation"
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-white text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-450 text-slate-950 font-bold transition-all shadow-sm"
                >
                  Save to Library
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. PAYLOAD HISTORY SIDEBAR (COLLAPSIBLE DRAWER)                           */}
      {/* ========================================================================= */}
      {isHistoryOpen && (
        <div className="fixed inset-y-0 right-0 z-50 w-full max-w-sm bg-slate-950 border-l border-slate-800 shadow-2xl p-4 flex flex-col font-mono-code text-xs animate-in slide-in-from-right duration-200">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-white text-sm">Payload Test History</span>
              <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 text-[10px]">
                {historyItems.length}
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              {historyItems.length > 0 && (
                <button
                  onClick={handleClearHistory}
                  className="p-1 rounded text-slate-500 hover:text-rose-400 transition-colors"
                  title="Clear history"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
              <button
                onClick={() => setIsHistoryOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto py-3 space-y-2">
            {historyItems.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                No payload tests executed yet. Click "Benchmark" on any payload to record live performance history.
              </div>
            ) : (
              historyItems.map(item => (
                <div
                  key={item.id}
                  className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 space-y-1.5 transition-all"
                >
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-cyan-400 font-bold">{item.name}</span>
                    <span className="text-slate-500">{item.timestamp}</span>
                  </div>

                  <div className="p-1.5 rounded bg-slate-950 text-amber-300 font-mono-code text-[11px] truncate">
                    {item.payload}
                  </div>

                  <div className="flex items-center justify-between text-[10px] pt-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white flex items-center gap-0.5">
                        <Gauge className="w-3 h-3 text-cyan-400" />
                        {item.latencyMs}ms
                      </span>
                      <span className="text-emerald-400 font-bold">HTTP {item.statusCode}</span>
                    </div>

                    <span className="text-slate-400">{item.filterStatus}</span>
                  </div>

                  <div className="flex items-center justify-end gap-1.5 pt-1 border-t border-slate-800/60">
                    <button
                      onClick={() => handleCopy(item.payload, `hist-${item.id}`)}
                      className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-white text-[10px] flex items-center gap-1"
                    >
                      {copiedKey === `hist-${item.id}` ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span>Copy</span>
                    </button>

                    <button
                      onClick={() => {
                        setCustomInput(item.payload);
                        setActiveSubTab('matrix');
                        setIsHistoryOpen(false);
                      }}
                      className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 text-cyan-400 text-[10px]"
                    >
                      Encode
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};

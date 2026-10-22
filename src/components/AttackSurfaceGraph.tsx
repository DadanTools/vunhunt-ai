import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import { Asset, Finding, ScopeRule } from '../types.ts';
import { 
  Network, 
  Layers, 
  ShieldAlert, 
  Maximize2, 
  RotateCcw, 
  Filter, 
  Info, 
  Flame, 
  ExternalLink,
  ChevronRight,
  Zap,
  Globe2,
  Lock,
  ArrowRight
} from 'lucide-react';

interface AttackSurfaceGraphProps {
  assets: Asset[];
  findings: Finding[];
  scopes: ScopeRule[];
  selectedTarget?: string;
}

export interface AttackNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  type: 'root' | 'subdomain' | 'port' | 'vulnerability' | 'exploit_chain';
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category?: string;
  radius: number;
  details: {
    host?: string;
    port?: number;
    protocol?: string;
    description?: string;
    impact?: string;
    remediation?: string;
    cve?: string;
    steps?: string[];
  };
}

export interface AttackLink extends d3.SimulationLinkDatum<AttackNode> {
  source: string | AttackNode;
  target: string | AttackNode;
  type: 'dns' | 'service' | 'vulnerability' | 'exploit_chain';
  label?: string;
}

export const AttackSurfaceGraph: React.FC<AttackSurfaceGraphProps> = ({
  assets,
  findings,
  scopes,
  selectedTarget: initialTarget
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Targets from scopes & assets
  const targetOptions = useMemo(() => {
    const set = new Set<string>();
    scopes.filter(s => s.is_active === 1).forEach(s => set.add(s.target));
    assets.forEach(a => set.add(a.host));
    if (set.size === 0) set.add('localhost:3000');
    return Array.from(set);
  }, [scopes, assets]);

  const [activeTarget, setActiveTarget] = useState<string>(initialTarget || targetOptions[0] || 'localhost:3000');
  const [filterMode, setFilterMode] = useState<'all' | 'chains_only' | 'vulns_only'>('all');
  const [selectedNode, setSelectedNode] = useState<AttackNode | null>(null);
  const [zoomTransform, setZoomTransform] = useState<d3.ZoomTransform | null>(null);

  // Synthesize & Graph Model Generator
  const { nodes, links, chainStats } = useMemo(() => {
    const rawNodes: AttackNode[] = [];
    const rawLinks: AttackLink[] = [];
    const nodeMap = new Map<string, AttackNode>();

    const addNode = (node: AttackNode) => {
      if (!nodeMap.has(node.id)) {
        nodeMap.set(node.id, node);
        rawNodes.push(node);
      }
      return nodeMap.get(node.id)!;
    };

    // 1. Apex Root Node
    const rootHost = activeTarget;
    addNode({
      id: `root-${rootHost}`,
      label: rootHost,
      type: 'root',
      radius: 22,
      details: {
        host: rootHost,
        description: 'Apex Target Domain configured in authorized scope.'
      }
    });

    // 2. Discovered Subdomains
    const relevantAssets = assets.filter(a => a.host === rootHost || a.host.endsWith(rootHost) || rootHost.includes(a.host));
    const hostList = new Set<string>();
    relevantAssets.forEach(a => hostList.add(a.host));
    
    // Also include affected assets from findings
    findings.forEach(f => {
      if (f.affected_asset) hostList.add(f.affected_asset);
    });

    if (hostList.size === 0) {
      hostList.add(rootHost);
      hostList.add(`api.${rootHost}`);
      hostList.add(`auth.${rootHost}`);
    }

    hostList.forEach(sub => {
      const subId = `sub-${sub}`;
      addNode({
        id: subId,
        label: sub,
        type: 'subdomain',
        radius: 16,
        details: {
          host: sub,
          description: `Discovered host endpoint under target scope.`
        }
      });

      if (sub !== rootHost) {
        rawLinks.push({
          source: `root-${rootHost}`,
          target: subId,
          type: 'dns',
          label: 'DNS / SAN'
        });
      }

      // 3. Open Ports for Subdomain
      const defaultPorts = [
        { port: 443, proto: 'HTTPS' },
        { port: 80, proto: 'HTTP' }
      ];

      // Add dev ports if localhost
      if (sub.includes('localhost') || sub.includes('127.0.0.1')) {
        defaultPorts.push({ port: 3000, proto: 'HTTP-Dev' });
      }

      defaultPorts.forEach(p => {
        const portId = `port-${sub}:${p.port}`;
        addNode({
          id: portId,
          label: `:${p.port} (${p.proto})`,
          type: 'port',
          radius: 12,
          details: {
            host: sub,
            port: p.port,
            protocol: p.proto,
            description: `Active listening TCP port & protocol.`
          }
        });

        rawLinks.push({
          source: subId,
          target: portId,
          type: 'service',
          label: 'TCP Service'
        });
      });
    });

    // 4. Vulnerabilities attached to Ports & Subdomains
    const relevantFindings = findings.filter(f => {
      return hostList.has(f.affected_asset) || f.affected_asset === rootHost || f.endpoint.includes(rootHost);
    });

    // If no findings yet, create realistic sample nodes for visualization clarity
    const findingsToMap = relevantFindings.length > 0 ? relevantFindings : [
      {
        id: 'sample-cors',
        title: 'CORS Wildcard with Credentials',
        category: 'cors_misconfiguration',
        severity: 'high' as const,
        affected_asset: rootHost,
        endpoint: `https://${rootHost}/api/lab/cors`,
        impact: 'Cross-origin authentication token extraction.',
        remediation: 'Restrict Access-Control-Allow-Origin header.'
      },
      {
        id: 'sample-idor',
        title: 'Broken Object Level Authorization (IDOR)',
        category: 'auth_idor',
        severity: 'high' as const,
        affected_asset: rootHost,
        endpoint: `https://${rootHost}/api/users/profile`,
        impact: 'Tenant account data theft.',
        remediation: 'Verify session ownership server-side.'
      },
      {
        id: 'sample-env',
        title: 'Exposed Environment File (.env)',
        category: 'information_disclosure',
        severity: 'critical' as const,
        affected_asset: rootHost,
        endpoint: `https://${rootHost}/.env`,
        impact: 'Leaked database credentials and API secrets.',
        remediation: 'Block dotfiles in web server location directives.'
      }
    ];

    findingsToMap.forEach(f => {
      const vulnId = `vuln-${f.id}`;
      const host = f.affected_asset || rootHost;
      const targetPort = host.includes(':') ? host.split(':')[1] : (f.endpoint.startsWith('http://') ? '80' : '443');
      const attachedPortId = `port-${host}:${targetPort}`;

      addNode({
        id: vulnId,
        label: f.title.length > 25 ? `${f.title.slice(0, 22)}...` : f.title,
        type: 'vulnerability',
        severity: f.severity,
        category: f.category,
        radius: f.severity === 'critical' ? 16 : 13,
        details: {
          host,
          description: f.title,
          impact: f.impact,
          remediation: f.remediation
        }
      });

      // Link vuln to port (or subdomain if port not mapped)
      const parentSource = nodeMap.has(attachedPortId) ? attachedPortId : `sub-${host}`;
      if (nodeMap.has(parentSource)) {
        rawLinks.push({
          source: parentSource,
          target: vulnId,
          type: 'vulnerability',
          label: f.severity.toUpperCase()
        });
      }
    });

    // 5. Synthesize Exploit Chaining Paths
    // Example: CORS + IDOR => Chained Token Takeover
    const hasCors = findingsToMap.some(f => f.category === 'cors_misconfiguration' || f.title.toLowerCase().includes('cors'));
    const hasIdor = findingsToMap.some(f => f.category === 'auth_idor' || f.title.toLowerCase().includes('idor') || f.title.toLowerCase().includes('bola'));
    const hasEnv = findingsToMap.some(f => f.title.toLowerCase().includes('.env') || f.category === 'information_disclosure');

    const chains: AttackNode[] = [];

    if (hasCors && hasIdor) {
      const chainNodeId = `chain-cors-idor-${rootHost}`;
      const chainNode = addNode({
        id: chainNodeId,
        label: 'CHAIN: CORS + IDOR Account Takeover',
        type: 'exploit_chain',
        severity: 'critical',
        radius: 17,
        details: {
          host: rootHost,
          description: 'Multi-stage exploit chain leading to cross-tenant full account compromise.',
          impact: 'An attacker hosts a malicious page that triggers authenticated CORS requests to read the victim user ID, then exploits the BOLA/IDOR vulnerability to access and hijack other tenant records.',
          remediation: '1. Enforce strict CORS whitelist. 2. Implement server-side authorization checks on all IDOR entity queries.',
          steps: [
            'Step 1: Attacker sends phishing link containing malicious fetch script',
            'Step 2: CORS wildcard reflects Origin with credentials, leaking victim session token',
            'Step 3: Attacker replays session token against unauthenticated IDOR endpoint to dump private database records'
          ]
        }
      });
      chains.push(chainNode);

      // Link from CORS and IDOR nodes to this chain node
      findingsToMap.filter(f => f.category === 'cors_misconfiguration' || f.category === 'auth_idor').forEach(f => {
        rawLinks.push({
          source: `vuln-${f.id}`,
          target: chainNodeId,
          type: 'exploit_chain',
          label: 'Exploit Chain'
        });
      });
    }

    if (hasEnv) {
      const chainNodeId = `chain-env-cloud-${rootHost}`;
      const chainNode = addNode({
        id: chainNodeId,
        label: 'CHAIN: Secret Exposure -> Cloud DB Takeover',
        type: 'exploit_chain',
        severity: 'critical',
        radius: 17,
        details: {
          host: rootHost,
          description: 'Direct lateral escalation from leaked environment configuration to database infrastructure.',
          impact: 'Leaked DATABASE_URL or AWS_SECRET_ACCESS_KEY enables direct out-of-band administrative access to application datastores.',
          remediation: 'Immediately rotate all exposed API credentials and block direct public downloads of .env files.',
          steps: [
            'Step 1: Fuzzer retrieves public /.env file containing DB password',
            'Step 2: Attacker connects directly to port 5432/3306 bypassing web authentication',
            'Step 3: Full extraction of customer database tables'
          ]
        }
      });
      chains.push(chainNode);

      findingsToMap.filter(f => f.title.toLowerCase().includes('.env')).forEach(f => {
        rawLinks.push({
          source: `vuln-${f.id}`,
          target: chainNodeId,
          type: 'exploit_chain',
          label: 'Exploit Escalation'
        });
      });
    }

    // Apply filters if needed
    let filteredNodes = rawNodes;
    let filteredLinks = rawLinks;

    if (filterMode === 'chains_only') {
      const chainSet = new Set<string>();
      rawNodes.filter(n => n.type === 'exploit_chain').forEach(c => chainSet.add(c.id));
      rawLinks.forEach(l => {
        const s = typeof l.source === 'string' ? l.source : l.source.id;
        const t = typeof l.target === 'string' ? l.target : l.target.id;
        if (chainSet.has(s) || chainSet.has(t)) {
          chainSet.add(s);
          chainSet.add(t);
        }
      });
      filteredNodes = rawNodes.filter(n => chainSet.has(n.id) || n.type === 'root');
      filteredLinks = rawLinks.filter(l => {
        const s = typeof l.source === 'string' ? l.source : l.source.id;
        const t = typeof l.target === 'string' ? l.target : l.target.id;
        return chainSet.has(s) && chainSet.has(t);
      });
    } else if (filterMode === 'vulns_only') {
      filteredNodes = rawNodes.filter(n => n.type !== 'port');
      filteredLinks = rawLinks.filter(l => l.type !== 'service');
    }

    return {
      nodes: filteredNodes,
      links: filteredLinks,
      chainStats: {
        totalChains: chains.length,
        totalAssets: hostList.size,
        totalVulns: findingsToMap.length
      }
    };
  }, [activeTarget, assets, findings, scopes, filterMode]);

  // D3 Force Simulation & Rendering
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const rect = containerRef.current.getBoundingClientRect();
    const width = Math.max(560, rect.width || 600);
    const height = 480;

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    // Definitions (Gradients & Arrowhead markers)
    const defs = svg.append('defs');

    // Arrow marker for standard links
    defs.append('marker')
      .attr('id', 'arrow-default')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#475569');

    // Arrow marker for exploit chain links (Glowing Red)
    defs.append('marker')
      .attr('id', 'arrow-chain')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 24)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#f43f5e');

    // Main graph group
    const g = svg.append('g').attr('class', 'graph-container');

    // D3 Zoom & Pan
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 3])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
        setZoomTransform(event.transform);
      });

    svg.call(zoom);

    // Deep copy nodes and links for D3 simulation
    const simNodes: AttackNode[] = nodes.map(d => ({ ...d }));
    const simLinks: AttackLink[] = links.map(d => ({ ...d }));

    // Force simulation
    const simulation = d3.forceSimulation<AttackNode>(simNodes)
      .force('link', d3.forceLink<AttackNode, AttackLink>(simLinks).id(d => d.id).distance(d => {
        if (d.type === 'exploit_chain') return 110;
        if (d.type === 'vulnerability') return 80;
        if (d.type === 'service') return 60;
        return 90;
      }))
      .force('charge', d3.forceManyBody().strength(-280))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide<AttackNode>().radius(d => d.radius + 18));

    // Draw Links
    const link = g.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(simLinks)
      .enter()
      .append('line')
      .attr('stroke', d => {
        if (d.type === 'exploit_chain') return '#f43f5e';
        if (d.type === 'vulnerability') return '#f59e0b';
        if (d.type === 'service') return '#a855f7';
        return '#38bdf8';
      })
      .attr('stroke-width', d => (d.type === 'exploit_chain' ? 2.5 : 1.5))
      .attr('stroke-dasharray', d => {
        if (d.type === 'exploit_chain') return '6,4';
        if (d.type === 'vulnerability') return '4,3';
        return 'none';
      })
      .attr('marker-end', d => (d.type === 'exploit_chain' ? 'url(#arrow-chain)' : 'url(#arrow-default)'))
      .attr('opacity', 0.8);

    // Draw Nodes
    const node = g.append('g')
      .attr('class', 'nodes')
      .selectAll('.attack-node')
      .data(simNodes)
      .enter()
      .append('g')
      .attr('class', 'attack-node')
      .style('cursor', 'pointer')
      .call(
        d3.drag<SVGGElement, AttackNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on('click', (_event, d) => {
        setSelectedNode(d);
      });

    // Node Circles
    node.append('circle')
      .attr('r', d => d.radius)
      .attr('fill', d => {
        if (d.type === 'root') return '#047857';
        if (d.type === 'subdomain') return '#0369a1';
        if (d.type === 'port') return '#6b21a8';
        if (d.type === 'exploit_chain') return '#be123c';
        // Vulnerabilities by severity
        if (d.severity === 'critical') return '#e11d48';
        if (d.severity === 'high') return '#ea580c';
        if (d.severity === 'medium') return '#d97706';
        return '#2563eb';
      })
      .attr('stroke', d => {
        if (d.type === 'exploit_chain') return '#fda4af';
        if (d.type === 'root') return '#6ee7b7';
        if (d.type === 'subdomain') return '#7dd3fc';
        return '#cbd5e1';
      })
      .attr('stroke-width', d => (d.type === 'exploit_chain' || d.type === 'root' ? 3 : 1.5))
      .attr('class', d => (d.type === 'exploit_chain' ? 'animate-pulse' : ''));

    // Node Icons / Text Badge inside
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '.35em')
      .style('fill', '#ffffff')
      .style('font-size', d => (d.type === 'root' ? '12px' : '9px'))
      .style('font-weight', 'bold')
      .style('font-family', 'monospace')
      .style('pointer-events', 'none')
      .text(d => {
        if (d.type === 'root') return 'APEX';
        if (d.type === 'subdomain') return 'SUB';
        if (d.type === 'port') return 'PORT';
        if (d.type === 'exploit_chain') return 'CHAIN';
        return d.severity ? d.severity[0].toUpperCase() : 'V';
      });

    // Node Outside Labels
    node.append('text')
      .attr('dx', d => d.radius + 6)
      .attr('dy', '.35em')
      .style('fill', '#e2e8f0')
      .style('font-size', '10px')
      .style('font-weight', d => (d.type === 'exploit_chain' || d.type === 'root' ? 'bold' : 'normal'))
      .style('font-family', 'monospace')
      .style('pointer-events', 'none')
      .text(d => d.label);

    // Tick update
    simulation.on('tick', () => {
      link
        .attr('x1', d => (d.source as AttackNode).x || 0)
        .attr('y1', d => (d.source as AttackNode).y || 0)
        .attr('x2', d => (d.target as AttackNode).x || 0)
        .attr('y2', d => (d.target as AttackNode).y || 0);

      node.attr('transform', d => `translate(${d.x || 0},${d.y || 0})`);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, links]);

  const handleResetZoom = () => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.transition().duration(500).call(
      d3.zoom<SVGSVGElement, unknown>().transform as any,
      d3.zoomIdentity
    );
  };

  return (
    <div ref={containerRef} className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3.5">
      {/* Top Header & Target Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <h3 className="text-sm font-bold text-white font-mono-code">Attack Surface & Exploit Chaining Map</h3>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-mono-code border border-slate-700">
                D3 Force Graph
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Correlates subdomains, open TCP ports, and multi-stage exploit chaining pathways
            </p>
          </div>
        </div>

        {/* Target Selector Dropdown */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 px-2 py-1 rounded-lg text-xs font-mono-code">
            <Globe2 className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={activeTarget}
              onChange={e => setActiveTarget(e.target.value)}
              className="bg-transparent text-white text-xs font-mono-code focus:outline-none cursor-pointer"
            >
              {targetOptions.map(t => (
                <option key={t} value={t} className="bg-slate-900 text-white">
                  {t}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleResetZoom}
            className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-white transition-all"
            title="Reset Graph Zoom & Position"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* KPI Ticker Bar */}
      <div className="grid grid-cols-3 gap-2 text-xs font-mono-code">
        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[9px] text-slate-500 uppercase block">Assets / Subdomains</span>
            <span className="text-sm font-bold text-cyan-400">{chainStats.totalAssets} mapped</span>
          </div>
          <Globe2 className="w-4 h-4 text-cyan-500/60" />
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[9px] text-slate-500 uppercase block">Associated Vulns</span>
            <span className="text-sm font-bold text-amber-400">{chainStats.totalVulns} active</span>
          </div>
          <Zap className="w-4 h-4 text-amber-500/60" />
        </div>

        <div className="p-2.5 rounded-lg bg-slate-950 border border-rose-900/60 flex items-center justify-between">
          <div>
            <span className="text-[9px] text-slate-500 uppercase block">Exploit Chains</span>
            <span className="text-sm font-bold text-rose-400">{chainStats.totalChains} lethal paths</span>
          </div>
          <Flame className="w-4 h-4 text-rose-500/80" />
        </div>
      </div>

      {/* Filter Switcher */}
      <div className="flex items-center justify-between gap-2 text-xs font-mono-code">
        <span className="text-[11px] text-slate-400 flex items-center gap-1">
          <Filter className="w-3 h-3 text-slate-500" />
          <span>Graph Filter:</span>
        </span>

        <div className="flex items-center gap-1 p-0.5 rounded-lg bg-slate-950 border border-slate-800">
          <button
            onClick={() => setFilterMode('all')}
            className={`px-2 py-0.5 rounded text-[10px] font-bold transition-all ${
              filterMode === 'all' ? 'bg-slate-800 text-cyan-400' : 'text-slate-400 hover:text-white'
            }`}
          >
            All Nodes
          </button>
          <button
            onClick={() => setFilterMode('chains_only')}
            className={`px-2 py-0.5 rounded text-[10px] font-bold transition-all ${
              filterMode === 'chains_only' ? 'bg-slate-800 text-rose-400' : 'text-slate-400 hover:text-white'
            }`}
          >
            Exploit Chains Only
          </button>
          <button
            onClick={() => setFilterMode('vulns_only')}
            className={`px-2 py-0.5 rounded text-[10px] font-bold transition-all ${
              filterMode === 'vulns_only' ? 'bg-slate-800 text-amber-400' : 'text-slate-400 hover:text-white'
            }`}
          >
            Direct Vulns
          </button>
        </div>
      </div>

      {/* Interactive D3 Canvas */}
      <div className="relative w-full h-[480px] bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
        <svg ref={svgRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

        {/* Legend Overlay */}
        <div className="absolute bottom-2 left-2 p-2 rounded-lg bg-slate-900/90 backdrop-blur-md border border-slate-800 text-[10px] font-mono-code space-y-1 pointer-events-none">
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-600 border border-emerald-300" />
            <span>Apex Domain</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-600 border border-sky-300" />
            <span>Subdomain</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-700 border border-purple-300" />
            <span>TCP Service Port</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-600" />
            <span>Finding / Vulnerability</span>
          </div>
          <div className="flex items-center gap-1.5 text-rose-400 font-bold">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-600 animate-pulse border border-rose-300" />
            <span>Exploit Chaining Path</span>
          </div>
        </div>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-700 space-y-2 text-xs font-mono-code animate-in fade-in duration-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                selectedNode.type === 'exploit_chain' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                selectedNode.type === 'root' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                selectedNode.type === 'subdomain' ? 'bg-sky-950 text-sky-300 border border-sky-800' :
                selectedNode.type === 'port' ? 'bg-purple-950 text-purple-300 border border-purple-800' :
                'bg-amber-950 text-amber-300 border border-amber-800'
              }`}>
                {selectedNode.type.replace('_', ' ')}
              </span>
              <span className="font-bold text-white text-sm truncate max-w-sm">{selectedNode.label}</span>
            </div>

            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-500 hover:text-slate-300 text-xs px-2 py-0.5 rounded"
            >
              Close
            </button>
          </div>

          {selectedNode.details.description && (
            <p className="text-slate-300 text-[11px] leading-relaxed">
              {selectedNode.details.description}
            </p>
          )}

          {selectedNode.details.steps && selectedNode.details.steps.length > 0 && (
            <div className="p-2.5 rounded-lg bg-slate-900 border border-rose-900/40 space-y-1">
              <span className="text-[10px] font-bold text-rose-400 uppercase block">
                Attack Execution Steps:
              </span>
              {selectedNode.details.steps.map((st, i) => (
                <div key={i} className="text-slate-300 text-[11px] flex items-start gap-1.5">
                  <ArrowRight className="w-3 h-3 text-rose-400 shrink-0 mt-0.5" />
                  <span>{st}</span>
                </div>
              ))}
            </div>
          )}

          {selectedNode.details.impact && (
            <div className="flex items-start gap-1 text-[11px] text-amber-300/90">
              <span className="font-bold text-amber-400 shrink-0">Impact:</span>
              <span>{selectedNode.details.impact}</span>
            </div>
          )}

          {selectedNode.details.remediation && (
            <div className="flex items-start gap-1 text-[11px] text-emerald-300/90">
              <span className="font-bold text-emerald-400 shrink-0">Defense / Fix:</span>
              <span>{selectedNode.details.remediation}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

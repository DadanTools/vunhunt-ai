import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  Battery, 
  BatteryCharging, 
  Gauge, 
  Flame, 
  ShieldCheck, 
  Activity, 
  RefreshCw, 
  Zap, 
  Thermometer, 
  Server, 
  Sliders, 
  Check, 
  AlertTriangle,
  Smartphone,
  Copy
} from 'lucide-react';

export interface HardwareMetrics {
  cpuTempC: number;
  cpuTempF: number;
  tempStatus: 'optimal' | 'warm' | 'hot' | 'critical';
  memory: {
    rssMb: number;
    heapUsedMb: number;
    heapTotalMb: number;
    systemFreeMb: number;
    systemTotalMb: number;
    memoryUsagePercent: number;
  };
  battery: {
    percentage: number;
    health: string;
    status: 'CHARGING' | 'DISCHARGING' | 'FULL' | 'NOT_CHARGING';
    plugged: 'PLUGGED_AC' | 'PLUGGED_USB' | 'UNPLUGGED';
    temperatureC: number;
  };
  system: {
    loadAvg: number[];
    activeScansCount: number;
    cpuCores: number;
    uptimeSeconds: number;
    governorMode: 'performance' | 'eco_saver' | 'throttled';
    wakeLockActive: boolean;
  };
}

export const ResourceMonitor: React.FC = () => {
  const [metrics, setMetrics] = useState<HardwareMetrics | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [governorUpdating, setGovernorUpdating] = useState(false);

  const fetchMetrics = async () => {
    try {
      const res = await fetch('/api/termux/hardware-metrics');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch {
      // Ignore network errors in polling
    }
  };

  useEffect(() => {
    fetchMetrics();
    if (!autoRefresh) return;
    const interval = setInterval(fetchMetrics, 2500);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const setGovernorMode = async (mode: 'performance' | 'eco_saver') => {
    setGovernorUpdating(true);
    try {
      const res = await fetch('/api/termux/governor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
      if (res.ok) {
        await fetchMetrics();
      }
    } catch {} finally {
      setGovernorUpdating(false);
    }
  };

  const toggleWakeLock = async () => {
    if (!metrics) return;
    setGovernorUpdating(true);
    try {
      await fetch('/api/termux/governor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ wakeLock: !metrics.system.wakeLockActive })
      });
      await fetchMetrics();
    } catch {} finally {
      setGovernorUpdating(false);
    }
  };

  if (!metrics) {
    return (
      <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center font-mono-code text-xs text-slate-400 space-y-2">
        <RefreshCw className="w-5 h-5 text-emerald-400 animate-spin mx-auto" />
        <p>Connecting to Termux hardware sensors...</p>
      </div>
    );
  }

  // Thermal color logic
  const isOptimal = metrics.tempStatus === 'optimal';
  const isWarm = metrics.tempStatus === 'warm';
  const isHot = metrics.tempStatus === 'hot';
  const isCritical = metrics.tempStatus === 'critical';

  const tempBadgeColor = isCritical ? 'bg-rose-950 text-rose-400 border-rose-700 animate-pulse' :
    isHot ? 'bg-orange-950 text-orange-400 border-orange-700' :
    isWarm ? 'bg-amber-950 text-amber-400 border-amber-700' :
    'bg-emerald-950 text-emerald-400 border-emerald-800';

  const isCharging = metrics.battery.status === 'CHARGING' || metrics.battery.status === 'FULL';

  return (
    <div className="space-y-3.5 font-mono-code text-xs">
      {/* Top Telemetry Header & Controls */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <Activity className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h3 className="text-sm font-bold text-white">Termux Hardware Resource Monitor</h3>
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold border ${tempBadgeColor}`}>
                  {metrics.tempStatus.toUpperCase()}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Live CPU thermal telemetry, RAM footprint, and battery governance</p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto">
            {/* Auto Refresh Toggle */}
            <button
              onClick={() => setAutoRefresh(prev => !prev)}
              className={`px-2.5 py-1 rounded-lg border text-xs font-bold flex items-center gap-1.5 transition-all ${
                autoRefresh
                  ? 'bg-slate-950 border-emerald-500/50 text-emerald-400'
                  : 'bg-slate-950 border-slate-800 text-slate-400'
              }`}
            >
              <RefreshCw className={`w-3 h-3 ${autoRefresh ? 'animate-spin' : ''}`} style={{ animationDuration: '3s' }} />
              <span>{autoRefresh ? 'Live (2.5s)' : 'Paused'}</span>
            </button>

            <button
              onClick={() => fetchMetrics()}
              className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-white"
              title="Refresh telemetry"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Governor Warning if Throttled */}
        {metrics.system.governorMode === 'throttled' && (
          <div className="p-2.5 rounded-lg bg-rose-950/80 border border-rose-600 text-rose-200 flex items-center gap-2 text-[11px] animate-pulse">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>
              <strong>Thermal Safety Throttle Active:</strong> CPU temperature is elevated ({metrics.cpuTempC}°C) or battery low. Scan request delays automatically increased to safeguard phone hardware.
            </span>
          </div>
        )}
      </div>

      {/* 4 Main Hardware Gauges Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
        {/* 1. CPU TEMPERATURE */}
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1 text-[11px] uppercase">
              <Thermometer className="w-3.5 h-3.5 text-rose-400" />
              <span>CPU Temp</span>
            </span>
            <span className="text-[10px] text-slate-500">{metrics.system.cpuCores} Cores</span>
          </div>

          <div className="flex items-baseline gap-2">
            <span className={`text-2xl font-black ${
              isCritical ? 'text-rose-400' : isHot ? 'text-orange-400' : isWarm ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {metrics.cpuTempC}&deg;C
            </span>
            <span className="text-slate-500 text-xs font-semibold">({metrics.cpuTempF}&deg;F)</span>
          </div>

          {/* Temperature Progress Gauge */}
          <div className="space-y-1">
            <div className="h-1.5 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800">
              <div 
                className={`h-full transition-all duration-500 ${
                  isCritical ? 'bg-rose-500' : isHot ? 'bg-orange-500' : isWarm ? 'bg-amber-400' : 'bg-emerald-400'
                }`}
                style={{ width: `${Math.min(100, Math.max(10, ((metrics.cpuTempC - 25) / 60) * 100))}%` }}
              />
            </div>
            <div className="flex justify-between text-[9px] text-slate-500">
              <span>Cool (30&deg;)</span>
              <span>Throttle (75&deg;)</span>
            </div>
          </div>
        </div>

        {/* 2. MEMORY (RAM) ENGINE FOOTPRINT */}
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1 text-[11px] uppercase">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Engine RAM</span>
            </span>
            <span className="text-[10px] text-emerald-400 font-bold">Ultra-light</span>
          </div>

          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-black text-cyan-400">{metrics.memory.rssMb}</span>
            <span className="text-xs text-slate-400">MB RSS</span>
          </div>

          {/* Memory Bar */}
          <div className="space-y-1">
            <div className="h-1.5 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800">
              <div 
                className="h-full bg-cyan-400 transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(5, (metrics.memory.rssMb / 250) * 100))}%` }}
              />
            </div>
            <div className="flex justify-between text-[9px] text-slate-500">
              <span>Heap: {metrics.memory.heapUsedMb} MB</span>
              <span>Sys Free: {metrics.memory.systemFreeMb} MB</span>
            </div>
          </div>
        </div>

        {/* 3. ANDROID BATTERY STATUS */}
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1 text-[11px] uppercase">
              {isCharging ? (
                <BatteryCharging className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Battery className="w-3.5 h-3.5 text-amber-400" />
              )}
              <span>Battery State</span>
            </span>
            <span className={`text-[10px] font-bold ${isCharging ? 'text-emerald-400' : 'text-amber-400'}`}>
              {metrics.battery.status}
            </span>
          </div>

          <div className="flex items-baseline gap-1.5">
            <span className={`text-2xl font-black ${
              metrics.battery.percentage <= 20 ? 'text-rose-400' :
              metrics.battery.percentage <= 40 ? 'text-amber-400' :
              'text-white'
            }`}>
              {metrics.battery.percentage}%
            </span>
            <span className="text-xs text-slate-500">({metrics.battery.plugged})</span>
          </div>

          {/* Battery Bar */}
          <div className="space-y-1">
            <div className="h-1.5 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800">
              <div 
                className={`h-full transition-all duration-500 ${
                  metrics.battery.percentage <= 20 ? 'bg-rose-500' :
                  metrics.battery.percentage <= 40 ? 'bg-amber-400' :
                  'bg-emerald-400'
                }`}
                style={{ width: `${metrics.battery.percentage}%` }}
              />
            </div>
            <div className="flex justify-between text-[9px] text-slate-500">
              <span>Health: {metrics.battery.health}</span>
              <span>Bat: {metrics.battery.temperatureC}&deg;C</span>
            </div>
          </div>
        </div>

        {/* 4. CONCURRENCY & WAKELOCK */}
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1 text-[11px] uppercase">
              <Gauge className="w-3.5 h-3.5 text-purple-400" />
              <span>Concurrency</span>
            </span>
            <span className="text-[10px] text-slate-500">Load: {metrics.system.loadAvg[0].toFixed(2)}</span>
          </div>

          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-black text-purple-400">{metrics.system.activeScansCount}</span>
            <span className="text-xs text-slate-400">active scan job{metrics.system.activeScansCount === 1 ? '' : 's'}</span>
          </div>

          <div className="flex items-center justify-between pt-1 text-[10px]">
            <span className="text-slate-500">Wake-Lock:</span>
            <button
              onClick={toggleWakeLock}
              disabled={governorUpdating}
              className={`px-1.5 py-0.5 rounded font-bold transition-all ${
                metrics.system.wakeLockActive
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : 'bg-slate-800 text-slate-400'
              }`}
            >
              {metrics.system.wakeLockActive ? 'ENGAGED' : 'OFF'}
            </button>
          </div>
        </div>
      </div>

      {/* Thermal & Concurrency Governor Mode Selector */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-bold text-white uppercase">Thermal Concurrency Governor</span>
          </div>
          <span className="text-[10px] text-slate-500">Protects Android phone battery & SoC from overheating</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {/* Performance Mode */}
          <button
            onClick={() => setGovernorMode('performance')}
            disabled={governorUpdating}
            className={`p-3 rounded-lg border text-left transition-all ${
              metrics.system.governorMode === 'performance'
                ? 'bg-slate-850 border-cyan-500 text-white shadow-sm'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-cyan-400 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5" />
                <span>Performance Mode (Standard)</span>
              </span>
              {metrics.system.governorMode === 'performance' && (
                <Check className="w-3.5 h-3.5 text-cyan-400" />
              )}
            </div>
            <p className="text-[11px] text-slate-400">
              Maximum scan throughput. Dispatches reconnaissance and route fuzzing with standard 80ms rate-limiting. Recommended when connected to a charger.
            </p>
          </button>

          {/* Eco / Battery Saver Mode */}
          <button
            onClick={() => setGovernorMode('eco_saver')}
            disabled={governorUpdating}
            className={`p-3 rounded-lg border text-left transition-all ${
              metrics.system.governorMode === 'eco_saver'
                ? 'bg-slate-850 border-emerald-500 text-white shadow-sm'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                <BatteryCharging className="w-3.5 h-3.5" />
                <span>Eco / Battery Saver Mode</span>
              </span>
              {metrics.system.governorMode === 'eco_saver' && (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              )}
            </div>
            <p className="text-[11px] text-slate-400">
              Polite throttle mode. Adds 250ms spacing between HTTP requests and limits parallel workers to 1, lowering phone temperature by ~8&deg;C and preserving battery.
            </p>
          </button>
        </div>

        {/* Android CLI Wake-Lock Instruction */}
        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 flex items-center justify-between gap-2 text-[11px]">
          <div className="flex items-center gap-2 text-slate-400 truncate">
            <Smartphone className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="truncate">CLI Wake-Lock Command: <code className="text-emerald-400">termux-wake-lock</code></span>
          </div>
          <button
            onClick={() => handleCopy('termux-wake-lock', 'wakelock_cmd')}
            className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-[10px] flex items-center gap-1 shrink-0"
          >
            {copiedKey === 'wakelock_cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copiedKey === 'wakelock_cmd' ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

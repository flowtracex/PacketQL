import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Search, ChevronRight, Play, Pause, X,
  Activity, Database, Globe, Terminal, ChevronDown, RefreshCcw,
  Zap, Layers, Plus, Trash2, Code,
  Clock, HardDrive, ShieldAlert, ShieldCheck, AlertTriangle,
  MapPin, ExternalLink, Info, CheckCircle2, TrendingUp,
  TrendingDown, ArrowUpRight, Target, Brain, Server
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, LineChart, Line, ComposedChart
} from 'recharts';
import {
  TIME_RANGES, QUERY_OPERATORS,
} from '../constants/config';
import { getLogSources, getFieldsForSource, getAllVisibleFields } from '../constants/fieldCatalogUtils';
import SchemaExplorer from '../components/common/SchemaExplorer';

// --- Types ---

type LogType = string;

interface LogEntry {
  id: string;
  timestamp: string;
  sourceIP: string;
  sourceAsset?: { hostname: string; owner: string; type: string; risk: number };
  destIP: string;
  destInfo?: { hostname: string; country: string; flag: string; reputation: string; malicious: boolean };
  type: LogType;
  protocol: string;
  port: number;
  message: string;
  bytes?: string;
  duration?: string;
  relatedDetection?: { id: string; title: string };
  threatIntel?: { malicious: boolean; sources: string[] };
}

interface QueryCondition {
  id: string;
  field: string;
  operator: string;
  value: string;
}



// --- Components ---

const LogsPage: React.FC<{
  defaultView?: 'search' | 'stats' | 'live';
  allowedViews?: Array<'search' | 'stats' | 'live'>;
  initialQuery?: string;
  onQueryConsumed?: () => void
}> = ({ defaultView = 'search', allowedViews, initialQuery, onQueryConsumed }) => {
  const allowed = useMemo(() => {
    const vals = (allowedViews && allowedViews.length > 0) ? allowedViews : ['search', 'stats', 'live'];
    return Array.from(new Set(vals));
  }, [allowedViews]);
  const [view, setView] = useState<'search' | 'stats' | 'live'>(
    (allowed.includes(defaultView) ? defaultView : allowed[0]) as 'search' | 'stats' | 'live'
  );
  const [selectedLog, setSelectedLog] = useState<any>(null);
  const [queryBuilderOpen, setQueryBuilderOpen] = useState(false);
  const [isLivePaused, setIsLivePaused] = useState(false);
  const [schemaOpen, setSchemaOpen] = useState(false);

  // Filter States
  const [timeRange, setTimeRange] = useState('Last 24h');
  const [activeSource, setActiveSource] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const searchTimeout = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  // Server-side search state
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searchTotal, setSearchTotal] = useState(0);
  const [searchPage, setSearchPage] = useState(1);
  const [searchPageCount, setSearchPageCount] = useState(1);
  const [searchLoading, setSearchLoading] = useState(false);
  const PAGE_SIZE = 15;

  // Query Builder State
  const [qbSource, setQbSource] = useState('');
  const [qbScope, setQbScope] = useState('Last 24h');
  const [queryConditions, setQueryConditions] = useState<QueryCondition[]>([
    { id: '1', field: '', operator: '==', value: '' }
  ]);
  // Active structured conditions sent to the API (set when QB "Run Search" is clicked)
  const [activeConditions, setActiveConditions] = useState<QueryCondition[]>([]);

  // Analytics State
  const [analyticsData, setAnalyticsData] = useState<any>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);

  // Live Logs State
  const [liveLogs, setLiveLogs] = useState<any[]>([]);
  const [liveLoading, setLiveLoading] = useState(false);
  const liveIntervalRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const [liveEventCount, setLiveEventCount] = useState(0);

  // Log mapping data
  const logSources = useMemo(() => getLogSources(), []);

  // Fields for selected query builder source
  const qbFields = useMemo(() => {
    if (!qbSource) {
      // Common fields across all Parquet sources
      return [
        { name: 'SrcIp', parquet: 'src_ip', type: 'string', ui_visible: true, group: 'most_used' as const },
        { name: 'DstIp', parquet: 'dst_ip', type: 'string', ui_visible: true, group: 'most_used' as const },
        { name: 'Protocol', parquet: 'protocol', type: 'string', ui_visible: true, group: 'most_used' as const },
        { name: 'Service', parquet: 'service', type: 'string', ui_visible: true, group: 'most_used' as const },
        { name: 'DstPort', parquet: 'dst_port', type: 'int32', ui_visible: true, group: 'most_used' as const },
        { name: 'SrcPort', parquet: 'src_port', type: 'int32', ui_visible: true, group: 'others' as const },
        { name: 'Direction', parquet: 'direction', type: 'string', ui_visible: true, group: 'others' as const },
        { name: 'EventType', parquet: 'event_type', type: 'string', ui_visible: true, group: 'others' as const },
        { name: 'FlowId', parquet: 'flow_id', type: 'string', ui_visible: true, group: 'others' as const },
      ];
    }
    return getAllVisibleFields(qbSource);
  }, [qbSource]);

  // Initialize default QB source only (search defaults to All)
  useEffect(() => {
    if (!allowed.includes(view)) {
      setView(allowed[0] as 'search' | 'stats' | 'live');
    }
  }, [allowed, view]);

  useEffect(() => {
    if (logSources.length > 0 && !qbSource) {
      setQbSource(logSources[0]);
    }
  }, [logSources]);

  // Handle initialQuery from deep-link (e.g. FTX ID from Evidence tab)
  useEffect(() => {
    if (initialQuery) {
      setSearchTerm(initialQuery);
      setDebouncedSearch(initialQuery);
      setView('search');
      onQueryConsumed?.();
    }
  }, [initialQuery]);

  // Debounce search term
  useEffect(() => {
    if (searchTimeout.current) clearTimeout(searchTimeout.current);
    searchTimeout.current = setTimeout(() => setDebouncedSearch(searchTerm), 400);
    return () => { if (searchTimeout.current) clearTimeout(searchTimeout.current); };
  }, [searchTerm]);

  // Reset page on filter change
  useEffect(() => {
    setSearchPage(1);
  }, [debouncedSearch, activeSource]);

  // SERVER-SIDE LOG SEARCH
  useEffect(() => {
    if (view !== 'search') return;
    let cancelled = false;
    const fetchLogs = async () => {
      setSearchLoading(true);
      const params = new URLSearchParams();
      if (activeSource) params.append('source', activeSource.toLowerCase());
      if (debouncedSearch) params.append('search', debouncedSearch);
      // ── Time filter (always bounded; avoid unbounded backend scans) ──
      const searchWindowMap: Record<string, string> = {
        'Last 1h': '1h',
        'Last 6h': '6h',
        'Last 24h': '24h',
        'Last 7d': '7d',
        'Last 30d': '30d',
      };
      params.append('window', searchWindowMap[timeRange] || '24h');
      // ── Structured QB conditions ─────────────────────────────────
      const validConditions = activeConditions.filter(c => c.field && c.value);
      if (validConditions.length > 0) {
        params.append('conditions', JSON.stringify(validConditions));
      }
      params.append('page', String(searchPage));
      params.append('limit', String(PAGE_SIZE));
      try {
        const res = await fetch(`/api/v1/logs/search?${params}`);
        const data = await res.json();
        if (!cancelled) {
          setSearchResults(data.logs || []);
          setSearchTotal(data.total || 0);
          setSearchPageCount(data.page_count || 1);
          setSearchLoading(false);
        }
      } catch {
        if (!cancelled) {
          setSearchResults([]);
          setSearchTotal(0);
          setSearchPageCount(1);
          setSearchLoading(false);
        }
      }
    };
    fetchLogs();
    return () => { cancelled = true; };
  }, [view, activeSource, debouncedSearch, searchPage, timeRange, activeConditions]);

  // Fetch analytics data — re-fetch when timeRange changes
  useEffect(() => {
    if (view === 'stats') {
      setAnalyticsLoading(true);
      // Map UI label to API window param
      const windowMap: Record<string, string> = {
        'Last 1h': '1h', 'Last 6h': '6h', 'Last 24h': '24h',
        'Last 7d': '7d', 'Last 30d': '30d',
      };
      const win = windowMap[timeRange] || '24h';
      fetch(`/api/v1/logs/analytics?window=${win}`)
        .then(res => res.json())
        .then(async data => {
          // If selected short window is empty, automatically show broader context.
          if (win === '24h' && Number(data?.total_events || 0) === 0) {
            try {
              const fb = await fetch('/api/v1/logs/analytics?window=30d');
              const fbData = await fb.json();
              if (Number(fbData?.total_events || 0) > 0) {
                fbData.window_requested = '24h';
                fbData.window_served = '30d';
                fbData.stale_fallback = true;
                setAnalyticsData(fbData);
                setAnalyticsLoading(false);
                return;
              }
            } catch (_) {
              // Keep original data if fallback fetch fails.
            }
          }
          setAnalyticsData(data);
          setAnalyticsLoading(false);
        })
        .catch(() => { setAnalyticsData({}); setAnalyticsLoading(false); });
    }
  }, [view, timeRange]);

  // LIVE LOGS: simulate streaming from Parquet data
  useEffect(() => {
    if (view !== 'live') {
      if (liveIntervalRef.current) clearInterval(liveIntervalRef.current);
      return;
    }
    setLiveLoading(true);
    setLiveLogs([]);
    setLiveEventCount(0);
    // Fetch a batch of logs then drip-feed them
    fetch('/api/v1/logs/search?source=conn&limit=100&page=1')
      .then(r => r.json())
      .then(data => {
        const allLogs = data.logs && data.logs.length > 0 ? data.logs : [];
        setLiveLoading(false);
        let idx = 0;
        liveIntervalRef.current = setInterval(() => {
          if (isLivePaused) return;
          const batch = allLogs.slice(idx, idx + 2 + Math.floor(Math.random() * 3));
          if (batch.length === 0) { idx = 0; return; }
          idx += batch.length;
          if (idx >= allLogs.length) idx = 0;
          setLiveLogs(prev => [...batch, ...prev].slice(0, 200));
          setLiveEventCount(prev => prev + batch.length);
        }, 800);
      })
      .catch(() => {
        setLiveLoading(false);
        setLiveLogs([]);
      });
    return () => {
      if (liveIntervalRef.current) clearInterval(liveIntervalRef.current);
    };
  }, [view]);

  // Handle pausing live stream
  useEffect(() => {
    // No need to do anything - the interval callback checks isLivePaused
  }, [isLivePaused]);

  // Clear all filters
  const clearAllFilters = useCallback(() => {
    setSearchTerm('');
    setDebouncedSearch('');
    setTimeRange('Last 24h');
    setActiveSource('');
    setActiveConditions([]);
    setSearchPage(1);
  }, []);

  // Query Builder helpers
  const addCondition = useCallback(() => {
    setQueryConditions(prev => [
      ...prev,
      { id: String(Date.now()), field: '', operator: '==', value: '' }
    ]);
  }, []);

  const removeCondition = useCallback((id: string) => {
    setQueryConditions(prev => prev.length > 1 ? prev.filter(c => c.id !== id) : prev);
  }, []);

  const updateCondition = useCallback((id: string, key: keyof QueryCondition, value: string) => {
    setQueryConditions(prev => prev.map(c => c.id === id ? { ...c, [key]: value } : c));
  }, []);

  const Breadcrumbs = () => (
    <div className="flex items-center justify-between mb-8">
      <div className="flex items-center gap-2 text-[10px] font-bold text-gray-500 uppercase tracking-widest">
        <span>Home</span>
        <ChevronRight size={10} />
        <span className="text-gray-300">Logs</span>
        <ChevronRight size={10} />
        <span className="text-[#00D4AA] font-black uppercase">{view}</span>
      </div>
      <div className="flex items-center gap-2 bg-[#161618] border border-[#1e1e20] p-1 rounded-xl shadow-xl">
        {allowed.includes('search') && (
          <button onClick={() => setView('search')} className={`px-6 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${view === 'search' ? 'bg-[#00D4AA] text-black shadow-lg' : 'text-gray-500 hover:text-white'}`}>Search</button>
        )}
        {allowed.includes('stats') && (
          <button onClick={() => setView('stats')} className={`px-6 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${view === 'stats' ? 'bg-[#00D4AA] text-black shadow-lg' : 'text-gray-500 hover:text-white'}`}>Analytics</button>
        )}
        {allowed.includes('live') && (
          <button onClick={() => setView('live')} className={`px-6 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${view === 'live' ? 'bg-[#00D4AA] text-black shadow-lg' : 'text-gray-500 hover:text-white'}`}>Live</button>
        )}
      </div>
    </div>
  );

  const MetricCard = ({ label, value, trend, trendGood, sub, color }: any) => (
    <div className="bg-zinc-900 border border-zinc-800 p-6 rounded-xl space-y-4 hover:border-zinc-700 transition-all group shadow-sm">
      <p className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">{label}</p>
      <div className="flex items-end justify-between">
        <h3 className="text-xl font-black text-white tracking-tighter">{value}</h3>
        {trend && (
          <div className="flex items-center gap-1 text-[11px] font-black">
            {trend.startsWith('↑') ? <TrendingUp size={14} /> : <TrendingDown size={14} />} {trend}
          </div>
        )}
      </div>
      {sub && <p className="text-[9px] font-bold text-zinc-600 uppercase tracking-tighter">{sub}</p>}
    </div>
  );

  // ─── SEARCH TAB ────────────────────────────────────────────────────
  const renderSearch = () => {
    const typeColors: Record<string, string> = {
      conn: 'border-l-blue-500', dns: 'border-l-emerald-500', http: 'border-l-amber-500',
      ssl: 'border-l-purple-500', tls: 'border-l-purple-500', dhcp: 'border-l-cyan-500',
      smtp: 'border-l-red-500', ssh: 'border-l-orange-500',
    };
    const typeBadgeColors: Record<string, string> = {
      conn: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      dns: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      http: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      ssl: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      tls: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      smtp: 'bg-red-500/10 text-red-400 border-red-500/20',
    };

    return (
      <div className="animate-in fade-in duration-500 space-y-4">
        <Breadcrumbs />


        {/* ═══ UNIFIED SEARCH BAR ═══ */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-2xl overflow-hidden">
          <div className="flex items-center gap-3 px-5 py-3">
            {/* Search Input */}
            <div className="flex-1 relative group">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600 group-focus-within:text-[#00D4AA] transition-colors" />
              <input
                type="text"
                placeholder="Search IPs, UIDs, domains, services…"
                className="w-full bg-zinc-950/60 border border-zinc-800/50 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white outline-none focus:border-[#00D4AA]/40 focus:ring-1 focus:ring-[#00D4AA]/20 transition-all placeholder:text-zinc-700"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            <div className="w-px h-8 bg-zinc-800" />

            {/* Source Dropdown */}
            <div className="relative">
              <select
                value={activeSource}
                onChange={(e) => setActiveSource(e.target.value)}
                className="bg-zinc-950/60 border border-zinc-800/50 rounded-xl pl-3 pr-8 py-2.5 text-xs font-bold text-zinc-300 outline-none focus:border-[#00D4AA]/40 appearance-none cursor-pointer uppercase tracking-wide min-w-[130px]"
              >
                <option value="">All Sources</option>
                {logSources.map(src => (
                  <option key={src} value={src}>{src.toLowerCase()}.log</option>
                ))}
              </select>
              <ChevronDown size={12} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-600 pointer-events-none" />
            </div>

            {/* Time Dropdown */}
            <div className="relative">
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="bg-zinc-950/60 border border-zinc-800/50 rounded-xl pl-3 pr-8 py-2.5 text-xs font-bold text-zinc-300 outline-none focus:border-[#00D4AA]/40 appearance-none cursor-pointer min-w-[130px]"
              >
                {(TIME_RANGES as readonly string[]).map(r => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
              <Clock size={12} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-600 pointer-events-none" />
            </div>

            {/* Query Builder Toggle */}
            <button
              onClick={() => setQueryBuilderOpen(!queryBuilderOpen)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wide transition-all border ${queryBuilderOpen
                ? 'bg-[#00D4AA]/10 border-[#00D4AA]/30 text-[#00D4AA]'
                : 'bg-zinc-950/60 border-zinc-800/50 text-zinc-500 hover:text-zinc-300 hover:border-zinc-700'
                }`}
            >
              <Code size={14} /> Builder
              <ChevronDown size={12} className={`transition-transform ${queryBuilderOpen ? 'rotate-180' : ''}`} />
            </button>

            {/* Schema Reference Toggle */}
            <button
              onClick={() => setSchemaOpen(!schemaOpen)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wide transition-all border ${schemaOpen
                ? 'bg-purple-500/10 border-purple-500/30 text-purple-400'
                : 'bg-zinc-950/60 border-zinc-800/50 text-zinc-500 hover:text-zinc-300 hover:border-zinc-700'
                }`}
            >
              <Database size={14} /> Fields
            </button>
          </div>

          {/* ═══ INLINE QUERY BUILDER ═══ */}
          {queryBuilderOpen && (
            <div className="border-t border-zinc-800 bg-zinc-950/40 px-5 py-4 animate-in slide-in-from-top duration-200 space-y-4">
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2">
                  <Database size={12} className="text-[#00D4AA]" />
                  <span className="text-[9px] font-black text-zinc-600 uppercase tracking-widest">Source</span>
                </div>
                <select
                  value={qbSource}
                  onChange={(e) => {
                    setQbSource(e.target.value);
                    setQueryConditions([{ id: String(Date.now()), field: '', operator: '==', value: '' }]);
                  }}
                  className="bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-bold text-white outline-none appearance-none cursor-pointer uppercase tracking-tight min-w-[120px]"
                >
                  <option value="">All</option>
                  {logSources.map(src => (
                    <option key={src} value={src}>{src.toLowerCase()}</option>
                  ))}
                </select>

                <div className="flex items-center gap-2 ml-2">
                  <Clock size={12} className="text-zinc-500" />
                  <span className="text-[9px] font-black text-zinc-600 uppercase tracking-widest">Time</span>
                </div>
                <select
                  value={qbScope}
                  onChange={(e) => setQbScope(e.target.value)}
                  className="bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-bold text-white outline-none appearance-none cursor-pointer min-w-[130px]"
                >
                  {(TIME_RANGES as readonly string[]).map(r => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-2">
                {queryConditions.map((cond, i) => (
                  <div key={cond.id} className="flex items-center gap-2">
                    <span className="w-8 text-right text-[9px] font-black text-zinc-700 uppercase shrink-0">
                      {i > 0 ? 'AND' : ''}
                    </span>
                    <select
                      value={cond.field}
                      onChange={(e) => updateCondition(cond.id, 'field', e.target.value)}
                      className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-[#00D4AA]/40 appearance-none font-bold uppercase tracking-tight"
                    >
                      <option value="" disabled>Field</option>
                      {qbFields.map(f => (
                        <option key={f.parquet} value={f.parquet}>{f.name} ({f.parquet})</option>
                      ))}
                    </select>
                    <select
                      value={cond.operator}
                      onChange={(e) => updateCondition(cond.id, 'operator', e.target.value)}
                      className="w-28 bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-400 outline-none focus:border-[#00D4AA]/40 appearance-none font-bold text-center"
                    >
                      {QUERY_OPERATORS.map(op => (
                        <option key={op.value} value={op.value}>{op.label}</option>
                      ))}
                    </select>
                    <input
                      type="text"
                      value={cond.value}
                      onChange={(e) => updateCondition(cond.id, 'value', e.target.value)}
                      placeholder="Value"
                      className="flex-[2] bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-[#00D4AA]/40"
                    />
                    <button
                      onClick={() => removeCondition(cond.id)}
                      className={`p-1.5 rounded transition-colors ${queryConditions.length > 1 ? 'text-zinc-700 hover:text-red-400' : 'text-zinc-900 cursor-not-allowed'}`}
                      disabled={queryConditions.length <= 1}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))}
              </div>

              <div className="flex items-center justify-between">
                <button onClick={addCondition} className="flex items-center gap-1.5 text-[10px] font-bold text-[#00D4AA] uppercase tracking-widest hover:underline">
                  <Plus size={12} /> Add Condition
                </button>
                <div className="flex gap-2">
                  <button onClick={() => setQueryBuilderOpen(false)} className="px-4 py-2 text-[10px] font-bold text-zinc-600 uppercase tracking-wider hover:text-white transition-colors">Cancel</button>
                  <button
                    onClick={() => {
                      // Apply source + time scope
                      setActiveSource(qbSource);
                      setTimeRange(qbScope);
                      // Store structured conditions for API — do NOT paste into search box
                      const valid = queryConditions.filter(c => c.field && c.value);
                      setActiveConditions(valid);
                      // Clear free-text search so it doesn't interfere
                      if (valid.length > 0) { setSearchTerm(''); setDebouncedSearch(''); }
                      setSearchPage(1);
                      setQueryBuilderOpen(false);
                    }}
                    className="px-6 py-2 bg-[#00D4AA] text-black rounded-lg text-[10px] font-black uppercase tracking-wider hover:bg-emerald-400 transition-colors"
                  >Run Search</button>
                </div>
              </div>
            </div>
          )}

          {/* Status bar */}
          <div className="flex items-center justify-between px-5 py-2 border-t border-zinc-800/50 bg-zinc-950/30">
            <div className="flex items-center gap-3 text-[10px] text-zinc-600">
              {timeRange && timeRange !== 'Last 24h' && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-800/50 text-zinc-400 font-bold">
                  <Clock size={10} /> {timeRange}
                  <X size={10} className="cursor-pointer hover:text-white" onClick={() => setTimeRange('Last 24h')} />
                </span>
              )}
              {activeSource && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-800/50 text-zinc-400 font-bold uppercase">
                  {activeSource.toLowerCase()}.log
                  <X size={10} className="cursor-pointer hover:text-white" onClick={() => setActiveSource('')} />
                </span>
              )}
              {debouncedSearch && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-[#00D4AA]/8 border border-[#00D4AA]/15 text-[#00D4AA] font-bold">
                  "{debouncedSearch}"
                  <X size={10} className="cursor-pointer hover:text-white" onClick={() => { setSearchTerm(''); setDebouncedSearch(''); }} />
                </span>
              )}
              {activeConditions.filter(c => c.field && c.value).map(c => (
                <span key={c.id} className="flex items-center gap-1 px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-bold font-mono text-[9px]">
                  {c.field} {c.operator} {c.value}
                  <X size={10} className="cursor-pointer hover:text-white" onClick={() => setActiveConditions(prev => prev.filter(x => x.id !== c.id))} />
                </span>
              ))}
              {(activeSource || debouncedSearch || activeConditions.length > 0 || timeRange !== 'Last 24h') && (
                <button onClick={clearAllFilters} className="text-[9px] font-bold text-zinc-600 hover:text-[#00D4AA] uppercase tracking-wider transition-colors">Clear All</button>
              )}
            </div>
            <span className="text-[10px] font-bold text-zinc-600">
              {searchLoading ? 'Searching…' : `${searchTotal.toLocaleString()} events`}
            </span>
          </div>
        </div>

        {/* ═══ LOG TABLE ═══ */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-2xl overflow-hidden">
          <table className="w-full text-left">
            <thead className="bg-zinc-950/60 border-b border-zinc-800">
              <tr className="text-[9px] font-black text-zinc-600 uppercase tracking-widest">
                <th className="pl-5 pr-2 py-3 w-8"></th>
                <th className="px-3 py-3 w-28">Time</th>
                <th className="px-3 py-3">Source</th>
                <th className="px-3 py-3">Destination</th>
                <th className="px-3 py-3 w-24 text-center">Type</th>
                <th className="px-3 py-3">Info</th>
                <th className="px-3 py-3 w-16 text-right pr-5"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {searchLoading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-16 text-center">
                    <div className="flex items-center justify-center gap-3">
                      <RefreshCcw size={16} className="text-[#00D4AA] animate-spin" />
                      <span className="text-xs text-zinc-500 uppercase tracking-wide font-bold">Querying Parquet data…</span>
                    </div>
                  </td>
                </tr>
              ) : searchResults.length > 0 ? (
                searchResults.map((log: any, i: number) => {
                  const ts = log.event_time ? new Date(log.event_time).toISOString().replace('T', ' ').slice(11, 23) : (log.ts || log.timestamp || '—');
                  const srcIp = log.src_ip || log.sourceIP || '—';
                  const dstIp = log.dst_ip || log.destIP || '—';
                  const srcPort = log.src_port || log.id_orig_p || '';
                  const dstPort = log.dst_port || log.id_resp_p || log.port || '';
                  const proto = log.protocol || log.proto || '';
                  const logType = log._source || log.type || 'conn';
                  const info = log.query || log.message || log.conn_state || log.host || log.flow_id || '—';
                  const borderColor = typeColors[logType] || 'border-l-zinc-700';
                  const badgeColor = typeBadgeColors[logType] || 'bg-zinc-800 text-zinc-500 border-zinc-700';

                  return (
                    <tr
                      key={log.flow_id || log.uid || log.id || i}
                      onClick={() => setSelectedLog(log)}
                      className={`hover:bg-zinc-800/40 transition-colors cursor-pointer group border-l-2 ${borderColor}`}
                    >
                      <td className="pl-5 pr-1 py-2.5 text-[9px] text-zinc-700 font-mono">{(searchPage - 1) * PAGE_SIZE + i + 1}</td>
                      <td className="px-3 py-2.5 text-[11px] text-zinc-500 font-mono tracking-tight">{typeof ts === 'string' ? ts.slice(0, 12) : ts}</td>
                      <td className="px-3 py-2.5">
                        <span className="text-[11px] font-bold text-zinc-200 group-hover:text-[#00D4AA] transition-colors">{srcIp}</span>
                        {srcPort && <span className="text-[9px] text-zinc-700 ml-0.5">:{srcPort}</span>}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="text-[11px] text-zinc-400">{dstIp}</span>
                        {dstPort && <span className="text-[9px] text-zinc-700 ml-0.5">:{dstPort}</span>}
                      </td>
                      <td className="px-3 py-2.5 text-center">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[8px] font-black uppercase tracking-widest ${badgeColor}`}>
                          {logType}
                          {proto && <span className="text-[7px] opacity-60">· {proto}</span>}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        <p className="text-[11px] text-zinc-400 line-clamp-1 max-w-[350px]">{info}</p>
                      </td>
                      <td className="px-3 py-2.5 pr-5 text-right">
                        <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button className="p-1 hover:bg-zinc-700 rounded text-zinc-600 hover:text-white" title="View Details"><Terminal size={12} /></button>
                          <button className="p-1 hover:bg-zinc-700 rounded text-zinc-600 hover:text-white" title="Investigate"><Search size={12} /></button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="px-6 py-16 text-center">
                    <p className="text-xs text-zinc-500 font-bold uppercase tracking-wide">No log events found</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          {searchPageCount > 1 && (
            <div className="flex items-center justify-between px-5 py-2.5 border-t border-zinc-800 bg-zinc-950/30">
              <div className="text-[10px] text-zinc-600 font-bold">
                Page <span className="text-white">{searchPage}</span> of <span className="text-white">{searchPageCount.toLocaleString()}</span>
                <span className="mx-2 text-zinc-800">·</span>
                <span className="text-white">{searchTotal.toLocaleString()}</span> events
              </div>
              <div className="flex items-center gap-1">
                <button
                  disabled={searchPage <= 1}
                  onClick={() => setSearchPage(p => Math.max(1, p - 1))}
                  className="px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-400 text-[10px] font-bold rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                >Prev</button>
                {Array.from({ length: Math.min(searchPageCount, 5) }, (_, i) => {
                  let pageNum: number;
                  if (searchPageCount <= 5) { pageNum = i + 1; }
                  else if (searchPage <= 3) { pageNum = i + 1; }
                  else if (searchPage >= searchPageCount - 2) { pageNum = searchPageCount - 4 + i; }
                  else { pageNum = searchPage - 2 + i; }
                  return (
                    <button
                      key={pageNum}
                      onClick={() => setSearchPage(pageNum)}
                      className={`px-2.5 py-1 text-[10px] font-bold rounded-lg transition-colors ${searchPage === pageNum ? 'bg-[#00D4AA] text-black' : 'bg-zinc-800 hover:bg-zinc-700 text-zinc-400'}`}
                    >{pageNum}</button>
                  );
                })}
                <button
                  disabled={searchPage >= searchPageCount}
                  onClick={() => setSearchPage(p => Math.min(searchPageCount, p + 1))}
                  className="px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-400 text-[10px] font-bold rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                >Next</button>
              </div>
            </div>
          )}
        </div>

        {/* Schema Explorer Slide-Out */}
        {schemaOpen && (
          <SchemaExplorer
            context="logs"
            selectedSource={activeSource || undefined}
            onFieldClick={(parquet) => {
              setSearchTerm(prev => prev ? `${prev} ${parquet}` : parquet);
            }}
            onClose={() => setSchemaOpen(false)}
            mode="sidebar"
          />
        )}
      </div>
    );
  };
  // ─── ANALYTICS TAB ─────────────────────────────────────────────────
  const renderAnalytics = () => {
    const data = analyticsData || {};

    if (analyticsLoading) {
      return (
        <div className="animate-in fade-in duration-500 space-y-8">
          <Breadcrumbs />
          <div className="flex items-center justify-center h-96">
            <div className="flex flex-col items-center gap-4">
              <RefreshCcw size={32} className="text-[#00D4AA] animate-spin" />
              <p className="text-xs font-black text-zinc-500 uppercase tracking-widest">Loading Analytics...</p>
            </div>
          </div>
        </div>
      );
    }

    // Derive real values from API — accept both snake_case (Redis pre-computed) and camelCase (legacy fallback)
    const totalEvents = data.total_events ?? data.totalEvents ?? 0;
    const sourceStats: Record<string, number> = data.source_stats ?? data.sourceStats ?? {};
    const activeSources = Object.entries(sourceStats).filter(([_, v]) => (v as number) > 0);
    const protocolDist: { protocol: string; count: number }[] = data.protocol_distribution ?? data.protocolDistribution ?? [];
    const topGenerators: { ip: string; count: number }[] = data.top_generators ?? data.topGenerators ?? [];

    // Sort sources by count
    const sortedSources = activeSources
      .map(([name, count]) => ({ name, count: count as number }))
      .sort((a, b) => b.count - a.count);
    const maxSourceCount = sortedSources.length > 0 ? sortedSources[0].count : 1;

    // Source colors
    const srcColors: Record<string, string> = {
      conn: '#3b82f6', dns: '#10b981', http: '#f97316', ssl: '#8b5cf6',
      tls: '#a855f7', ssh: '#f59e0b', dhcp: '#06b6d4', smtp: '#e11d48',
      ftp: '#84cc16', rdp: '#ef4444', smb_files: '#6366f1', kerberos: '#14b8a6',
    };

    const protoColors: Record<string, string> = { tcp: '#3b82f6', udp: '#10b981', icmp: '#f59e0b' };
    const fmtNum = (n: number) => { if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`; if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`; return n.toString(); };

    return (
      <div className="animate-in fade-in duration-500 space-y-6">
        <Breadcrumbs />

        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">Analytics Window</span>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="bg-zinc-950/80 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-bold text-zinc-200 outline-none focus:border-[#00D4AA]/40 min-w-[140px]"
            >
              {(TIME_RANGES as readonly string[]).map(r => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div className="text-[10px] text-zinc-600 font-bold">
            {data.window_served && data.window_served !== data.window_requested
              ? `Showing ${data.window_served} data (requested ${data.window_requested || timeRange})`
              : `Showing ${timeRange}`}
          </div>
        </div>

        {/* KPI Strip */}
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-[#161618] border border-[#1e1e20] p-5 rounded-xl">
            <p className="text-[9px] font-black text-zinc-500 uppercase tracking-widest">Total Events</p>
            <h3 className="text-2xl font-black text-white tracking-tighter mt-1">{fmtNum(totalEvents)}</h3>
            <p className="text-[9px] font-bold text-zinc-600 uppercase mt-1">From Parquet logs</p>
          </div>
          <div className="bg-[#161618] border border-[#1e1e20] p-5 rounded-xl">
            <p className="text-[9px] font-black text-zinc-500 uppercase tracking-widest">Active Sources</p>
            <h3 className="text-2xl font-black text-white tracking-tighter mt-1">{activeSources.length}</h3>
            <p className="text-[9px] font-bold text-zinc-600 uppercase mt-1">of {Object.keys(sourceStats).length} configured</p>
          </div>
          <div className="bg-[#161618] border border-[#1e1e20] p-5 rounded-xl">
            <p className="text-[9px] font-black text-zinc-500 uppercase tracking-widest">Top Protocol</p>
            <h3 className="text-2xl font-black text-white tracking-tighter mt-1 uppercase">{protocolDist[0]?.protocol || '—'}</h3>
            <p className="text-[9px] font-bold text-zinc-600 uppercase mt-1">{protocolDist[0] ? `${fmtNum(protocolDist[0].count)} events` : ''}</p>
          </div>
          <div className="bg-[#161618] border border-[#1e1e20] p-5 rounded-xl">
            <p className="text-[9px] font-black text-zinc-500 uppercase tracking-widest">Top Generator</p>
            <h3 className="text-lg font-black text-white tracking-tighter mt-1 font-mono">{topGenerators[0]?.ip || '—'}</h3>
            <p className="text-[9px] font-bold text-zinc-600 uppercase mt-1">{topGenerators[0] ? `${fmtNum(topGenerators[0].count)} events` : ''}</p>
          </div>
        </div>

        {/* Source Breakdown + Protocol Distribution */}
        <div className="grid grid-cols-5 gap-6">
          {/* Log Source Breakdown — 3 cols */}
          <div className="col-span-3 bg-[#161618] border border-[#1e1e20] rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Log Source Breakdown</h3>
              <span className="text-[9px] text-zinc-600 font-bold">{fmtNum(totalEvents)} total</span>
            </div>
            <div className="space-y-3">
              {sortedSources.map(s => {
                const pct = ((s.count / Math.max(totalEvents, 1)) * 100).toFixed(1);
                const color = srcColors[s.name] || '#6b7280';
                return (
                  <div key={s.name} className="space-y-1.5">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                        <span className="text-xs font-bold text-white uppercase">{s.name}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-[10px] text-zinc-500 font-mono">{fmtNum(s.count)}</span>
                        <span className="text-xs font-bold text-white w-14 text-right">{pct}%</span>
                      </div>
                    </div>
                    <div className="h-2 bg-[#0a0a0b] rounded-full overflow-hidden">
                      <div className="h-full rounded-full transition-all duration-500" style={{ width: `${(s.count / maxSourceCount) * 100}%`, backgroundColor: color }} />
                    </div>
                  </div>
                );
              })}
              {sortedSources.length === 0 && (
                <p className="text-xs text-zinc-600 text-center py-8">No log sources with data</p>
              )}
            </div>
          </div>

          {/* Protocol Distribution — 2 cols */}
          <div className="col-span-2 bg-[#161618] border border-[#1e1e20] rounded-xl p-6 space-y-4">
            <h3 className="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Protocol Distribution</h3>
            {protocolDist.length > 0 ? (
              <>
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={protocolDist.map(p => ({ name: p.protocol.toUpperCase(), value: p.count }))}
                        innerRadius={50} outerRadius={70} paddingAngle={5} dataKey="value" stroke="none"
                      >
                        {protocolDist.map((p, i) => (
                          <Cell key={i} fill={protoColors[p.protocol] || ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6'][i % 4]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#0a0a0b', border: '1px solid #27272a', borderRadius: '8px', fontSize: '10px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-2">
                  {protocolDist.map((p, i) => {
                    const pct = ((p.count / Math.max(totalEvents, 1)) * 100).toFixed(1);
                    const color = protoColors[p.protocol] || ['#3b82f6', '#10b981', '#f59e0b'][i % 3];
                    return (
                      <div key={p.protocol} className="flex justify-between items-center">
                        <div className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                          <span className="text-xs font-bold text-white uppercase">{p.protocol}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-zinc-500 font-mono">{fmtNum(p.count)}</span>
                          <span className="text-xs font-bold text-zinc-400">{pct}%</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            ) : (
              <p className="text-xs text-zinc-600 text-center py-8">No protocol data</p>
            )}
          </div>
        </div>

        {/* Top Log Generators */}
        <div className="bg-[#161618] border border-[#1e1e20] rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Top Log Generators</h3>
            <span className="text-[9px] text-zinc-600 font-bold">{topGenerators.length} assets</span>
          </div>
          <div className="bg-[#0a0a0b] border border-zinc-800/50 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-zinc-900/50 border-b border-zinc-800">
                <tr className="text-[9px] font-bold text-zinc-500 uppercase tracking-wider">
                  <th className="px-4 py-3 text-left w-8">#</th>
                  <th className="px-4 py-3 text-left">IP Address</th>
                  <th className="px-4 py-3 text-right">Events</th>
                  <th className="px-4 py-3 text-right">% of Total</th>
                  <th className="px-4 py-3 text-left w-48">Volume</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {topGenerators.slice(0, 10).map((gen, i) => {
                  const pct = ((gen.count / Math.max(totalEvents, 1)) * 100).toFixed(2);
                  const barWidth = topGenerators.length > 0 ? (gen.count / topGenerators[0].count) * 100 : 0;
                  return (
                    <tr key={gen.ip} className="hover:bg-zinc-900/30 transition-colors group cursor-pointer">
                      <td className="px-4 py-3 text-xs text-zinc-600 font-mono">{i + 1}</td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono font-bold text-white group-hover:text-[#00D4AA] transition-colors">{gen.ip}</span>
                      </td>
                      <td className="px-4 py-3 text-xs font-semibold text-white text-right">{gen.count.toLocaleString()}</td>
                      <td className="px-4 py-3 text-xs text-zinc-500 text-right">{pct}%</td>
                      <td className="px-4 py-3">
                        <div className="h-1.5 bg-zinc-900 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${i === 0 ? 'bg-[#00D4AA]' : 'bg-blue-500'}`} style={{ width: `${barWidth}%` }} />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // ─── LIVE LOGS TAB ─────────────────────────────────────────────────
  const renderLive = () => {
    return (
      <div className="animate-in fade-in duration-500 space-y-6 flex flex-col h-full min-h-[700px]">
        <Breadcrumbs />
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg flex-1 flex flex-col overflow-hidden shadow-2xl">
          <div className="p-6 border-b border-zinc-800 flex items-center justify-between bg-zinc-950/50">
            <div className="flex items-center gap-6">
              <button
                onClick={() => setIsLivePaused(prev => !prev)}
                className={`flex items-center gap-2 px-6 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${isLivePaused ? 'bg-[#f59e0b] text-black' : 'bg-emerald-500 text-black'}`}
              >
                {isLivePaused ? <Play size={14} /> : <Pause size={14} />} {isLivePaused ? 'Resume' : 'Pause Live'}
              </button>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${isLivePaused ? 'bg-zinc-600' : 'bg-emerald-500 animate-pulse'}`} />
                <span className="text-[10px] font-black text-zinc-500 uppercase tracking-[0.2em]">
                  {isLivePaused ? 'Paused' : `Streaming from Parquet · ${liveEventCount} events received`}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[9px] font-black text-zinc-600 uppercase tracking-widest">Buffer: {liveLogs.length}/200</span>
            </div>
          </div>
          <div className="flex-1 bg-[#0c0c0e] text-[11px] p-6 overflow-y-auto space-y-0 no-scrollbar font-mono">
            {liveLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="flex flex-col items-center gap-4">
                  <RefreshCcw size={24} className="text-[#00D4AA] animate-spin" />
                  <p className="text-xs font-black text-zinc-500 uppercase tracking-widest">Connecting to Parquet data...</p>
                </div>
              </div>
            ) : (
              liveLogs.map((log: any, i: number) => {
                const ts = log.ts ? String(log.ts).split('T')[1]?.slice(0, 12) || String(log.ts).slice(11, 23) : (log.ingest_time ? String(log.ingest_time).split('T')[1]?.slice(0, 12) : '—');
                const srcIp = log.src_ip || log.sourceIP || '—';
                const dstIp = log.dst_ip || log.destIP || '—';
                const proto = log.protocol || '—';
                const service = log.service || log.type || '—';
                const info = log.query || log.conn_state || log.flow_id || '—';
                return (
                  <div
                    key={`${log.flow_id || log.id || ''}-${i}`}
                    className={`flex items-center gap-4 py-1 group cursor-pointer hover:bg-white/5 transition-all ${i === 0 ? 'animate-in slide-in-from-top duration-300' : ''}`}
                    onClick={() => setSelectedLog(log)}
                  >
                    <span className="text-zinc-700 w-28 shrink-0">{ts}</span>
                    <span className="text-[#00D4AA] w-32 shrink-0 font-bold">{srcIp}</span>
                    <span className="text-zinc-600 w-4 shrink-0">→</span>
                    <span className="text-zinc-400 w-32 shrink-0">{dstIp}</span>
                    <span className="text-zinc-600 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-[9px] uppercase font-black w-12 text-center shrink-0">{proto}</span>
                    <span className="text-blue-400 w-16 shrink-0 text-[10px] font-bold uppercase">{service}</span>
                    <span className="text-zinc-500 group-hover:text-zinc-300 transition-colors truncate">{info}</span>
                  </div>
                );
              })
            )}
            {!isLivePaused && !liveLoading && (
              <div className="animate-pulse flex items-center gap-4 py-1">
                <span className="text-zinc-800 w-28">--:--:--.---</span>
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <div className="h-2 w-32 bg-zinc-900 rounded" />
                <span className="text-zinc-800">→</span>
                <div className="h-2 w-32 bg-zinc-900 rounded" />
                <div className="h-2 w-12 bg-zinc-900 rounded" />
                <div className="h-2 w-64 bg-zinc-900 rounded" />
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-[1300px] mx-auto pb-48 px-6 relative">
      {view === 'search' && renderSearch()}
      {view === 'stats' && renderAnalytics()}
      {view === 'live' && renderLive()}

      {/* LOG DETAILS SIDEBAR — shows ALL raw fields */}
      {selectedLog && (
        <div className="fixed inset-y-0 right-0 w-[650px] bg-zinc-900 border-l border-zinc-800 shadow-2xl z-50 overflow-y-auto animate-in slide-in-from-right duration-300">
          <div className="sticky top-0 bg-zinc-950/95 backdrop-blur-sm border-b border-zinc-800 p-6 flex items-center justify-between z-10">
            <div>
              <h3 className="text-lg font-black text-white uppercase tracking-tight">Log Details</h3>
              <p className="text-[10px] text-zinc-500 mt-1">{selectedLog.flow_id || selectedLog.id || '—'}</p>
            </div>
            <button
              onClick={() => setSelectedLog(null)}
              className="p-2 hover:bg-zinc-800 rounded-lg transition-colors"
            >
              <X size={20} className="text-zinc-500 hover:text-white" />
            </button>
          </div>
          <div className="p-6 space-y-6">
            {/* Key fields highlighted */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Source IP', value: selectedLog.src_ip || selectedLog.sourceIP },
                { label: 'Destination IP', value: selectedLog.dst_ip || selectedLog.destIP },
                { label: 'Src Port', value: selectedLog.src_port || selectedLog.id_orig_p },
                { label: 'Dst Port', value: selectedLog.dst_port || selectedLog.id_resp_p || selectedLog.port },
                { label: 'Protocol', value: selectedLog.protocol },
                { label: 'Service', value: selectedLog.service || selectedLog.type },
                { label: 'Direction', value: selectedLog.direction },
                { label: 'Duration', value: selectedLog.duration != null ? `${Number(selectedLog.duration).toFixed(4)}s` : undefined },
              ].filter(f => f.value != null && f.value !== '').map(f => (
                <div key={f.label} className="bg-zinc-950 border border-zinc-800 rounded-lg p-3">
                  <p className="text-[9px] font-black text-zinc-600 uppercase tracking-wider">{f.label}</p>
                  <p className="text-sm font-bold text-white mt-1">{String(f.value)}</p>
                </div>
              ))}
            </div>

            {/* ALL RAW FIELDS */}
            <div className="space-y-3">
              <h4 className="text-[10px] font-black text-zinc-500 uppercase tracking-widest flex items-center gap-2">
                <Info size={14} className="text-[#00D4AA]" /> All Fields ({Object.keys(selectedLog).length})
              </h4>
              <div className="bg-zinc-950 border border-zinc-800 rounded-xl divide-y divide-zinc-800">
                {Object.entries(selectedLog)
                  .filter(([k]) => k !== 'raw_log')
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([key, value]) => (
                    <div key={key} className="flex items-start justify-between px-4 py-2 hover:bg-zinc-900/50 transition-colors">
                      <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider shrink-0 w-40">{key}</p>
                      <p className="text-[11px] text-zinc-300 text-right break-all">{value == null ? '—' : typeof value === 'boolean' ? (value ? 'true' : 'false') : String(value)}</p>
                    </div>
                  ))}
              </div>
            </div>

            {/* RAW LOG JSON */}
            {selectedLog.raw_log && (
              <div className="space-y-3">
                <h4 className="text-[10px] font-black text-zinc-500 uppercase tracking-widest flex items-center gap-2">
                  <Terminal size={14} className="text-blue-400" /> Raw Log
                </h4>
                <pre className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 text-[10px] text-zinc-400 overflow-x-auto whitespace-pre-wrap font-mono max-h-[300px] overflow-y-auto no-scrollbar">
                  {(() => {
                    try { return JSON.stringify(JSON.parse(selectedLog.raw_log), null, 2); } catch { return selectedLog.raw_log; }
                  })()}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
};

export default LogsPage;

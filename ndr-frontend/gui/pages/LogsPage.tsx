import React, { useEffect, useMemo, useState } from 'react';
import { Search, Filter } from 'lucide-react';
import { getLogSources } from '../constants/fieldCatalogUtils';

type ViewMode = 'search' | 'stats';

const WINDOW_OPTIONS = ['1h', '6h', '24h', '7d', '30d'];

const LogsPage: React.FC<{ defaultView?: ViewMode }> = ({ defaultView = 'search' }) => {
  const [view, setView] = useState<ViewMode>(defaultView);
  const [search, setSearch] = useState('');
  const [source, setSource] = useState('');
  const [window, setWindow] = useState('24h');
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [analytics, setAnalytics] = useState<any>(null);

  const sources = useMemo(() => getLogSources(), []);

  const loadSearch = async (nextPage = page, nextSource = source, nextSearch = search) => {
    setLoading(true);
    const q = new URLSearchParams();
    q.set('page', String(nextPage));
    q.set('limit', '50');
    q.set('window', window);
    if (nextSource) q.set('source', nextSource);
    if (nextSearch) q.set('search', nextSearch);
    try {
      const res = await fetch(`/api/v1/logs/search?${q.toString()}`);
      const data = await res.json();
      setRows(Array.isArray(data?.logs) ? data.logs : []);
      setTotal(data?.total || 0);
    } catch {
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  const loadAnalytics = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/logs/analytics?window=${encodeURIComponent(window)}`);
      const data = await res.json();
      setAnalytics(data || {});
    } catch {
      setAnalytics({});
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (view === 'search') loadSearch(1);
    else loadAnalytics();
  }, [view, window]);

  const openSourceInSearch = (src: string) => {
    setSource(src);
    setView('search');
    setPage(1);
    loadSearch(1, src, search);
  };

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Log Explorer</h1>
          <p className="text-sm text-gray-400">Search and analyze parsed logs. All sources are shown by default.</p>
        </div>
        <div className="flex items-center gap-2 bg-[#161618] border border-[#222] rounded-lg p-1">
          <button onClick={() => setView('search')} className={`px-4 py-1.5 text-xs font-bold rounded ${view === 'search' ? 'bg-[#00D4AA] text-black' : 'text-gray-300'}`}>Search</button>
          <button onClick={() => setView('stats')} className={`px-4 py-1.5 text-xs font-bold rounded ${view === 'stats' ? 'bg-[#00D4AA] text-black' : 'text-gray-300'}`}>Analytics</button>
        </div>
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-xl p-4 flex flex-wrap items-center gap-3">
        <div className="inline-flex items-center gap-2 text-gray-400 text-xs uppercase tracking-wider font-bold">
          <Filter size={12} /> Filters
        </div>
        <select value={source} onChange={(e) => setSource(e.target.value)} className="bg-[#0a0a0c] border border-[#222] rounded px-3 py-2 text-sm">
          <option value="">All Sources</option>
          {sources.map((s) => (
            <option key={s} value={s.toLowerCase()}>{s}</option>
          ))}
        </select>
        <select value={window} onChange={(e) => setWindow(e.target.value)} className="bg-[#0a0a0c] border border-[#222] rounded px-3 py-2 text-sm">
          {WINDOW_OPTIONS.map((w) => <option key={w} value={w}>{w}</option>)}
        </select>
        <div className="flex-1 min-w-[220px] relative">
          <Search size={14} className="absolute left-3 top-2.5 text-gray-500" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search logs..." className="w-full bg-[#0a0a0c] border border-[#222] rounded pl-9 pr-3 py-2 text-sm" />
        </div>
        <button onClick={() => { setPage(1); loadSearch(1); }} className="px-4 py-2 rounded bg-[#00D4AA] text-black text-sm font-bold">Search</button>
      </div>

      {view === 'search' && (
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Results</h2>
            <span className="text-xs text-gray-500">Total: {total}</span>
          </div>
          {loading ? <p className="text-sm text-gray-400">Loading...</p> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-[#222]">
                    <th className="py-2 pr-3">Time</th>
                    <th className="py-2 pr-3">Source</th>
                    <th className="py-2 pr-3">Src IP</th>
                    <th className="py-2 pr-3">Dst IP</th>
                    <th className="py-2 pr-3">Protocol</th>
                    <th className="py-2 pr-3">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.length === 0 && (
                    <tr><td colSpan={6} className="py-4 text-gray-500">No logs found.</td></tr>
                  )}
                  {rows.map((r: any, idx: number) => (
                    <tr key={idx} className="border-b border-[#1a1a1a]">
                      <td className="py-2 pr-3 text-gray-300">{r.timestamp || r.event_time || '—'}</td>
                      <td className="py-2 pr-3 text-gray-300">{r.log_type || r.source || '—'}</td>
                      <td className="py-2 pr-3 text-gray-400">{r.src_ip || r.source_ip || '—'}</td>
                      <td className="py-2 pr-3 text-gray-400">{r.dst_ip || r.destination_ip || '—'}</td>
                      <td className="py-2 pr-3 text-gray-400">{r.protocol || '—'}</td>
                      <td className="py-2 pr-3 text-gray-400">{r.message || r.query || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {view === 'stats' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <button onClick={() => openSourceInSearch('')} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55] transition-all">
              <p className="text-xs uppercase tracking-wider text-gray-500">Total Events</p>
              <p className="text-2xl font-bold mt-1">{analytics?.total_events ?? 0}</p>
            </button>
            <button onClick={() => openSourceInSearch('conn')} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55] transition-all">
              <p className="text-xs uppercase tracking-wider text-gray-500">Top Source</p>
              <p className="text-lg font-bold mt-1">{analytics?.top_generators?.[0]?.ip || '—'}</p>
            </button>
            <button onClick={() => openSourceInSearch('dns')} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55] transition-all">
              <p className="text-xs uppercase tracking-wider text-gray-500">Top DNS</p>
              <p className="text-lg font-bold mt-1 truncate">{analytics?.top_dns_queries?.[0]?.domain || '—'}</p>
            </button>
          </div>

          <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3">Log Source Breakdown (click to open search)</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {Object.entries(analytics?.source_stats || {}).map(([k, v]: any) => (
                <button key={k} onClick={() => openSourceInSearch(String(k))} className="text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-3 hover:border-[#00D4AA55] transition-all">
                  <p className="text-xs uppercase tracking-wider text-gray-500">{k}</p>
                  <p className="text-lg font-bold">{v as number}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LogsPage;

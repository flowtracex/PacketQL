import React, { useEffect, useMemo, useState } from 'react';
import { BarChart3, Activity, Table, Loader2 } from 'lucide-react';
import { LogSearchPrefill } from './LogSearchPage';

type Props = {
  onDrillDown: (prefill: LogSearchPrefill) => void;
  currentSourceId?: string;
  onOpenTableExplorer?: () => void;
  ingestActive?: boolean;
};

const WIDGET_LIMIT = 20;
const DISPLAY_LIMIT = 10;
const pct = (value: number, total: number) => (total > 0 ? Math.max(2, Math.round((value / total) * 100)) : 0);

const LogDashboardPage: React.FC<Props> = ({ onDrillDown, currentSourceId, onOpenTableExplorer, ingestActive }) => {
  const [loading, setLoading] = useState(false);
  const [analytics, setAnalytics] = useState<any>({});

  const loadAnalytics = async () => {
    setLoading(true);
    try {
      const q = new URLSearchParams({ window: 'all' });
      if (currentSourceId) q.set('source_id', currentSourceId);
      const res = await fetch(`/api/v1/logs/analytics?${q.toString()}`);
      const data = await res.json();
      setAnalytics(data || {});
    } catch {
      setAnalytics({});
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAnalytics();
  }, [currentSourceId]);

  useEffect(() => {
    if (!ingestActive) return;
    const id = setInterval(() => {
      loadAnalytics();
    }, 3000);
    return () => clearInterval(id);
  }, [ingestActive, currentSourceId]);

  const sourceBreakdown = useMemo(() => {
      const stats = analytics?.source_stats || {};
      return Object.entries(stats)
        .map(([name, count]: any) => ({ name, count: Number(count || 0) }))
      .sort((a, b) => b.count - a.count);
  }, [analytics]);
  const sourceBreakdownActive = sourceBreakdown.filter((r) => r.count > 0);
  const sourceBreakdownLimited = sourceBreakdownActive.slice(0, DISPLAY_LIMIT);
  const topDnsLimited = (analytics?.top_dns_queries || []).slice(0, DISPLAY_LIMIT);
  const topRespCodesLimited = (analytics?.top_response_codes || []).slice(0, DISPLAY_LIMIT);
  const topSrcIpsLimited = (analytics?.top_generators || []).slice(0, DISPLAY_LIMIT);
  const topDstIpsLimited = (analytics?.top_dst_ips || []).slice(0, DISPLAY_LIMIT);
  const topProtocolsLimited = (analytics?.protocol_distribution || []).slice(0, DISPLAY_LIMIT);
  const topHttpHostsLimited = (analytics?.top_http_hosts || []).slice(0, DISPLAY_LIMIT);

  const totalEvents = Number(analytics?.total_events || 0);
  const topSourceIp = analytics?.top_generators?.[0]?.ip || '—';
  const topDomain = analytics?.top_dns_queries?.[0]?.domain || '—';

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white inline-flex items-center gap-2">
            Log Dashboard
            {loading && <Loader2 size={16} className="animate-spin text-gray-400" />}
          </h1>
          <p className="text-sm text-gray-400">SOC-centric security analytics with one-click drill-down into Log Search.</p>
        </div>
        <button
          onClick={onOpenTableExplorer}
          className="inline-flex items-center gap-2 text-sm px-4 py-2 rounded-lg border border-[#00D4AA55] text-[#00D4AA] hover:bg-[#00D4AA10] font-semibold"
        >
          <Table size={15} /> Zeek Log Tables
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <button onClick={() => onDrillDown({ window: 'all' })} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55]">
          <p className="text-xs uppercase tracking-wider text-gray-500">Total Events</p>
          <p className="text-2xl font-bold mt-1">{totalEvents}</p>
        </button>
        <button onClick={() => onDrillDown({ source: 'conn', window: 'all' })} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55]">
          <p className="text-xs uppercase tracking-wider text-gray-500">Top Source IP</p>
          <p className="text-lg font-bold mt-1 truncate">{topSourceIp}</p>
        </button>
        <button onClick={() => onDrillDown({ source: 'dns', search: topDomain !== '—' ? topDomain : '', window: 'all' })} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55]">
          <p className="text-xs uppercase tracking-wider text-gray-500">Top Queried Domain</p>
          <p className="text-lg font-bold mt-1 truncate">{topDomain}</p>
        </button>
        <button onClick={() => onDrillDown({ source: 'conn', window: 'all' })} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55]">
          <p className="text-xs uppercase tracking-wider text-gray-500">Ingestion Rate (EPS)</p>
          <p className="text-2xl font-bold mt-1">{Number(analytics?.ingestion_rate_eps || 0).toFixed(3)}</p>
        </button>
      </div>

      {loading && <p className="text-sm text-gray-400">Loading dashboard...</p>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 inline-flex items-center gap-2"><Activity size={14} /> Active Log Sources</h2>
            <button onClick={() => onDrillDown({ window: 'all' })} className="text-xs text-[#38bdf8] hover:text-[#7dd3fc] font-semibold">More</button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-72 overflow-auto pr-1">
            {sourceBreakdownLimited.length === 0 && <p className="text-sm text-gray-500 col-span-full">No source activity in this window.</p>}
            {sourceBreakdownLimited.map((row) => (
              <button
                key={row.name}
                onClick={() => onDrillDown({ source: row.name, window: 'all' })}
                className="text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
              >
                <div className="flex items-center justify-between text-sm">
                  <span>{row.name}</span>
                  <span className="text-gray-400">{row.count}</span>
                </div>
                <div className="h-1 bg-[#1b1b1d] rounded mt-1.5 overflow-hidden">
                  <div className="h-full bg-[#38bdf8]" style={{ width: `${pct(row.count, totalEvents)}%` }} />
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 inline-flex items-center gap-2"><BarChart3 size={14} /> Top Queried Domains</h2>
            <button onClick={() => onDrillDown({ source: 'dns', window: 'all' })} className="text-xs text-[#38bdf8] hover:text-[#7dd3fc] font-semibold">More</button>
          </div>
          <div className="space-y-2 max-h-72 overflow-auto pr-1">
            {topDnsLimited.length === 0 && <p className="text-sm text-gray-500">No DNS query data available.</p>}
            {topDnsLimited.map((row: any) => (
              <button
                key={row.domain}
                onClick={() => onDrillDown({ source: 'dns', search: row.domain, window: 'all' })}
                className="w-full text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm truncate">{row.domain}</span>
                  <span className="text-xs text-gray-400">{row.count}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Top Source IPs</h2>
            <button onClick={() => onDrillDown({ source: 'conn', window: 'all' })} className="text-xs text-[#38bdf8] hover:text-[#7dd3fc] font-semibold">More</button>
          </div>
          <div className="space-y-2 max-h-72 overflow-auto pr-1">
            {topSrcIpsLimited.length === 0 && <p className="text-sm text-gray-500">No source IP data available.</p>}
            {topSrcIpsLimited.map((row: any) => (
              <button
                key={`src-${row.ip}`}
                onClick={() => onDrillDown({ source: 'conn', conditions: [{ field: 'src_ip', operator: '==', value: row.ip }], window: 'all' })}
                className="w-full text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
              >
                <div className="flex items-center justify-between text-sm">
                  <span>{row.ip}</span>
                  <span className="text-gray-400">{row.count}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Top Destination IPs</h2>
            <button onClick={() => onDrillDown({ source: 'conn', window: 'all' })} className="text-xs text-[#38bdf8] hover:text-[#7dd3fc] font-semibold">More</button>
          </div>
          <div className="space-y-2 max-h-72 overflow-auto pr-1">
            {topDstIpsLimited.length === 0 && <p className="text-sm text-gray-500">No destination IP data available.</p>}
            {topDstIpsLimited.map((row: any) => (
              <button
                key={`dst-${row.ip}`}
                onClick={() => onDrillDown({ source: 'conn', conditions: [{ field: 'dst_ip', operator: '==', value: row.ip }], window: 'all' })}
                className="w-full text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
              >
                <div className="flex items-center justify-between text-sm">
                  <span>{row.ip}</span>
                  <span className="text-gray-400">{row.count}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Protocol Distribution</h2>
            <button onClick={() => onDrillDown({ source: 'conn', window: 'all' })} className="text-xs text-[#38bdf8] hover:text-[#7dd3fc] font-semibold">More</button>
          </div>
          <div className="space-y-2 max-h-72 overflow-auto pr-1">
            {topProtocolsLimited.length === 0 && <p className="text-sm text-gray-500">No protocol data available.</p>}
            {topProtocolsLimited.map((row: any) => (
              <button
                key={`proto-${row.protocol}`}
                onClick={() => onDrillDown({ source: 'conn', conditions: [{ field: 'protocol', operator: '==', value: String(row.protocol) }], window: 'all' })}
                className="w-full text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
              >
                <div className="flex items-center justify-between text-sm">
                  <span>{String(row.protocol).toUpperCase()}</span>
                  <span className="text-gray-400">{row.count}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Top HTTP Hosts</h2>
            <button onClick={() => onDrillDown({ source: 'http', window: 'all' })} className="text-xs text-[#38bdf8] hover:text-[#7dd3fc] font-semibold">More</button>
          </div>
          <div className="space-y-2 max-h-72 overflow-auto pr-1">
            {topHttpHostsLimited.length === 0 && <p className="text-sm text-gray-500">No HTTP host data available.</p>}
            {topHttpHostsLimited.map((row: any) => (
              <button
                key={`host-${row.host}`}
                onClick={() => onDrillDown({ source: 'http', search: row.host, window: 'all' })}
                className="w-full text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
              >
                <div className="flex items-center justify-between text-sm gap-3">
                  <span className="truncate">{row.host}</span>
                  <span className="text-gray-400">{row.count}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Top HTTP Response Codes</h2>
          <button onClick={() => onDrillDown({ source: 'http', window: 'all' })} className="text-xs text-[#38bdf8] hover:text-[#7dd3fc] font-semibold">More</button>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
          {topRespCodesLimited.length === 0 && <p className="text-sm text-gray-500 col-span-full">No HTTP response code data available.</p>}
          {topRespCodesLimited.map((row: any) => (
            <button
              key={`status-${row.code}`}
              onClick={() => onDrillDown({ source: 'http', conditions: [{ field: 'status_code', operator: '==', value: String(row.code) }], window: 'all' })}
              className="text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
            >
              <div className="text-xs text-gray-400">Status</div>
              <div className="text-lg font-bold leading-tight">#{row.code}</div>
              <div className="text-xs text-gray-400 mt-1">{row.count} events</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default LogDashboardPage;

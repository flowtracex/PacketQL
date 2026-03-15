import React, { useEffect, useMemo, useState } from 'react';
import { FileArchive, Network, Globe, Activity, Table, Loader2 } from 'lucide-react';
import { LogSearchPrefill } from './LogSearchPage';
import { API_BASE } from '../services/api';

type Props = {
  onDrillDown: (prefill: LogSearchPrefill) => void;
  currentSourceId?: string;
  onOpenTableExplorer?: () => void;
  ingestActive?: boolean;
};

const readJsonSafe = async (res: Response) => {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
};

const PcapDashboardPage: React.FC<Props> = ({ onDrillDown, currentSourceId, onOpenTableExplorer, ingestActive }) => {
  const [analytics, setAnalytics] = useState<any>({});
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const q = new URLSearchParams({ window: 'all' });
      if (currentSourceId) q.set('source_id', currentSourceId);
      const [analyticsRes, filesRes] = await Promise.all([
        fetch(`${API_BASE}/logs/analytics?${q.toString()}`),
        fetch(`${API_BASE}/logs/data-sources`),
      ]);
      const [analyticsJson, filesJson] = await Promise.all([readJsonSafe(analyticsRes), readJsonSafe(filesRes)]);
      setAnalytics(analyticsJson || {});
      setFiles(Array.isArray(filesJson?.sources) ? filesJson.sources : []);
    } catch {
      setAnalytics({});
      setFiles([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [currentSourceId]);

  useEffect(() => {
    if (!ingestActive) return;
    const id = setInterval(() => {
      load();
    }, 3000);
    return () => clearInterval(id);
  }, [ingestActive, currentSourceId]);

  const topSources = useMemo(() => (analytics?.top_generators || []).slice(0, 8), [analytics]);
  const topDestinations = useMemo(() => (analytics?.top_dst_ips || []).slice(0, 8), [analytics]);

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white inline-flex items-center gap-2">
            PCAP Dashboard
            {loading && <Loader2 size={16} className="animate-spin text-gray-400" />}
          </h1>
          <p className="text-sm text-gray-400">Traffic analytics from parsed PCAP data. Click any widget to investigate in Log Search.</p>
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
          <p className="text-xs uppercase tracking-wider text-gray-500">Traffic Events</p>
          <p className="text-2xl font-bold mt-1">{analytics?.total_events ?? 0}</p>
        </button>
        <button onClick={() => onDrillDown({ source: 'conn', window: 'all' })} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55]">
          <p className="text-xs uppercase tracking-wider text-gray-500">Active Sources</p>
          <p className="text-2xl font-bold mt-1">{analytics?.active_sources ?? 0}</p>
        </button>
        <button onClick={() => onDrillDown({ source: 'dns', window: 'all' })} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55]">
          <p className="text-xs uppercase tracking-wider text-gray-500">Top DNS Query</p>
          <p className="text-sm font-bold mt-2 truncate">{analytics?.top_dns_queries?.[0]?.domain || '—'}</p>
        </button>
        <button onClick={() => onDrillDown({ source: 'http', window: 'all' })} className="text-left bg-[#111113] border border-[#222] rounded-xl p-4 hover:border-[#00D4AA55]">
          <p className="text-xs uppercase tracking-wider text-gray-500">Top HTTP Host</p>
          <p className="text-sm font-bold mt-2 truncate">{analytics?.top_http_hosts?.[0]?.host || '—'}</p>
        </button>
      </div>

      {loading && <p className="text-sm text-gray-400">Loading dashboard...</p>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3 inline-flex items-center gap-2"><Network size={14} /> Protocol Distribution</h2>
          <div className="space-y-2">
            {(analytics?.protocol_distribution || []).slice(0, 10).map((row: any) => (
              <button
                key={row.protocol}
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
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3 inline-flex items-center gap-2"><Globe size={14} /> DNS Queries</h2>
          <div className="space-y-2">
            {(analytics?.top_dns_queries || []).slice(0, 10).map((row: any) => (
              <button
                key={row.domain}
                onClick={() => onDrillDown({ source: 'dns', search: row.domain, window: 'all' })}
                className="w-full text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
              >
                <div className="flex items-center justify-between text-sm gap-3">
                  <span className="truncate">{row.domain}</span>
                  <span className="text-gray-400">{row.count}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3 inline-flex items-center gap-2"><Activity size={14} /> Top Source IPs</h2>
          <div className="space-y-2">
            {topSources.map((row: any) => (
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
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3">Top Destination IPs</h2>
          <div className="space-y-2">
            {topDestinations.map((row: any) => (
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
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3">HTTP Hosts</h2>
          <div className="space-y-2">
            {(analytics?.top_http_hosts || []).slice(0, 10).map((row: any) => (
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

        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3">HTTP Response Codes</h2>
          <div className="space-y-2">
            {(analytics?.top_response_codes || []).slice(0, 10).map((row: any) => (
              <button
                key={`code-${row.code}`}
                onClick={() => onDrillDown({ source: 'http', conditions: [{ field: 'status_code', operator: '==', value: String(row.code) }], window: 'all' })}
                className="w-full text-left bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5 hover:border-[#00D4AA55]"
              >
                <div className="flex items-center justify-between text-sm">
                  <span>Status {row.code}</span>
                  <span className="text-gray-400">{row.count}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3 inline-flex items-center gap-2"><FileArchive size={14} /> Uploaded PCAP Files</h2>
        {files.length === 0 ? (
          <p className="text-sm text-gray-500">No uploaded files available yet.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {files.slice(0, 10).map((f) => (
              <div key={f.source_id || `${f.name}-${f.created_at}`} className="bg-[#0a0a0c] border border-[#1f1f1f] rounded-lg p-2.5">
                <p className="text-sm text-gray-200 truncate">{f.name}</p>
                <p className="text-xs text-gray-500 mt-1">{new Date(f.created_at).toLocaleString()}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default PcapDashboardPage;

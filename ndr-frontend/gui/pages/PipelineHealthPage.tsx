import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Activity, CircleAlert, Loader2 } from 'lucide-react';
import { API_BASE } from '../services/api';

type PipelineHealth = {
  current_source?: { source_id: string; name: string } | null;
  processing_status?: {
    active?: any;
    sources?: any[];
  };
  dropped_events?: {
    total_dropped_packets?: number;
    sources?: any[];
  };
  error_logs?: {
    files?: Array<{ file: string; entries: Array<{ line: string; level: string }> }>;
    source_failures?: any[];
  };
};

const readJsonSafe = async (res: Response) => {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    const preview = text.slice(0, 180).replace(/\s+/g, ' ').trim();
    throw new Error(`API returned non-JSON response (${res.status}): ${preview || 'empty response'}`);
  }
};

const badgeClass = (status: string) => {
  const s = String(status || '').toLowerCase();
  if (s === 'ready') return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30';
  if (s === 'failed') return 'bg-red-500/15 text-red-300 border border-red-500/30';
  if (s === 'processing') return 'bg-amber-500/15 text-amber-300 border border-amber-500/30';
  return 'bg-gray-500/15 text-gray-300 border border-gray-500/30';
};

const PipelineHealthPage: React.FC<{ currentSourceId?: string; ingestActive?: boolean }> = ({ currentSourceId, ingestActive }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [payload, setPayload] = useState<PipelineHealth>({});

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const q = new URLSearchParams();
      if (currentSourceId) q.set('source_id', currentSourceId);
      const res = await fetch(`${API_BASE}/logs/pipeline-health?${q.toString()}`);
      const data = await readJsonSafe(res);
      if (!res.ok) throw new Error(data?.error || 'Failed to load pipeline health');
      setPayload(data || {});
    } catch (e: any) {
      const msg = String(e?.message || 'Failed to load pipeline health');
      if (msg.includes('non-JSON response')) {
        setError('Pipeline Health API is unavailable or not loaded yet. Restart the API service and try again.');
      } else {
        setError(msg);
      }
      setPayload({});
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [currentSourceId]);

  useEffect(() => {
    const id = setInterval(() => {
      load();
    }, ingestActive ? 3000 : 7000);
    return () => clearInterval(id);
  }, [ingestActive, currentSourceId]);

  const active = payload?.processing_status?.active || null;
  const sources = payload?.processing_status?.sources || [];
  const droppedRows = payload?.dropped_events?.sources || [];
  const totalDropped = Number(payload?.dropped_events?.total_dropped_packets || 0);
  const files = payload?.error_logs?.files || [];
  const sourceFailures = payload?.error_logs?.source_failures || [];

  const totalRows = useMemo(
    () => sources.reduce((sum: number, r: any) => sum + Number(r?.total_rows || 0), 0),
    [sources],
  );

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white inline-flex items-center gap-2">
            Pipeline Health
            {loading && <Loader2 size={16} className="animate-spin text-gray-400" />}
          </h1>
          <p className="text-sm text-gray-400">Processing Status, Dropped Events, and Error Logs for ingestion reliability.</p>
        </div>
        <button onClick={load} className="px-4 py-2 rounded-lg border border-[#00D4AA55] text-[#00D4AA] hover:bg-[#00D4AA10] text-sm font-semibold">
          Refresh
        </button>
      </div>

      {error && <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-sm text-red-300">{error}</div>}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <p className="text-xs uppercase tracking-wider text-gray-500">Tracked Sources</p>
          <p className="text-2xl font-bold mt-1">{sources.length}</p>
        </div>
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <p className="text-xs uppercase tracking-wider text-gray-500">Total Parsed Rows</p>
          <p className="text-2xl font-bold mt-1">{totalRows}</p>
        </div>
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <p className="text-xs uppercase tracking-wider text-gray-500">Dropped Packets</p>
          <p className="text-2xl font-bold mt-1">{totalDropped}</p>
        </div>
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <p className="text-xs uppercase tracking-wider text-gray-500">Error Sources</p>
          <p className="text-2xl font-bold mt-1">{sourceFailures.length}</p>
        </div>
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3 inline-flex items-center gap-2">
          <Activity size={14} /> Processing Status
        </h2>
        {active ? (
          <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
            <p className="text-amber-200 font-semibold">Active: {active.name}</p>
            <p className="text-amber-200/90 mt-1">{active.message || 'Processing in progress'}</p>
          </div>
        ) : (
          <p className="text-sm text-gray-500 mb-3">No active ingestion currently.</p>
        )}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-[#222]">
                <th className="py-2 pr-3">Source</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Rows</th>
                <th className="py-2 pr-3">Updated</th>
                <th className="py-2 pr-3">Message</th>
              </tr>
            </thead>
            <tbody>
              {sources.length === 0 && (
                <tr><td colSpan={5} className="py-4 text-gray-500">No source status available.</td></tr>
              )}
              {sources.map((r: any) => (
                <tr key={r.source_id} className="border-b border-[#1a1a1a]">
                  <td className="py-2 pr-3 text-gray-300">{r.name}</td>
                  <td className="py-2 pr-3">
                    <span className={`inline-flex px-2 py-0.5 rounded text-[11px] font-semibold ${badgeClass(r.status)}`}>
                      {r.status || 'unknown'}
                    </span>
                  </td>
                  <td className="py-2 pr-3 text-gray-300">{Number(r.total_rows || 0)}</td>
                  <td className="py-2 pr-3 text-gray-400">{r.updated_at ? new Date(r.updated_at).toLocaleString() : '—'}</td>
                  <td className="py-2 pr-3 text-gray-400">{r.message || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3 inline-flex items-center gap-2">
          <AlertTriangle size={14} /> Dropped Events
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-[#222]">
                <th className="py-2 pr-3">Source</th>
                <th className="py-2 pr-3">Dropped</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Detail</th>
              </tr>
            </thead>
            <tbody>
              {droppedRows.length === 0 && (
                <tr><td colSpan={4} className="py-4 text-gray-500">No dropped-event details detected.</td></tr>
              )}
              {droppedRows.map((r: any) => (
                <tr key={`drop:${r.source_id}`} className="border-b border-[#1a1a1a]">
                  <td className="py-2 pr-3 text-gray-300">{r.name}</td>
                  <td className="py-2 pr-3 text-amber-300 font-semibold">{r.dropped_packets}</td>
                  <td className="py-2 pr-3 text-gray-400">{r.status || '—'}</td>
                  <td className="py-2 pr-3 text-gray-400">{r.message || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3 inline-flex items-center gap-2">
          <CircleAlert size={14} /> Error Logs
        </h2>

        {sourceFailures.length > 0 && (
          <div className="mb-4 space-y-2">
            {sourceFailures.slice(0, 8).map((f: any) => (
              <div key={`fail:${f.source_id}`} className="rounded-lg border border-red-500/25 bg-red-500/10 p-2.5 text-xs">
                <p className="text-red-300 font-semibold">{f.name} ({f.status})</p>
                <p className="text-red-200 mt-1">{f.message || 'No error detail provided.'}</p>
              </div>
            ))}
          </div>
        )}

        <div className="space-y-3">
          {files.length === 0 && <p className="text-sm text-gray-500">No error lines found in monitored log files.</p>}
          {files.map((f) => (
            <div key={f.file} className="border border-[#2a2a2f] rounded-lg overflow-hidden">
              <div className="px-3 py-2 text-xs font-semibold bg-[#17181d] text-gray-300">{f.file}</div>
              <div className="max-h-56 overflow-auto">
                {f.entries.map((entry, idx) => (
                  <div key={`${f.file}:${idx}`} className="px-3 py-1.5 text-[11px] border-t border-[#1f2025] font-mono text-gray-300">
                    {entry.line}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default PipelineHealthPage;

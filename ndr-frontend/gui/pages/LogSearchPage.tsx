import React, { useEffect, useMemo, useState } from 'react';
import { Filter, Plus, Search, X, Table, Loader2 } from 'lucide-react';
import { getAllVisibleFields, getLogSources } from '../constants/fieldCatalogUtils';

export type QueryCondition = {
  field: string;
  operator: '==' | '!=' | 'contains' | '>' | '<' | '>=' | '<=' | 'starts' | 'ends';
  value: string;
};

export type LogSearchPrefill = {
  source?: string;
  search?: string;
  window?: string;
  conditions?: QueryCondition[];
};

const OPERATORS: QueryCondition['operator'][] = ['==', '!=', 'contains', 'starts', 'ends', '>', '>=', '<', '<='];

const normalizeSource = (src: string) => src.trim().toLowerCase();

const LogSearchPage: React.FC<{ prefill?: LogSearchPrefill; prefillVersion?: number; currentSourceId?: string; onOpenTableExplorer?: () => void; ingestActive?: boolean }> = ({ prefill, prefillVersion, currentSourceId, onOpenTableExplorer, ingestActive }) => {
  const [source, setSource] = useState('');
  const [window, setWindow] = useState('all');
  const [search, setSearch] = useState('');
  const [conditions, setConditions] = useState<QueryCondition[]>([]);

  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [pageCount, setPageCount] = useState(1);
  const [loading, setLoading] = useState(false);
  const [selectedRow, setSelectedRow] = useState<any | null>(null);

  const sources = useMemo(() => getLogSources().map((s) => s.toLowerCase()), []);

  const availableFields = useMemo(() => {
    if (source) {
      const selectedSource = source.toUpperCase();
      return getAllVisibleFields(selectedSource).map((f) => f.name).filter(Boolean);
    }

    const all = new Set<string>([
      'src_ip', 'dst_ip', 'source_ip', 'destination_ip', 'protocol', 'query', 'host', 'uri', 'status_code', 'method', 'conn_state',
    ]);
    for (const s of getLogSources()) {
      for (const f of getAllVisibleFields(s)) {
        if (f.name) all.add(f.name);
      }
    }
    return Array.from(all).sort();
  }, [source]);

  const loadSearch = async (nextPage = page, opts?: { source?: string; search?: string; window?: string; conditions?: QueryCondition[] }) => {
    const src = opts?.source ?? source;
    const s = opts?.search ?? search;
    const w = opts?.window ?? window;
    const c = opts?.conditions ?? conditions;

    setLoading(true);
    const q = new URLSearchParams();
    q.set('page', String(nextPage));
    q.set('limit', '50');
    q.set('window', w);
    if (currentSourceId) q.set('source_id', currentSourceId);
    if (src) q.set('source', normalizeSource(src));
    if (s) q.set('search', s);
    if (c.length) q.set('conditions', JSON.stringify(c));

    try {
      const res = await fetch(`/api/v1/logs/search?${q.toString()}`);
      const data = await res.json();
      setRows(Array.isArray(data?.logs) ? data.logs : []);
      setTotal(Number(data?.total || 0));
      setPageCount(Math.max(1, Number(data?.page_count || 1)));
      setSelectedRow(null);
    } catch {
      setRows([]);
      setTotal(0);
      setPageCount(1);
      setSelectedRow(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!prefillVersion) {
      loadSearch(1);
      return;
    }

    const nextSource = normalizeSource(prefill?.source || '');
    const nextSearch = prefill?.search || '';
    const nextWindow = prefill?.window || 'all';
    const nextConditions = Array.isArray(prefill?.conditions) ? prefill!.conditions : [];

    setSource(nextSource);
    setSearch(nextSearch);
    setWindow(nextWindow);
    setConditions(nextConditions);
    setPage(1);
    loadSearch(1, {
      source: nextSource,
      search: nextSearch,
      window: nextWindow,
      conditions: nextConditions,
    });
  }, [prefillVersion, currentSourceId]);

  useEffect(() => {
    if (!ingestActive) return;
    const id = setInterval(() => {
      loadSearch(page);
    }, 3000);
    return () => clearInterval(id);
  }, [ingestActive, page, source, search, JSON.stringify(conditions), currentSourceId]);

  const addCondition = () => {
    setConditions((prev) => [
      ...prev,
      {
        field: availableFields[0] || 'src_ip',
        operator: 'contains',
        value: '',
      },
    ]);
  };

  const updateCondition = (index: number, patch: Partial<QueryCondition>) => {
    setConditions((prev) => prev.map((c, i) => (i === index ? { ...c, ...patch } : c)));
  };

  const removeCondition = (index: number) => {
    setConditions((prev) => prev.filter((_, i) => i !== index));
  };

  const selectedEntries = useMemo(() => {
    if (!selectedRow) return [];
    return Object.entries(selectedRow).sort(([a], [b]) => a.localeCompare(b));
  }, [selectedRow]);

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white inline-flex items-center gap-2">
            Log Search
            {loading && <Loader2 size={16} className="animate-spin text-gray-400" />}
          </h1>
          <p className="text-sm text-gray-400">Focused log exploration and investigation. All log sources are included by default.</p>
        </div>
        <button
          onClick={onOpenTableExplorer}
          className="inline-flex items-center gap-2 text-sm px-4 py-2 rounded-lg border border-[#00D4AA55] text-[#00D4AA] hover:bg-[#00D4AA10] font-semibold"
        >
          <Table size={15} /> Zeek Log Tables
        </button>
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-xl p-4 space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="inline-flex items-center gap-2 text-gray-400 text-xs uppercase tracking-wider font-bold">
            <Filter size={12} /> Scope
          </div>
          <select value={source} onChange={(e) => setSource(e.target.value)} className="bg-[#0a0a0c] border border-[#222] rounded px-3 py-2 text-sm">
            <option value="">All Sources</option>
            {sources.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          <div className="flex-1 min-w-[220px] relative">
            <Search size={14} className="absolute left-3 top-2.5 text-gray-500" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IP, domain, host, URI..."
              className="w-full bg-[#0a0a0c] border border-[#222] rounded pl-9 pr-3 py-2 text-sm"
            />
          </div>

          <button
            onClick={() => {
              setPage(1);
              loadSearch(1);
            }}
            className="px-4 py-2 rounded bg-[#38bdf8] text-[#04101d] text-sm font-bold hover:bg-[#22a9e6]"
          >
            Search
          </button>
        </div>

        <div className="border-t border-[#1f1f21] pt-4 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Query Builder</h2>
            <button onClick={addCondition} className="inline-flex items-center gap-1 text-xs px-2.5 py-1.5 rounded border border-[#00D4AA55] text-[#00D4AA] hover:bg-[#00D4AA10]">
              <Plus size={12} /> Add Condition
            </button>
          </div>

          {conditions.length === 0 && (
            <p className="text-xs text-gray-500">No advanced conditions added. Use Search for broad exploration.</p>
          )}

          {conditions.map((condition, index) => (
            <div key={index} className="grid grid-cols-1 md:grid-cols-12 gap-2">
              <select
                value={condition.field}
                onChange={(e) => updateCondition(index, { field: e.target.value })}
                className="md:col-span-4 bg-[#0a0a0c] border border-[#222] rounded px-3 py-2 text-sm"
              >
                {availableFields.map((f) => (
                  <option key={f} value={f}>{f}</option>
                ))}
              </select>

              <select
                value={condition.operator}
                onChange={(e) => updateCondition(index, { operator: e.target.value as QueryCondition['operator'] })}
                className="md:col-span-2 bg-[#0a0a0c] border border-[#222] rounded px-3 py-2 text-sm"
              >
                {OPERATORS.map((op) => (
                  <option key={op} value={op}>{op}</option>
                ))}
              </select>

              <input
                value={condition.value}
                onChange={(e) => updateCondition(index, { value: e.target.value })}
                placeholder="value"
                className="md:col-span-5 bg-[#0a0a0c] border border-[#222] rounded px-3 py-2 text-sm"
              />

              <button onClick={() => removeCondition(index)} className="md:col-span-1 inline-flex items-center justify-center rounded border border-[#333] hover:border-[#555] text-gray-400 hover:text-white">
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Results</h2>
          <span className="text-xs text-gray-500">Total: {total}</span>
        </div>

        {loading ? (
          <p className="text-sm text-gray-400">Loading...</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-[#222]">
                  <th className="py-2 pr-3">Time</th>
                  <th className="py-2 pr-3">Source</th>
                  <th className="py-2 pr-3">Src IP</th>
                  <th className="py-2 pr-3">Dst IP</th>
                  <th className="py-2 pr-3">Protocol</th>
                  <th className="py-2 pr-3">Query/Message</th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-4 text-gray-500">No matching logs found.</td>
                  </tr>
                )}
                {rows.map((r: any, idx: number) => (
                  <tr
                    key={idx}
                    className="border-b border-[#1b324a] hover:bg-[#101219] cursor-pointer"
                    onClick={() => setSelectedRow(r)}
                  >
                    <td className="py-2 pr-3 text-gray-200">{r.timestamp || r.ts || r.ingest_time || '—'}</td>
                    <td className="py-2 pr-3 text-gray-200">{r._source || r.log_type || r.source || '—'}</td>
                    <td className="py-2 pr-3 text-gray-400">{r.src_ip || r.source_ip || '—'}</td>
                    <td className="py-2 pr-3 text-gray-400">{r.dst_ip || r.destination_ip || '—'}</td>
                    <td className="py-2 pr-3 text-gray-400">{r.protocol || r.service || '—'}</td>
                    <td className="py-2 pr-3 text-gray-400">{r.query || r.host || r.uri || r.message || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="mt-4 flex items-center justify-end gap-2">
          <button
            onClick={() => {
              if (page <= 1) return;
              const next = page - 1;
              setPage(next);
              loadSearch(next);
            }}
            disabled={page <= 1 || loading}
            className="px-3 py-1.5 text-xs rounded border border-[#333] disabled:opacity-50"
          >
            Previous
          </button>
          <span className="text-xs text-gray-500">Page {page} / {pageCount}</span>
          <button
            onClick={() => {
              if (page >= pageCount) return;
              const next = page + 1;
              setPage(next);
              loadSearch(next);
            }}
            disabled={page >= pageCount || loading}
            className="px-3 py-1.5 text-xs rounded border border-[#333] disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>

      {selectedRow && (
        <div className="fixed inset-0 z-[75] bg-black/60 flex justify-end">
          <div className="h-full w-[640px] max-w-[92vw] bg-[#111113] border-l border-[#2a2a2f] shadow-2xl flex flex-col">
            <div className="px-5 py-3 border-b border-[#2a2a2f] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-white">Log Record Details</h2>
                <p className="text-[11px] text-gray-400">All fields for selected result</p>
              </div>
              <button onClick={() => setSelectedRow(null)} className="p-1.5 rounded-lg hover:bg-white/5 text-gray-400 hover:text-white">
                <X size={16} />
              </button>
            </div>
            <div className="px-5 py-3 border-b border-[#2a2a2f] text-xs text-gray-400">
              Source: {selectedRow?._source || selectedRow?.log_type || selectedRow?.source || '—'} ·
              Time: {selectedRow?.timestamp || selectedRow?.ts || selectedRow?.ingest_time || '—'}
            </div>
            <div className="flex-1 overflow-auto p-4">
              <div className="border border-[#2d2d35] rounded-xl overflow-hidden">
                <table className="w-full text-xs">
                  <thead className="bg-[#17181d] text-gray-400 border-b border-[#2a2a2f]">
                    <tr>
                      <th className="text-left px-3 py-2 w-[36%]">Field</th>
                      <th className="text-left px-3 py-2">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedEntries.map(([field, value]) => {
                      const formatted =
                        value === null || value === undefined
                          ? 'null'
                          : typeof value === 'object'
                          ? JSON.stringify(value)
                          : String(value);
                      return (
                        <tr key={field} className="border-b border-[#1f2025] align-top">
                          <td className="px-3 py-2 font-mono text-[#00D4AA] break-all">{field}</td>
                          <td className="px-3 py-2 text-gray-200 break-all">{formatted}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LogSearchPage;

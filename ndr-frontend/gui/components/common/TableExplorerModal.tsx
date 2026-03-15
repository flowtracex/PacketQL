import React, { useEffect, useMemo, useState } from 'react';
import { Database, Search, X } from 'lucide-react';
import { API_BASE } from '../../services/api';
import { getAllVisibleFields, getLogSources } from '../../constants/fieldCatalogUtils';

type TableField = {
  name: string;
  type: string;
};

type TableEntry = {
  table: string;
  field_count: number;
  fields: TableField[];
};

const readJsonSafe = async (res: Response) => {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    const preview = text.slice(0, 200).replace(/\s+/g, ' ').trim();
    throw new Error(`API returned non-JSON response (${res.status}): ${preview || 'empty response'}`);
  }
};

const TableExplorerModal: React.FC<{
  sourceId?: string;
  sourceName?: string;
  onClose: () => void;
}> = ({ sourceId, sourceName, onClose }) => {
  const [tables, setTables] = useState<TableEntry[]>([]);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [search, setSearch] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const load = async () => {
      if (!sourceId) {
        setError('No current data source selected.');
        setTables([]);
        return;
      }
      setLoading(true);
      setError('');
      try {
        const qs = new URLSearchParams({ source_id: sourceId });
        const res = await fetch(`${API_BASE}/logs/table-schema?${qs.toString()}`);
        const data = await readJsonSafe(res);
        if (!res.ok) throw new Error(data?.error || 'Failed to load table schema');
        const list = Array.isArray(data?.tables) ? data.tables : [];

        const merged = new Map<string, TableEntry>();
        for (const t of list) {
          merged.set(String(t.table).toLowerCase(), {
            table: String(t.table).toLowerCase(),
            field_count: Number(t.field_count || 0),
            fields: Array.isArray(t.fields) ? t.fields : [],
          });
        }

        for (const src of getLogSources()) {
          const key = String(src).toLowerCase();
          if (merged.has(key)) continue;
          const catalogFields = getAllVisibleFields(src).map((f) => ({
            name: String(f.name || f.parquet || '').trim(),
            type: String((f as any).type || 'string'),
          })).filter((f) => f.name);
          merged.set(key, {
            table: key,
            field_count: catalogFields.length,
            fields: catalogFields,
          });
        }

        const mergedList = Array.from(merged.values()).sort((a, b) => a.table.localeCompare(b.table));
        setTables(mergedList);
        const nextExpanded: Record<string, boolean> = {};
        mergedList.slice(0, 2).forEach((t: TableEntry) => {
          nextExpanded[t.table] = true;
        });
        setExpanded(nextExpanded);
      } catch (e: any) {
        setError(e?.message || 'Failed to load table schema');
        setTables([]);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [sourceId]);

  const filteredTables = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return tables;
    return tables
      .map((t) => {
        if (t.table.toLowerCase().includes(q)) return t;
        const fields = t.fields.filter((f) => f.name.toLowerCase().includes(q) || String(f.type).toLowerCase().includes(q));
        if (fields.length === 0) return null;
        return { ...t, fields, field_count: fields.length };
      })
      .filter(Boolean) as TableEntry[];
  }, [search, tables]);

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60">
      <div className="w-[900px] max-w-[92vw] max-h-[88vh] overflow-hidden bg-[#111113] border border-[#2a2a2f] rounded-2xl shadow-2xl flex flex-col">
        <div className="px-5 py-3 border-b border-[#2a2a2f] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database size={16} className="text-[#00D4AA]" />
            <div>
              <h2 className="text-sm font-bold text-white">Zeek Log Tables</h2>
              <p className="text-[11px] text-gray-400">{sourceName || 'Current source'} · {tables.length} tables</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5 text-gray-400 hover:text-white">
            <X size={16} />
          </button>
        </div>

        <div className="px-5 py-3 border-b border-[#2a2a2f] bg-[#0f1115]">
          <p className="text-xs text-gray-200 leading-relaxed">
            Zeek is running in the background to process captured traffic. Protocol logs (DNS, HTTP, TLS, Conn, and others)
            are converted into structured tables, normalized into rows and columns, and stored with defined field types so
            analysts can query data quickly using SQL.
          </p>
        </div>

        <div className="px-5 py-3 border-b border-[#2a2a2f]">
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search table or field..."
              className="w-full bg-[#0b0b0d] border border-[#2d2d35] rounded-lg pl-8 pr-3 py-2 text-xs text-gray-200"
            />
          </div>
        </div>

        <div className="flex-1 overflow-auto p-4">
          {loading && <p className="text-xs text-gray-400">Loading schema...</p>}
          {error && <p className="text-xs text-red-400">{error}</p>}
          {!loading && !error && filteredTables.length === 0 && <p className="text-xs text-gray-500">No tables/fields matched.</p>}

          <div className="space-y-3">
            {filteredTables.map((t) => (
              <div key={t.table} className="border border-[#2d2d35] rounded-xl overflow-hidden">
                <button
                  onClick={() => setExpanded((prev) => ({ ...prev, [t.table]: !prev[t.table] }))}
                  className="w-full px-4 py-2.5 flex items-center justify-between bg-[#16161a] hover:bg-[#1d1d23]"
                >
                  <span className="font-mono text-sm text-[#00D4AA]">{t.table}</span>
                  <span className="text-[11px] text-gray-400">{t.field_count} fields</span>
                </button>
                {expanded[t.table] && (
                  <div className="max-h-72 overflow-auto">
                    <table className="w-full text-xs">
                      <thead className="bg-[#0f1014] text-gray-500 border-y border-[#202028]">
                        <tr>
                          <th className="text-left px-4 py-2">Field</th>
                          <th className="text-left px-4 py-2">Type</th>
                        </tr>
                      </thead>
                      <tbody>
                        {t.fields.map((f) => (
                          <tr key={`${t.table}:${f.name}`} className="border-b border-[#1b1b22]">
                            <td className="px-4 py-1.5 font-mono text-gray-200">{f.name}</td>
                            <td className="px-4 py-1.5 text-gray-400">{f.type}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default TableExplorerModal;

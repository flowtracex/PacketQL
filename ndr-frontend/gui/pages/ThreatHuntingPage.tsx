import React, { useEffect, useMemo, useState } from 'react';
import { Play, Save, BookOpen } from 'lucide-react';
import { huntApi } from '../services/api';
import { CONFIG } from '../config';

type View = 'builder' | 'history';

const QUERY_LIBRARY = [
  {
    name: 'Top Source IPs',
    sql: 'SELECT src_ip, COUNT(*) AS hits FROM conn GROUP BY src_ip ORDER BY hits DESC LIMIT 50;'
  },
  {
    name: 'Top DNS Domains',
    sql: 'SELECT query, COUNT(*) AS hits FROM dns GROUP BY query ORDER BY hits DESC LIMIT 50;'
  },
  {
    name: 'Unusual Destination Ports',
    sql: 'SELECT dst_ip, dst_port, COUNT(*) AS hits FROM conn WHERE dst_port NOT IN (53,80,443,22) GROUP BY dst_ip, dst_port ORDER BY hits DESC LIMIT 100;'
  },
  {
    name: 'Failed/Rejected Connections',
    sql: "SELECT src_ip, dst_ip, conn_state, COUNT(*) AS hits FROM conn WHERE conn_state IN ('REJ','S0','RSTO','RSTR') GROUP BY src_ip, dst_ip, conn_state ORDER BY hits DESC LIMIT 100;"
  },
  {
    name: 'Large Data Transfers',
    sql: 'SELECT src_ip, dst_ip, SUM(COALESCE(orig_bytes,0)+COALESCE(resp_bytes,0)) AS total_bytes FROM conn GROUP BY src_ip, dst_ip ORDER BY total_bytes DESC LIMIT 50;'
  }
];

const ThreatHuntingPage: React.FC<{ defaultView?: View; currentSourceId?: string }> = ({ defaultView = 'builder', currentSourceId }) => {
  const isReadOnlyDemo = CONFIG.APP_MODE === 'demo';
  const [view, setView] = useState<View>(defaultView);
  const [name, setName] = useState('SOC SQL Hunt');
  const [sql, setSql] = useState(QUERY_LIBRARY[0].sql);
  const [running, setRunning] = useState(false);
  const [saving, setSaving] = useState(false);
  const [rows, setRows] = useState<any[]>([]);
  const [error, setError] = useState('');
  const [history, setHistory] = useState<any[]>([]);

  const columns = useMemo(() => {
    if (!rows.length) return [];
    return Object.keys(rows[0]);
  }, [rows]);

  const loadHistory = async () => {
    const res = await huntApi.list({ limit: 200 });
    setHistory(res?.hunts || []);
  };

  useEffect(() => {
    if (view === 'history') loadHistory();
  }, [view]);

  const run = async () => {
    setRunning(true);
    setError('');
    try {
      const res = await huntApi.run({ query_type: 'sql', query: sql, source_id: currentSourceId });
      if (res?.error) {
        setError(res.error);
        setRows([]);
      } else {
        setRows(res?.results || []);
      }
    } catch {
      setError('Query execution failed');
      setRows([]);
    } finally {
      setRunning(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      const saved = await huntApi.save({
        name: name || 'SOC SQL Hunt',
        type: 'sql',
        log_source: 'multi',
        source_id: currentSourceId,
        sql_query: sql,
        query: sql,
        status: 'created'
      });
      if (!saved?.id) throw new Error('Save failed');
      await huntApi.run({ hunt_id: String(saved.id), query_type: 'sql', query: sql, source_id: currentSourceId });
      await loadHistory();
      setView('history');
    } catch (e: any) {
      setError(e?.message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">SQL Query Builder</h1>
          <p className="text-sm text-gray-400">Write SQL directly. Visual builder is removed for analyst speed.</p>
        </div>
        <div className="flex items-center gap-2 bg-[#161618] border border-[#222] rounded-lg p-1">
          <button onClick={() => setView('builder')} className={`px-4 py-1.5 text-xs font-bold rounded ${view === 'builder' ? 'bg-[#00D4AA] text-black' : 'text-gray-300'}`}>Editor</button>
          <button onClick={() => setView('history')} className={`px-4 py-1.5 text-xs font-bold rounded ${view === 'history' ? 'bg-[#00D4AA] text-black' : 'text-gray-300'}`}>Query Library</button>
        </div>
      </div>

      {view === 'builder' && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 bg-[#111113] border border-[#222] rounded-xl p-4">
              <div className="flex flex-wrap items-center gap-2 mb-3">
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="bg-[#0a0a0c] border border-[#222] rounded px-3 py-2 text-sm min-w-[220px]"
                  placeholder="Query name"
                />
                <button onClick={run} disabled={running} className="px-3 py-2 rounded bg-[#00D4AA] text-black text-sm font-bold disabled:opacity-50 inline-flex items-center gap-2">
                  <Play size={14} /> {running ? 'Running...' : 'Run'}
                </button>
                {!isReadOnlyDemo && (
                  <button onClick={save} disabled={saving} className="px-3 py-2 rounded border border-[#00D4AA55] text-[#00D4AA] text-sm font-bold disabled:opacity-50 inline-flex items-center gap-2">
                    <Save size={14} /> {saving ? 'Saving...' : 'Save'}
                  </button>
                )}
              </div>
              {isReadOnlyDemo && (
                <p className="mb-3 text-xs text-sky-300">
                  Public demo is read-only. Run investigation queries, but saving or modifying query history is disabled.
                </p>
              )}
              <textarea
                value={sql}
                onChange={(e) => setSql(e.target.value)}
                className="w-full min-h-[300px] bg-[#0a0a0c] border border-[#222] rounded p-3 text-sm font-mono"
              />
              {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
            </div>

            <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
              <div className="inline-flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-gray-400 mb-3">
                <BookOpen size={14} /> SOC Example Queries
              </div>
              <div className="space-y-2">
                {QUERY_LIBRARY.map((q) => (
                  <button
                    key={q.name}
                    onClick={() => setSql(q.sql)}
                    className="w-full text-left bg-[#0a0a0c] border border-[#1f1f1f] hover:border-[#00D4AA55] rounded p-3 text-sm"
                  >
                    {q.name}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
            <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3">Results</h2>
            {rows.length === 0 ? (
              <p className="text-sm text-gray-500">Run a query to view results.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500 border-b border-[#222]">
                      {columns.map((c) => (
                        <th key={c} className="py-2 pr-3">{c}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r, i) => (
                      <tr key={i} className="border-b border-[#1a1a1a]">
                        {columns.map((c) => (
                          <td key={c} className="py-2 pr-3 text-gray-300">{String(r[c] ?? '—')}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {view === 'history' && (
        <div className="bg-[#111113] border border-[#222] rounded-xl p-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400 mb-3">Saved Queries</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-[#222]">
                  <th className="py-2 pr-3">Name</th>
                  <th className="py-2 pr-3">Type</th>
                  <th className="py-2 pr-3">Matches</th>
                  <th className="py-2 pr-3">Last Run</th>
                  <th className="py-2 pr-3">Action</th>
                </tr>
              </thead>
              <tbody>
                {history.length === 0 && (
                  <tr><td colSpan={5} className="py-4 text-gray-500">No saved queries.</td></tr>
                )}
                {history.map((h) => (
                  <tr key={h.id} className="border-b border-[#1a1a1a]">
                    <td className="py-2 pr-3 text-gray-200">{h.name}</td>
                    <td className="py-2 pr-3 text-gray-400">{h.type}</td>
                    <td className="py-2 pr-3 text-gray-400">{h.matches_found ?? 0}</td>
                    <td className="py-2 pr-3 text-gray-400">{h.last_run_at ? new Date(h.last_run_at).toLocaleString() : '—'}</td>
                    <td className="py-2 pr-3">
                      <button
                        onClick={() => {
                          setSql(h.sql_query || h.query || '');
                          setName(h.name || 'SOC SQL Hunt');
                          setView('builder');
                        }}
                        className="text-xs px-2 py-1 rounded border border-[#00D4AA55] text-[#00D4AA]"
                      >
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatHuntingPage;

import React, { useEffect, useMemo, useState } from 'react';
import { Upload, FileArchive, RefreshCcw, BarChart3, Search, Table } from 'lucide-react';
import { API_BASE } from '../services/api';

type PcapFile = {
  source_id: string;
  name: string;
  raw_size: number;
  created_at: string;
};

type UploadSummary = {
  total_events: number;
  table_counts: Record<string, number>;
  protocol_distribution: Array<{ protocol: string; count: number }>;
};

type ActiveIngest = {
  source: { source_id: string; name: string };
  ingest: { status: string; message?: string; age_seconds?: number };
};

type UploadState = {
  active: boolean;
  progress: number;
  fileName: string;
};

const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const readJsonSafe = async (res: Response) => {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    const preview = text.slice(0, 120).replace(/\s+/g, ' ').trim();
    throw new Error(`API returned non-JSON response (${res.status}): ${preview || 'empty response'}`);
  }
};

const PcapUploadPage: React.FC<{
  onUploadComplete?: (source: { source_id: string; name: string; created_at: string }) => void;
  onOpenDashboard?: () => void;
  onOpenLogSearch?: () => void;
  onOpenTableExplorer?: () => void;
  activeIngest?: ActiveIngest | null;
  uploadState?: UploadState;
  onUploadFile?: (file: File) => Promise<any>;
}> = ({ onUploadComplete, onOpenDashboard, onOpenLogSearch, onOpenTableExplorer, activeIngest, uploadState, onUploadFile }) => {
  const [selected, setSelected] = useState<File | null>(null);
  const [files, setFiles] = useState<PcapFile[]>([]);
  const [message, setMessage] = useState<string>('');
  const [filePage, setFilePage] = useState(1);
  const pageSize = 10;

  const [uploadResult, setUploadResult] = useState<{
    sourceId?: string;
    sourceName?: string;
    ingestSuccess: boolean;
    ingestStatus?: string;
    ingestMessage: string;
    ingestUpdatedAt?: string;
    uploadedAt?: string;
    summary?: UploadSummary;
  } | null>(null);
  const uploading = !!uploadState?.active;
  const uploadProgress = uploadState?.progress ?? 0;
  const activeBlocked = (!!activeIngest && String(activeIngest.ingest?.status).toLowerCase() === 'processing') || uploading;

  const loadFiles = async () => {
    try {
      const res = await fetch(`${API_BASE}/logs/data-sources`);
      const data = await readJsonSafe(res);
      setFiles(Array.isArray(data?.sources) ? data.sources : []);
    } catch (e: any) {
      setMessage(e?.message || 'Failed to load PCAP files');
      setFiles([]);
    }
  };

  const loadSummary = async (
    sourceId: string,
  ): Promise<{ summary?: UploadSummary; ingest?: { status?: string; message?: string; tables?: Record<string, number>; updated_at?: string } }> => {
    try {
      const qs = new URLSearchParams({ source_id: sourceId });
      const summaryRes = await fetch(`${API_BASE}/logs/source-summary?${qs.toString()}`);
      const summaryData = await readJsonSafe(summaryRes);
      if (!summaryRes.ok) return {};
      return {
        summary: summaryData?.summary as UploadSummary,
        ingest: summaryData?.ingest as { status?: string; message?: string; tables?: Record<string, number>; updated_at?: string },
      };
    } catch {
      return {};
    }
  };

  const pollSummaryInBackground = async (sourceId: string, retry = 600) => {
    for (let i = 0; i < retry; i++) {
      const { summary, ingest } = await loadSummary(sourceId);
      if (summary || ingest) {
        setUploadResult((prev) => {
          if (!prev || prev.sourceId !== sourceId) return prev;
          return {
            ...prev,
            ingestStatus: ingest?.status || prev.ingestStatus,
            ingestMessage: ingest?.message || prev.ingestMessage,
            ingestUpdatedAt: ingest?.updated_at || prev.ingestUpdatedAt,
            summary: summary || prev.summary,
          };
        });
      }
      if (ingest?.status === 'ready' || ingest?.status === 'failed') return;
      await new Promise((r) => setTimeout(r, 1500));
    }
  };

  useEffect(() => {
    loadFiles();
  }, []);

  const pagedFiles = useMemo(() => {
    const start = (filePage - 1) * pageSize;
    return files.slice(start, start + pageSize);
  }, [files, filePage]);
  const filePageCount = Math.max(1, Math.ceil(files.length / pageSize));

  const upload = async () => {
    if (activeBlocked) {
      setMessage(`Another file is still processing: ${activeIngest?.source?.name || 'current source'}`);
      return;
    }
    if (!selected) return;
    setMessage('');
    setUploadResult(null);
    try {
      const data = await (onUploadFile
        ? onUploadFile(selected)
        : Promise.reject(new Error('Upload action unavailable')));
      const sourceId = data?.source?.source_id as string | undefined;
      const sourceName = data?.source?.name as string | undefined;
      const ingestSuccess = true;
      const ingestStatus = String(data?.ingest?.status || 'processing');
      const ingestMessage = String(data?.ingest?.message || '');

      const tables = (data?.ingest?.tables || {}) as Record<string, number>;
      const total = Object.values(tables).reduce((s, x) => s + Number(x || 0), 0);
      const summary: UploadSummary = { total_events: total, table_counts: tables, protocol_distribution: [] };

      setUploadResult({
        sourceId,
        sourceName,
        ingestSuccess,
        ingestStatus,
        ingestMessage,
        ingestUpdatedAt: new Date().toISOString(),
        uploadedAt: new Date().toISOString(),
        summary,
      });
      setMessage(`Uploaded: ${data.filename}`);
      if (sourceId) {
        void pollSummaryInBackground(sourceId);
      }
      setSelected(null);
      await loadFiles();
      setFilePage(1);
      if (onUploadComplete && data?.source) {
        onUploadComplete({
          source_id: data.source.source_id,
          name: data.source.name,
          created_at: data.source.created_at,
        });
      }
    } catch (e: any) {
      setMessage(e?.message || 'Upload failed');
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="bg-[#111113] border border-[#222] rounded-2xl p-6">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold text-white">PCAP Upload</h1>
            <p className="text-sm text-gray-400 mt-1">Upload `.pcap` or `.pcapng` files (preferably under 50 MB), then choose how to investigate.</p>
          </div>
          <button
            onClick={onOpenTableExplorer}
            className="inline-flex items-center gap-2 text-sm px-4 py-2 rounded-lg border border-[#00D4AA55] text-[#00D4AA] hover:bg-[#00D4AA10] font-semibold"
          >
            <Table size={15} /> Open Zeek Log Tables
          </button>
        </div>

        <div className="mt-5 flex flex-col sm:flex-row gap-3">
          <input
            type="file"
            accept=".pcap,.pcapng"
            disabled={activeBlocked}
            onChange={(e) => setSelected(e.target.files?.[0] || null)}
            className="block w-full text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-bold file:bg-[#00D4AA] file:text-black hover:file:bg-[#00c09a]"
          />
          <button
            onClick={upload}
            disabled={!selected || uploading || activeBlocked}
            className="px-4 py-2 rounded-lg text-sm font-bold bg-[#00D4AA] text-black hover:bg-[#00c09a] disabled:opacity-50"
          >
            <span className="inline-flex items-center gap-2">
              <Upload size={14} />
              {uploading ? 'Uploading...' : 'Upload'}
            </span>
          </button>
        </div>

        {uploading && (
          <div className="mt-3">
            <div className="flex items-center justify-between text-xs text-gray-400 mb-1">
              <span>Upload progress{uploadState?.fileName ? ` (${uploadState.fileName})` : ''}</span>
              <span>{uploadProgress}%</span>
            </div>
            <div className="h-2 w-full bg-[#1e1e22] rounded overflow-hidden">
              <div className="h-full bg-[#00D4AA] transition-all" style={{ width: `${uploadProgress}%` }} />
            </div>
          </div>
        )}

        {message && <p className="mt-3 text-xs text-gray-300">{message}</p>}
        {activeBlocked && (
          <p className="mt-2 text-xs text-amber-300">
            New upload is locked until current processing finishes: {activeIngest?.source?.name}
          </p>
        )}
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-2xl p-6">
        <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Upload Result</h2>
        {!uploadResult && (
          <p className="mt-3 text-sm text-gray-500">Upload a PCAP to see summary and quick actions.</p>
        )}

        {uploadResult && !uploadResult.ingestSuccess && (
          <div className="mt-3 rounded-xl border border-red-500/30 bg-red-500/10 p-4">
            <p className="text-xs uppercase tracking-wider text-red-300 font-semibold">Parsing Failed</p>
            <p className="mt-1 text-sm text-red-200">{uploadResult.ingestMessage || 'Unknown parsing error'}</p>
          </div>
        )}

        {uploadResult && uploadResult.ingestSuccess && (
          <div className="mt-3 space-y-3">
            {uploadResult.ingestStatus !== 'ready' && (
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3">
                <p className="text-xs text-amber-300">
                  Parsing in progress. Large files can take several minutes. Status updates automatically.
                </p>
                {uploadResult.ingestUpdatedAt && (
                  <p className="text-[11px] text-amber-200/80 mt-1">
                    Last update: {new Date(uploadResult.ingestUpdatedAt).toLocaleTimeString()}
                  </p>
                )}
              </div>
            )}
            {uploadResult.ingestStatus === 'failed' && (
              <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3">
                <p className="text-xs text-red-300">{uploadResult.ingestMessage || 'Parsing failed.'}</p>
              </div>
            )}
            <div
              className={`rounded-xl p-4 ${
                uploadResult.ingestStatus === 'ready'
                  ? 'border border-[#00D4AA33] bg-[#00D4AA0f]'
                  : uploadResult.ingestStatus === 'failed'
                  ? 'border border-red-500/30 bg-red-500/10'
                  : 'border border-amber-500/30 bg-amber-500/10'
              }`}
            >
              <p
                className={`text-xs uppercase tracking-wider font-semibold ${
                  uploadResult.ingestStatus === 'ready'
                    ? 'text-[#00D4AA]'
                    : uploadResult.ingestStatus === 'failed'
                    ? 'text-red-300'
                    : 'text-amber-300'
                }`}
              >
                {uploadResult.ingestStatus === 'ready'
                  ? 'PCAP Parsed'
                  : uploadResult.ingestStatus === 'failed'
                  ? 'PCAP Parse Failed'
                  : 'PCAP Parsing'}
              </p>
              <p className="mt-1 text-sm text-gray-200">
                Source: <span className="font-semibold">{uploadResult.sourceName || uploadResult.sourceId}</span> ·
                Total events: <span className="font-semibold">{uploadResult.summary?.total_events ?? 'N/A'}</span>
              </p>
              <p className="mt-1 text-xs text-gray-400">
                Protocols:{' '}
                {uploadResult.summary?.protocol_distribution?.length
                  ? uploadResult.summary.protocol_distribution.slice(0, 5).map((p) => `${p.protocol}: ${p.count}`).join(', ')
                  : 'Not available yet'}
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                onClick={onOpenDashboard}
                className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-[#00D4AA55] text-[#00D4AA] hover:bg-[#00D4AA10] text-sm font-semibold"
              >
                <BarChart3 size={14} /> Log Dashboard
              </button>
              <button
                onClick={onOpenLogSearch}
                className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-[#2d2d35] text-gray-200 hover:bg-white/5 text-sm font-semibold"
              >
                <Search size={14} /> SQL Query / Log Search
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="bg-[#111113] border border-[#222] rounded-2xl p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-wider text-gray-400">Uploaded Files (History)</h2>
          <button onClick={loadFiles} className="text-xs text-gray-300 hover:text-white inline-flex items-center gap-1">
            <RefreshCcw size={12} /> Refresh
          </button>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-[#222]">
                <th className="py-2 pr-3">File</th>
                <th className="py-2 pr-3">Size</th>
                <th className="py-2 pr-3">Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {files.length === 0 && (
                <tr>
                  <td className="py-4 text-gray-500" colSpan={3}>No PCAP files uploaded yet.</td>
                </tr>
              )}
              {pagedFiles.map((f) => (
                <tr key={f.source_id} className="border-b border-[#1a1a1a]">
                  <td className="py-2 pr-3 text-gray-200">
                    <span className="inline-flex items-center gap-2"><FileArchive size={14} /> {f.name}</span>
                  </td>
                  <td className="py-2 pr-3 text-gray-400">{fmtBytes(f.raw_size)}</td>
                  <td className="py-2 pr-3 text-gray-400">{new Date(f.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {files.length > pageSize && (
          <div className="mt-3 flex items-center justify-end gap-2">
            <button
              onClick={() => setFilePage((p) => Math.max(1, p - 1))}
              disabled={filePage <= 1}
              className="px-3 py-1.5 text-xs rounded border border-[#333] disabled:opacity-50"
            >
              Previous
            </button>
            <span className="text-xs text-gray-500">Page {filePage} / {filePageCount}</span>
            <button
              onClick={() => setFilePage((p) => Math.min(filePageCount, p + 1))}
              disabled={filePage >= filePageCount}
              className="px-3 py-1.5 text-xs rounded border border-[#333] disabled:opacity-50"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default PcapUploadPage;

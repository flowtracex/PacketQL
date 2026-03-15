import React, { useState } from 'react';
import Sidebar, { PageId } from './components/layout/Sidebar';
import TopNav from './components/layout/TopNav';
import PlatformNav from './components/layout/PlatformNav';
import PcapUploadPage from './pages/PcapUploadPage';
import LogSearchPage, { LogSearchPrefill } from './pages/LogSearchPage';
import LogDashboardPage from './pages/LogDashboardPage';
import ThreatHuntingPage from './pages/ThreatHuntingPage';
import TableExplorerModal from './components/common/TableExplorerModal';
import HowItWorksModal from './components/common/HowItWorksModal';
import AISQLAssistantModal from './components/common/AISQLAssistantModal';
import PipelineHealthPage from './pages/PipelineHealthPage';
import { API_BASE } from './services/api';
import { CONFIG } from './config';

type DataSource = {
  source_id: string;
  name: string;
  created_at: string;
  updated_at?: string;
};

type ActiveIngest = {
  source: {
    source_id: string;
    name: string;
  };
  ingest: {
    status: string;
    message: string;
    tables?: Record<string, number>;
    updated_at?: string;
    age_seconds?: number;
  };
};

type RecentIngest = {
  source_id: string;
  name: string;
  ingest_status?: string;
  ingest_message?: string;
  updated_at?: string;
  ingest_tables?: Record<string, number>;
};

type UploadState = {
  active: boolean;
  progress: number;
  fileName: string;
};

const App: React.FC = () => {
  const isReadOnlyDemo = CONFIG.APP_MODE === 'demo';
  const [activePage, setActivePage] = useState<PageId>('pcap-upload');
  const [searchPrefill, setSearchPrefill] = useState<LogSearchPrefill>({});
  const [searchPrefillVersion, setSearchPrefillVersion] = useState(0);
  const [sources, setSources] = useState<DataSource[]>([]);
  const [currentSource, setCurrentSource] = useState<DataSource | null>(null);
  const [showTableExplorer, setShowTableExplorer] = useState(false);
  const [showHowItWorks, setShowHowItWorks] = useState(false);
  const [showAISQLAssistant, setShowAISQLAssistant] = useState(false);
  const [activeIngest, setActiveIngest] = useState<ActiveIngest | null>(null);
  const [recentIngest, setRecentIngest] = useState<RecentIngest | null>(null);
  const [dismissedRecentId, setDismissedRecentId] = useState<string | null>(null);
  const [uploadState, setUploadState] = useState<UploadState>({ active: false, progress: 0, fileName: '' });

  const loadSources = async () => {
    try {
      const [listRes, currentRes] = await Promise.all([
        fetch(`${API_BASE}/logs/data-sources`),
        fetch(`${API_BASE}/logs/current-source`),
      ]);
      const [listData, currentData] = await Promise.all([listRes.json(), currentRes.json()]);
      setSources(Array.isArray(listData?.sources) ? listData.sources : []);
      setCurrentSource(currentData?.current || null);
    } catch {
      setSources([]);
      setCurrentSource(null);
    }
  };

  React.useEffect(() => {
    loadSources();
  }, []);

  const loadIngestStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/logs/ingest-status`);
      const data = await res.json();
      const nextActive = data?.has_active ? (data.active as ActiveIngest) : null;
      setActiveIngest(nextActive);
      setRecentIngest((data?.recent as RecentIngest) || null);
      if (nextActive?.source?.source_id) {
        const activeSourceId = String(nextActive.source.source_id);
        setCurrentSource((prev) => {
          if (prev?.source_id === activeSourceId) return prev;
          return {
            source_id: activeSourceId,
            name: String(nextActive.source.name || activeSourceId),
            created_at: new Date().toISOString(),
          };
        });
      }
    } catch {
      setActiveIngest(null);
      setRecentIngest(null);
    }
  };

  React.useEffect(() => {
    loadIngestStatus();
    const id = setInterval(loadIngestStatus, 2000);
    return () => clearInterval(id);
  }, []);

  const switchSource = async (sourceId: string) => {
    try {
      const res = await fetch(`${API_BASE}/logs/current-source`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source_id: sourceId }),
      });
      const data = await res.json();
      setCurrentSource(data?.current || null);
      await loadSources();
    } catch {
      // no-op
    }
  };

  const openLogSearch = (prefill: LogSearchPrefill = {}) => {
    setSearchPrefill(prefill);
    setSearchPrefillVersion((v) => v + 1);
    setActivePage('logs-search');
  };

  const resetAllData = async () => {
    const ok = window.confirm(
      'This will permanently delete all uploaded PCAP files and derived data (Parquet/work). Continue?',
    );
    if (!ok) return;
    try {
      const res = await fetch(`${API_BASE}/logs/reset-data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'Reset failed');
      setCurrentSource(null);
      setSources([]);
      setSearchPrefill({});
      setSearchPrefillVersion((v) => v + 1);
      setActivePage('pcap-upload');
      await loadSources();
      window.alert('All uploaded data has been reset.');
    } catch (e: any) {
      window.alert(e?.message || 'Failed to reset data');
    }
  };

  const uploadPcapWithProgress = (file: File): Promise<any> =>
    new Promise((resolve, reject) => {
      if (uploadState.active) {
        reject(new Error('Another upload is already in progress.'));
        return;
      }

      const xhr = new XMLHttpRequest();
      const form = new FormData();
      form.append('file', file);

      setUploadState({ active: true, progress: 0, fileName: file.name });
      xhr.open('POST', `${API_BASE}/logs/upload-pcap`, true);
      xhr.upload.onprogress = (evt) => {
        if (!evt.lengthComputable) return;
        const pct = Math.round((evt.loaded / evt.total) * 100);
        setUploadState((prev) => ({ ...prev, progress: Math.min(100, Math.max(0, pct)) }));
      };
      xhr.onerror = () => {
        setUploadState({ active: false, progress: 0, fileName: '' });
        reject(new Error('Network upload failed'));
      };
      xhr.onload = () => {
        const text = xhr.responseText || '';
        let payload: any = {};
        try {
          payload = text ? JSON.parse(text) : {};
        } catch {
          setUploadState({ active: false, progress: 0, fileName: '' });
          const preview = text.slice(0, 140).replace(/\s+/g, ' ').trim();
          reject(new Error(`API returned non-JSON response (${xhr.status}): ${preview || 'empty response'}`));
          return;
        }
        if (xhr.status < 200 || xhr.status >= 300) {
          setUploadState({ active: false, progress: 0, fileName: '' });
          reject(new Error(payload?.error || payload?.message || `Upload failed (${xhr.status})`));
          return;
        }
        setUploadState((prev) => ({ ...prev, progress: 100 }));
        setTimeout(() => setUploadState({ active: false, progress: 0, fileName: '' }), 400);
        resolve(payload);
      };
      xhr.send(form);
    });

  const renderContent = () => {
    const effectiveSourceId = activeIngest?.source?.source_id || currentSource?.source_id;
    switch (activePage) {
      case 'pcap-upload':
        return (
          <PcapUploadPage
            demoReadOnly={isReadOnlyDemo}
            onUploadComplete={(source) => {
              setCurrentSource(source);
              loadSources();
            }}
            onOpenDashboard={() => setActivePage('logs-dashboard')}
            onOpenLogSearch={() => setActivePage('logs-search')}
            onOpenTableExplorer={() => setShowTableExplorer(true)}
            activeIngest={activeIngest}
            uploadState={uploadState}
            onUploadFile={uploadPcapWithProgress}
          />
        );
      case 'logs-search':
        return <LogSearchPage prefill={searchPrefill} prefillVersion={searchPrefillVersion} currentSourceId={effectiveSourceId} onOpenTableExplorer={() => setShowTableExplorer(true)} ingestActive={!!activeIngest} />;
      case 'logs-dashboard':
        return <LogDashboardPage onDrillDown={openLogSearch} currentSourceId={effectiveSourceId} onOpenTableExplorer={() => setShowTableExplorer(true)} ingestActive={!!activeIngest} />;
      case 'pipeline-health':
        return <PipelineHealthPage currentSourceId={effectiveSourceId} ingestActive={!!activeIngest} />;
      case 'threat-hunting-builder':
        return <ThreatHuntingPage key="threat-hunting-builder" defaultView="builder" currentSourceId={effectiveSourceId} />;
      case 'threat-hunting-history':
        return <ThreatHuntingPage key="threat-hunting-history" defaultView="history" currentSourceId={effectiveSourceId} />;
      default:
        return (
          <PcapUploadPage
            demoReadOnly={isReadOnlyDemo}
            onUploadComplete={(source) => {
              setCurrentSource(source);
              loadSources();
            }}
            onOpenDashboard={() => setActivePage('logs-dashboard')}
            onOpenLogSearch={() => setActivePage('logs-search')}
            onOpenTableExplorer={() => setShowTableExplorer(true)}
            activeIngest={activeIngest}
            uploadState={uploadState}
            onUploadFile={uploadPcapWithProgress}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-[#f5f7fa] selection:bg-[#38bdf8]/30">
      <PlatformNav
        onNavigate={(page) => setActivePage(page as PageId)}
        currentSource={currentSource}
        sources={sources}
        onSourceChange={switchSource}
        onResetData={isReadOnlyDemo ? undefined : resetAllData}
        onOpenHowItWorks={() => setShowHowItWorks(true)}
        onOpenAISQLAssistant={() => setShowAISQLAssistant(true)}
        readOnlyDemo={isReadOnlyDemo}
      />
      <Sidebar activePage={activePage} onPageChange={setActivePage} />
      <TopNav />
      <div className="ml-64 px-8 pt-3">
        <div className="rounded-xl border border-[#2a2a2f] bg-[#111113] px-4 py-2.5 text-xs flex flex-wrap items-center gap-3">
          <span className="text-gray-500 uppercase tracking-wider font-bold">Current Source</span>
          <span className="text-gray-200 font-semibold">{currentSource?.name || 'No source selected'}</span>
          {currentSource?.created_at && (
            <span className="text-gray-400">
              Uploaded: {new Date(currentSource.created_at).toLocaleString()}
            </span>
          )}
          {(currentSource?.updated_at || activeIngest?.ingest?.updated_at) && (
            <span className="text-gray-400">
              Last Processed: {new Date(String(currentSource?.updated_at || activeIngest?.ingest?.updated_at)).toLocaleString()}
            </span>
          )}
        </div>
      </div>
      {uploadState.active && (
        <div className="ml-64 px-8 pt-3">
          <div className="rounded-xl border border-sky-500/40 bg-sky-500/10 px-4 py-2.5 text-xs">
            <div className="flex items-center justify-between mb-1">
              <span className="text-sky-300 font-semibold">Uploading PCAP: {uploadState.fileName}</span>
              <span className="text-sky-200">{uploadState.progress}%</span>
            </div>
            <div className="h-2 w-full bg-[#10131a] rounded overflow-hidden">
              <div className="h-full bg-sky-400 transition-all" style={{ width: `${uploadState.progress}%` }} />
            </div>
          </div>
        </div>
      )}
      {activeIngest && (
        <div className="ml-64 px-8 pt-3">
          <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-xs">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-amber-300 font-semibold">Processing:</span>
              <span className="text-amber-200">{activeIngest.source.name}</span>
              <span className="text-amber-300/80">Stage: {activeIngest.ingest.message || 'processing'}</span>
              <span className="text-amber-300/80">Last update: {activeIngest.ingest.age_seconds ?? 0}s ago</span>
              {activeIngest.ingest.tables && Object.keys(activeIngest.ingest.tables).length > 0 && (
                <span className="text-amber-200 font-semibold">
                  Rows parsed: {Object.values(activeIngest.ingest.tables).reduce((s, x) => s + Number(x || 0), 0)}
                </span>
              )}
            </div>
            <div className="mt-2 h-2 w-full bg-[#2b210f] rounded overflow-hidden">
              <div className="h-full w-full bg-amber-400/80 animate-pulse" />
            </div>
          </div>
        </div>
      )}
      {!activeIngest && recentIngest && recentIngest.source_id !== dismissedRecentId && (
        <div className="ml-64 px-8 pt-3">
          <div
            className={`rounded-xl px-4 py-2.5 flex flex-wrap items-center gap-3 text-xs ${
              String(recentIngest.ingest_status).toLowerCase() === 'ready'
                ? 'border border-emerald-500/40 bg-emerald-500/10'
                : 'border border-red-500/40 bg-red-500/10'
            }`}
          >
            <span
              className={`font-semibold ${
                String(recentIngest.ingest_status).toLowerCase() === 'ready' ? 'text-emerald-300' : 'text-red-300'
              }`}
            >
              {String(recentIngest.ingest_status).toLowerCase() === 'ready' ? 'Processing Completed:' : 'Processing Failed:'}
            </span>
            <span className="text-gray-200">{recentIngest.name}</span>
            {recentIngest.ingest_message && <span className="text-gray-300">{recentIngest.ingest_message}</span>}
            <button
              onClick={() => setDismissedRecentId(recentIngest.source_id)}
              className="ml-auto text-[11px] px-2 py-1 rounded border border-white/20 hover:bg-white/10"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}
      <main className="ml-64 p-8 pb-16">{renderContent()}</main>
      {showTableExplorer && (
        <TableExplorerModal
          sourceId={currentSource?.source_id}
          sourceName={currentSource?.name}
          onClose={() => setShowTableExplorer(false)}
        />
      )}
      {showHowItWorks && <HowItWorksModal onClose={() => setShowHowItWorks(false)} />}
      {showAISQLAssistant && <AISQLAssistantModal onClose={() => setShowAISQLAssistant(false)} />}
    </div>
  );
};

export default App;

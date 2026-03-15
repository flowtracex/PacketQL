import React from 'react';

interface PlatformNavProps {
  onNavigate?: (page: string) => void;
  currentSource?: { source_id: string; name: string; created_at: string; updated_at?: string } | null;
  sources?: Array<{ source_id: string; name: string; created_at: string; updated_at?: string }>;
  onSourceChange?: (sourceId: string) => void;
  onResetData?: () => void;
  onOpenHowItWorks?: () => void;
  onOpenAISQLAssistant?: () => void;
  readOnlyDemo?: boolean;
}

const PlatformNav: React.FC<PlatformNavProps> = ({ currentSource, sources = [], onSourceChange, onResetData, onOpenHowItWorks, onOpenAISQLAssistant, readOnlyDemo = false }) => {
  return (
    <div className="h-14 bg-[#0f0f10] border-b border-[#242428] flex items-center justify-between px-6 sticky top-0 z-[60]">
      <div className="flex items-center gap-4">
        <img src="/images/logo-white.png" alt="PCAPQL" className="h-5 w-auto" />
        <span className="text-lg font-extrabold tracking-wide text-white">
          PacketQL
        </span>
        {readOnlyDemo && (
          <span className="rounded-full border border-[#38bdf855] bg-[#38bdf810] px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.18em] text-[#7dd3fc]">
            Public Demo
          </span>
        )}
      </div>

      <div className="flex items-center gap-3">
        {onOpenAISQLAssistant && (
          <button
            onClick={onOpenAISQLAssistant}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg border border-[#38bdf855] text-[#38bdf8] hover:bg-[#38bdf810] transition-all"
          >
            AI SQL Assistant
          </button>
        )}
        {onOpenHowItWorks && (
          <button
            onClick={onOpenHowItWorks}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg border border-[#00D4AA55] text-[#00D4AA] hover:bg-[#00D4AA10] transition-all"
          >
            How It Works
          </button>
        )}
        <div className="flex items-center gap-2 text-xs">
          <span className="text-gray-500 uppercase tracking-wider font-bold">Select Source</span>
          <select
            value={currentSource?.source_id || ''}
            onChange={(e) => onSourceChange && onSourceChange(e.target.value)}
            className="bg-[#141416] border border-[#2e2e33] rounded px-2 py-1 text-xs text-gray-200"
          >
            <option value="" disabled>{sources.length ? 'Select source' : 'No sources'}</option>
            {sources.map((s) => (
              <option key={s.source_id} value={s.source_id}>{s.name}</option>
            ))}
          </select>
        </div>
        {onResetData && (
          <button
            onClick={onResetData}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg border border-red-500/40 text-red-300 hover:bg-red-500/10 transition-all"
          >
            Reset Data
          </button>
        )}
      </div>
    </div>
  );
};

export default PlatformNav;

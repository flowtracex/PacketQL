import React from 'react';

interface PlatformNavProps {
  onNavigate?: (page: string) => void;
}

const PlatformNav: React.FC<PlatformNavProps> = ({ onNavigate }) => {
  return (
    <div className="h-14 bg-[#0a0a0c] border-b border-[#1e1e20] flex items-center justify-between px-6 sticky top-0 z-[60]">
      <div className="flex items-center gap-4">
        <img src="/images/logo-white.png" alt="PCAPQL" className="h-8 w-auto" />
        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">
          SOC Packet Investigation
        </span>
      </div>

      <div className="flex items-center gap-3">
        {onNavigate && (
          <button
            onClick={() => onNavigate('logs-search')}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg text-gray-300 hover:text-white hover:bg-white/5 transition-all"
          >
            Search
          </button>
        )}
        {onNavigate && (
          <button
            onClick={() => onNavigate('threat-hunting-builder')}
            className="text-xs font-semibold px-3 py-1.5 rounded-lg text-black bg-[#00D4AA] hover:bg-[#00c09a] transition-all"
          >
            SQL Query
          </button>
        )}
      </div>
    </div>
  );
};

export default PlatformNav;

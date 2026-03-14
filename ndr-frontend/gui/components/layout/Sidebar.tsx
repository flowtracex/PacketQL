import React from 'react';
import { Search, Database, History } from 'lucide-react';

export type PageId =
  | 'logs-search'
  | 'logs-analytics'
  | 'threat-hunting-builder'
  | 'threat-hunting-history';

interface SidebarProps {
  activePage: PageId;
  onPageChange: (id: PageId) => void;
}

const itemClass = (active: boolean) =>
  `w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${
    active ? 'bg-[#00D4AA10] text-[#00D4AA]' : 'text-gray-400 hover:text-white hover:bg-white/5'
  }`;

const Sidebar: React.FC<SidebarProps> = ({ activePage, onPageChange }) => {
  return (
    <aside className="w-64 flex flex-col h-[calc(100vh-3.5rem)] bg-[#111113] border-r border-[#222] fixed left-0 top-14 z-50">
      <nav className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
        <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 px-2">PCAPQL</div>

        <button
          onClick={() => onPageChange('logs-search')}
          className={itemClass(activePage === 'logs-search')}
        >
          <Search size={16} />
          <span className="font-semibold">Log Search</span>
        </button>

        <button
          onClick={() => onPageChange('logs-analytics')}
          className={itemClass(activePage === 'logs-analytics')}
        >
          <Database size={16} />
          <span className="font-semibold">Log Analytics</span>
        </button>

        <button
          onClick={() => onPageChange('threat-hunting-builder')}
          className={itemClass(activePage === 'threat-hunting-builder')}
        >
          <Database size={16} />
          <span className="font-semibold">SQL Query</span>
        </button>

        <button
          onClick={() => onPageChange('threat-hunting-history')}
          className={itemClass(activePage === 'threat-hunting-history')}
        >
          <History size={16} />
          <span className="font-semibold">Saved Queries</span>
        </button>
      </nav>
    </aside>
  );
};

export default Sidebar;

import React, { useState } from 'react';
import Sidebar, { PageId } from './components/layout/Sidebar';
import TopNav from './components/layout/TopNav';
import PlatformNav from './components/layout/PlatformNav';
import LogsPage from './pages/LogsPage';
import ThreatHuntingPage from './pages/ThreatHuntingPage';

const App: React.FC = () => {
  const [activePage, setActivePage] = useState<PageId>('logs-search');

  const renderContent = () => {
    switch (activePage) {
      case 'logs-search':
        return <LogsPage key="logs-search" defaultView="search" allowedViews={['search', 'live']} />;
      case 'logs-analytics':
        return <LogsPage key="logs-analytics" defaultView="stats" allowedViews={['stats']} />;
      case 'threat-hunting-builder':
        return <ThreatHuntingPage key="threat-hunting-builder" defaultView="builder" />;
      case 'threat-hunting-history':
        return <ThreatHuntingPage key="threat-hunting-history" defaultView="history" />;
      default:
        return <LogsPage key="logs-search-default" defaultView="search" allowedViews={['search', 'live']} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-[#fafafa] selection:bg-[#00D4AA]/30">
      <PlatformNav onNavigate={(page) => setActivePage(page as PageId)} />
      <Sidebar activePage={activePage} onPageChange={setActivePage} />
      <TopNav />
      <main className="ml-64 p-8 pb-16">{renderContent()}</main>
    </div>
  );
};

export default App;

import React, { useState, useMemo, useEffect } from 'react';
import {
  Search, Play, ChevronRight, Target, Layers, Zap, Shield,
  ArrowRight, Download, Activity, Calendar, Plus, X,
  Compass, Clock, Filter, Database, Globe, Monitor,
  MoreVertical, ArrowLeft, Info, Trash2, ChevronDown,
  Lock, CheckCircle2, AlertTriangle, Fingerprint, TrendingUp,
  ExternalLink, Save, HelpCircle, FileText, RefreshCcw,
  ArrowUpRight, Maximize2, Send, Sparkles, History as HistoryIcon,
  Smartphone, User, ShieldAlert, Brain,
  Terminal, Copy, ShieldCheck, Workflow, Tag, Minus, Link, Eye, Edit
} from 'lucide-react';
import {
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import { getLogSources, getAllVisibleFields, getFieldsForSource } from '../constants/fieldCatalogUtils';
import SchemaExplorer from '../components/common/SchemaExplorer';
import { QUERY_OPERATORS, TIME_RANGES } from '../constants/config';
import { CONFIG } from '../config';
import { huntApi } from '../services/api';

// --- Interfaces ---

interface Condition {
  id: string;
  field: string;
  operator: string;
  value: string;
}

interface LogicGroup {
  id: string;
  source: string;
  conditions: Condition[];
}

interface Hunt {
  id: string;
  name: string;
  hypothesis: string;
  type: 'visual' | 'sql';
  logSource: string;
  sqlQuery?: string;
  conditions: Condition[];
  dataSources: string[];
  timeRange: string;
  status: 'running' | 'completed' | 'failed';
  createdAt: string;
  lastRunAt?: string;
  completedAt?: string;
  duration: number;
  dataProcessed: number;
  matchesFound: number;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  topFinding: string;
  stages: number[];
  author: string;
}

interface HuntResult {
  matchId: number;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  suspiciousness: number;
  category: string;
  sourceIP: string;
  destIP: string;
  sourceHostname: string;
  destHostname: string;
  destCountry: string;
  destFlag: string;
  matchReasons: string[];
  details: {
    duration: string;
    connections: number;
    dataTransferred: string;
    firstSeen: string;
    lastSeen: string;
  };
  assetContext: {
    hostname: string;
    type: string;
    owner: string;
    riskScore: number;
  };
  threatIntel: {
    reputation: string;
    category: string;
    malware: string;
    firstReported: string;
  };
  relatedDetections: Array<{
    id: string;
    title: string;
  }>;
  timeline: Array<{ time: string; count: number }>;
}

// --- Constants ---

// Log sources now come from zeek_field_catalog.json
const LOG_SOURCE_NAMES = getLogSources();


const ThreatHuntingPage: React.FC<{ defaultView?: 'builder' | 'history' | 'detail' | 'results' | 'findings' }> = ({ defaultView = 'history' }) => {
  const [view, setView] = useState<'builder' | 'history' | 'detail' | 'results' | 'findings'>(defaultView);
  const [selectedHunt, setSelectedHunt] = useState<Hunt | null>(null);
  const [huntMode, setHuntMode] = useState('sql');
  const [lockedHuntMode, setLockedHuntMode] = useState<'visual' | 'sql' | null>(null);
  const [findingsSidebarOpen, setFindingsSidebarOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Builder inline results
  const [builderResults, setBuilderResults] = useState<any[] | null>(null);
  const [builderDrawerGroup, setBuilderDrawerGroup] = useState<{ key: string; rows: any[] } | null>(null);
  const [builderRunning, setBuilderRunning] = useState(false);
  const [builderQuery, setBuilderQuery] = useState('');

  // UID detail drawer
  const [uidDrawerOpen, setUidDrawerOpen] = useState(false);
  const [uidDrawerData, setUidDrawerData] = useState<{ table: string; uid: string; fields: Record<string, any> } | null>(null);
  const [uidDrawerLoading, setUidDrawerLoading] = useState(false);

  const handleUidClick = async (uid: string) => {
    // Navigate to log search page with UID filter
    window.location.href = `/logs-search?search=${encodeURIComponent(uid)}`;
  };

  // Detect if a column name looks like a UID
  const isUidColumn = (key: string) => key === 'uid' || key.endsWith('_uid');

  // Detect which log source a column belongs to (for multi-log coloring)
  const getColumnSource = (key: string): string | null => {
    const prefixes = ['conn_', 'dns_', 'http_', 'ssh_', 'ssl_', 'ftp_', 'smtp_'];
    for (const p of prefixes) {
      if (key.startsWith(p)) return p.replace('_', '');
    }
    return null;
  };

  const sourceColors: Record<string, string> = {
    conn: 'text-blue-400',
    dns: 'text-emerald-400',
    http: 'text-amber-400',
    ssh: 'text-red-400',
    ssl: 'text-purple-400',
  };

  const sourceBorderColors: Record<string, string> = {
    conn: 'border-blue-500/30',
    dns: 'border-emerald-500/30',
    http: 'border-amber-500/30',
    ssh: 'border-red-500/30',
    ssl: 'border-purple-500/30',
  };

  // Hunt History State
  const [hunts, setHunts] = useState<Hunt[]>([]);
  const [historyPage, setHistoryPage] = useState(1);
  const HUNTS_PER_PAGE = 10;
  const [historySearch, setHistorySearch] = useState('');
  const [historySourceFilter, setHistorySourceFilter] = useState('all');
  const [editingHuntId, setEditingHuntId] = useState<string | null>(null);

  // Fetch hunts from API on mount
  useEffect(() => {
    (async () => {
      try {
        const response = await huntApi.list({ limit: 100 });
        if (response && response.hunts && response.hunts.length > 0) {
          // Map API response to Hunt interface
          const detectLogSources = (sql: string): string[] => {
            if (!sql) return [];
            const tables = new Set<string>();
            const fromMatch = sql.match(/\bFROM\s+(\w+)/gi);
            const joinMatch = sql.match(/\bJOIN\s+(\w+)/gi);
            if (fromMatch) fromMatch.forEach(m => tables.add(m.replace(/^FROM\s+/i, '').toLowerCase()));
            if (joinMatch) joinMatch.forEach(m => tables.add(m.replace(/^JOIN\s+/i, '').toLowerCase()));
            return Array.from(tables);
          };

          const apiHunts: Hunt[] = response.hunts.map((h: any) => {
            const sqlSources = detectLogSources(h.sql_query || h.query || '');
            const sources = sqlSources.length > 0 ? sqlSources : [h.log_source || 'conn'];
            const displaySource = sources.length > 1 ? sources.join('+') : sources[0];
            return {
              id: String(h.id),
              name: h.name || '',
              hypothesis: h.hypothesis || h.description || '',
              type: h.type || 'visual',
              logSource: displaySource,
              sqlQuery: h.sql_query || h.query || '',
              conditions: (h.conditions || []).map((c: any, i: number) => ({ id: String(i + 1), field: c.field || '', operator: c.operator || '==', value: c.value || '' })),
              dataSources: sources,
              timeRange: h.time_range || 'Last 24h',
              status: h.status || 'completed',
              createdAt: h.created_at || '',
              lastRunAt: h.last_run_at || undefined,
              duration: h.duration || 0,
              dataProcessed: h.data_processed || 0,
              matchesFound: h.matches_found || 0,
              confidence: h.confidence || 'LOW',
              topFinding: '',
              stages: sources.length > 1 ? sources.map((_, i) => i + 1) : [1],
              author: typeof h.author === 'string' ? h.author : (h.author?.username || 'Unknown')
            };
          });
          setHunts(apiHunts);
          console.log('[API] Loaded', apiHunts.length, 'hunts from production API');
        }
      } catch (e) {
        console.error('[API] Hunt fetch failed, showing empty list.');
        setHunts([]);
      }
    })();
  }, []);


  // Builder State
  const [huntName, setHuntName] = useState('');
  const [hypothesis, setHypothesis] = useState('');
  const [timeRange, setTimeRange] = useState('Last 24 hours');
  const [severity, setSeverity] = useState<'critical' | 'high' | 'medium' | 'low'>('high');
  const [selectedSources, setSelectedSources] = useState<string[]>(['flow', 'dns', 'http', 'tls']);

  // Logic Groups State
  const [logicGroups, setLogicGroups] = useState<LogicGroup[]>([
    {
      id: 'lb1', source: 'conn.log', conditions: [
        { id: 'c1', field: '', operator: 'EQUAL', value: '' }
      ]
    }
  ]);

  // Threshold State
  const [thresholdHits, setThresholdHits] = useState(5);
  const [thresholdWindow, setThresholdWindow] = useState(5);
  const [thresholdUnit, setThresholdUnit] = useState('MINUTES');
  const [thresholdField, setThresholdField] = useState('source.ip');

  // Group-By State (Visual Builder)
  const [groupByEnabled, setGroupByEnabled] = useState(false);
  const [groupByField, setGroupByField] = useState('');
  const [havingThreshold, setHavingThreshold] = useState(5);

  // SQL State
  const [sqlQuery, setSqlQuery] = useState("SELECT src_ip, COUNT(*) AS hits\nFROM dns\nWHERE ts > now() - INTERVAL '5 minutes'\nGROUP BY src_ip\nHAVING COUNT(*) > 10;");

  const [expandedTables, setExpandedTables] = useState(['dns', 'http']);
  const [selectedField, setSelectedField] = useState(null);



  const getValidConditions = (conditions: Condition[] = []) =>
    conditions
      .map(c => ({
        field: (c.field || '').trim(),
        operator: c.operator,
        value: (c.value || '').trim()
      }))
      .filter(c => c.field && c.value);

  // Run hunt WITHOUT saving — just preview results inline in builder
  const handleRunNewHunt = async () => {
    setBuilderRunning(true);
    setBuilderResults(null);

    const logSource = logicGroups[0]?.source?.replace('.log', '') || 'conn';
    const conditions = getValidConditions(logicGroups[0]?.conditions || []);

    try {
      const runResult = await huntApi.run({
        hunt_id: '',
        query_type: huntMode as 'sql' | 'visual',
        query: sqlQuery,
        log_source: logSource,
        conditions: conditions,
        ...(huntMode === 'visual' && groupByEnabled && groupByField ? {
          group_by: groupByField,
          having_threshold: havingThreshold
        } : {})
      });
      setBuilderResults(runResult?.results || []);
      setBuilderQuery(runResult?.query || sqlQuery);
    } catch (e) {
      console.error('Run failed:', e);
      setBuilderResults([]);
    } finally {
      setBuilderRunning(false);
    }
  };

  // Save hunt to history AFTER previewing results
  const handleSaveHunt = async () => {
    const newHunt = {
      name: huntName || `New ${huntMode === 'visual' ? 'Visual' : 'SQL'} Hunt`,
      hypothesis: hypothesis,
      type: huntMode,
      log_source: logicGroups[0]?.source?.replace('.log', '') || 'conn',
      sql_query: sqlQuery,
      conditions: getValidConditions(logicGroups[0]?.conditions || []),
      time_range: timeRange,
      status: 'completed'
    };

    try {
      const savedHunt = await huntApi.save(newHunt);
      if (!savedHunt || !savedHunt.id) throw new Error('Save failed');

      // Run to create a HuntResult entry
      const runResult = await huntApi.run({
        hunt_id: String(savedHunt.id),
        query_type: newHunt.type as 'sql' | 'visual',
        query: newHunt.sql_query,
        log_source: newHunt.log_source,
        conditions: newHunt.conditions,
        ...(newHunt.type === 'visual' && groupByEnabled && groupByField ? {
          group_by: groupByField,
          having_threshold: havingThreshold
        } : {})
      });

      const realHunt: Hunt = {
        id: String(savedHunt.id),
        name: newHunt.name,
        hypothesis: newHunt.hypothesis,
        type: newHunt.type as 'visual' | 'sql',
        logSource: newHunt.log_source,
        sqlQuery: newHunt.sql_query,
        conditions: logicGroups[0]?.conditions || [],
        dataSources: [newHunt.log_source],
        timeRange: newHunt.time_range,
        status: 'completed',
        createdAt: new Date().toISOString(),
        lastRunAt: new Date().toISOString(),
        duration: parseFloat(runResult?.executionTime) || 0,
        matchesFound: runResult?.total || 0,
        dataProcessed: 0,
        confidence: 'LOW',
        topFinding: '',
        stages: [1],
        author: 'Analyst'
      };

      setHunts(prev => [realHunt, ...prev]);
      setBuilderResults(null);
      setLockedHuntMode(null);
      setView('history');
    } catch (e) {
      console.error('Save failed:', e);
    }
  };

  // Modal State
  const [showFieldModal, setShowFieldModal] = useState(false);
  const [activeFieldInput, setActiveFieldInput] = useState<{ groupId: string, condId: string, fieldType: 'field' | 'value' } | null>(null);
  const [selectedDefaultField, setSelectedDefaultField] = useState<string | null>(null);


  // Schema Explorer state
  const [schemaExplorerOpen, setSchemaExplorerOpen] = useState(false);

  const toggleTable = (tableName) => {
    setExpandedTables(prev =>
      prev.includes(tableName)
        ? prev.filter(t => t !== tableName)
        : [...prev, tableName]
    );
  };

  // Field Catalog — dynamic from zeek_field_catalog.json based on selected source
  const fieldCatalog = useMemo(() => {
    const source = logicGroups[0]?.source?.replace('.log', '').toUpperCase() || 'CONN';
    const { mostUsed, others } = getFieldsForSource(source);
    return {
      mostUsed: mostUsed.map(f => ({ id: f.parquet, label: f.name, type: f.type })),
      others: others.map(f => ({ id: f.parquet, label: f.name, type: f.type })),
    };
  }, [logicGroups]);

  const selectedCondition = useMemo(() => {
    if (!activeFieldInput || activeFieldInput.fieldType !== 'value') return null;
    const group = logicGroups.find(g => g.id === activeFieldInput.groupId);
    return group?.conditions.find(c => c.id === activeFieldInput.condId) || null;
  }, [activeFieldInput, logicGroups]);

  const selectedFieldType = useMemo(() => {
    if (!selectedCondition?.field) return '';
    const source = logicGroups[0]?.source?.replace('.log', '').toUpperCase() || 'CONN';
    const field = getAllVisibleFields(source).find(f => f.parquet === selectedCondition.field);
    return (field?.type || '').toLowerCase();
  }, [logicGroups, selectedCondition]);

  // Value catalog — only for true boolean fields
  const valueCatalog = useMemo(() => {
    if (selectedFieldType.includes('bool')) {
      return [
        { id: 'true', desc: 'Boolean True' },
        { id: 'false', desc: 'Boolean False' },
        { id: 'null', desc: 'Undefined' },
      ];
    }
    return [];
  }, [selectedFieldType]);

  // Group By fields — depends on selected log source
  const groupByFields = useMemo(() => {
    const source = logicGroups[0]?.source?.replace('.log', '').toUpperCase() || 'CONN';
    return getAllVisibleFields(source).map(f => f.parquet);
  }, [logicGroups]);

  useEffect(() => {
    setView(defaultView);
  }, [defaultView]);

  // Keyboard Shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'Enter' && view === 'builder') {
        setView('results');
      }
      if (e.key === 'Escape') {
        if (showFieldModal) {
          closeFieldModal();
        } else if (view === 'results') {
          setView('findings');
        } else if (view === 'findings') {
          setView('detail');
        } else if (view === 'detail') {
          setView('history');
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [view, showFieldModal]);

  const toggleSource = (id: string) => {
    setSelectedSources(prev => prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]);
  };

  const addLogicGroup = () => {
    const newId = `lb${logicGroups.length + 1}`;
    setLogicGroups([...logicGroups, { id: newId, source: 'http.log', conditions: [{ id: Math.random().toString(), field: '', operator: 'EQUAL', value: '' }] }]);
  };

  const removeLogicGroup = (id: string) => setLogicGroups(logicGroups.filter(g => g.id !== id));

  const addCondition = (groupId: string) => {
    setLogicGroups(logicGroups.map(g => g.id === groupId ? { ...g, conditions: [...g.conditions, { id: Math.random().toString(), field: '', operator: 'EQUAL', value: '' }] } : g));
  };

  const removeCondition = (groupId: string, condId: string) => {
    setLogicGroups(logicGroups.map(g => g.id === groupId ? { ...g, conditions: g.conditions.filter(c => c.id !== condId) } : g));
  };

  const updateCondition = (groupId: string, condId: string, data: Partial<Condition>) => {
    setLogicGroups(logicGroups.map(g => g.id === groupId ? { ...g, conditions: g.conditions.map(c => c.id === condId ? { ...c, ...data } : c) } : g));
  };

  // Modal Functions
  const openFieldModal = (groupId: string, condId: string, fieldType: 'field' | 'value') => {
    setActiveFieldInput({ groupId, condId, fieldType });
    setSelectedDefaultField(null);
    setShowFieldModal(true);
  };

  const closeFieldModal = () => {
    setShowFieldModal(false);
    setActiveFieldInput(null);
    setSelectedDefaultField(null);
  };

  const selectFieldValue = (value: string) => {
    if (activeFieldInput) {
      const { groupId, condId, fieldType } = activeFieldInput;

      if (groupId === 'correlation-g1' && condId === 'join-key') {
        setThresholdField(value);
      } else if (groupId === 'correlation-g2' && condId === 'join-key') {
        console.log('Group B join key:', value);
      } else {
        updateCondition(groupId, condId, fieldType === 'field' ? { field: value } : { value });
      }
    }
    closeFieldModal();
  };

  // NEW FUNCTIONS FOR HUNT ACTIONS
  const handleRunHunt = async (hunt: Hunt) => {
    const now = new Date().toISOString();
    setSelectedHunt({ ...hunt, status: 'running', lastRunAt: now });
    setHunts(prev => prev.map(h => h.id === hunt.id ? { ...h, status: 'running' as const, lastRunAt: now } : h));
    setView('detail');
    try {
      const result = await huntApi.run({
        hunt_id: hunt.id,
        query_type: hunt.type as 'sql' | 'visual',
        query: hunt.sqlQuery,
        log_source: hunt.logSource,
        conditions: hunt.conditions,
      });
      if (result && result.total !== undefined) {
        const updated = { ...hunt, status: 'completed' as const, matchesFound: result.total, duration: parseFloat(result.executionTime) || 0, lastRunAt: now };
        setHunts(prev => prev.map(h => h.id === hunt.id ? updated : h));
        setSelectedHunt(updated);
      }
    } catch (e) {
      console.error('Run hunt failed:', e);
      setHunts(prev => prev.map(h => h.id === hunt.id ? { ...h, status: 'failed' as const } : h));
      setSelectedHunt(prev => prev ? { ...prev, status: 'failed' } : prev);
    }
  };

  const handleViewHunt = (hunt: Hunt) => {
    setSelectedHunt(hunt);
    setView('detail');
  };

  const handleCopyHunt = (hunt: Hunt) => {
    setEditingHuntId(null);
    setHuntName(`Copy of ${hunt.name}`);
    setHypothesis(hunt.hypothesis);
    setHuntMode(hunt.type);
    setLockedHuntMode(hunt.type as 'visual' | 'sql');
    setTimeRange(hunt.timeRange);
    setBuilderResults(null);
    if (hunt.sqlQuery) setSqlQuery(hunt.sqlQuery);
    if (hunt.conditions.length > 0) {
      setLogicGroups([{ id: 'lb1', source: `${hunt.logSource.toLowerCase()}.log`, conditions: hunt.conditions }]);
    }
    setView('builder');
  };

  const handleDeleteHunt = (huntId: string) => {
    setHunts(prev => prev.filter(h => h.id !== huntId));
    huntApi.delete(huntId).catch(() => { });
  };

  const handleRerunHunt = async (hunt: Hunt) => {
    const now = new Date().toISOString();
    setHunts(prev => prev.map(h => h.id === hunt.id ? { ...h, status: 'running' as const, lastRunAt: now } : h));
    setSelectedHunt({ ...hunt, status: 'running', lastRunAt: now });
    setView('detail');
    try {
      const result = await huntApi.run({
        hunt_id: hunt.id,
        query_type: hunt.type as 'sql' | 'visual',
        query: hunt.sqlQuery,
        log_source: hunt.logSource,
        conditions: hunt.conditions,
      });
      if (result && result.total !== undefined) {
        const updated = { ...hunt, status: 'completed' as const, matchesFound: result.total, duration: parseFloat(result.executionTime) || 0, lastRunAt: now };
        setHunts(prev => prev.map(h => h.id === hunt.id ? updated : h));
        setSelectedHunt(updated);
      }
    } catch (e) {
      console.error('Rerun hunt failed:', e);
      setHunts(prev => prev.map(h => h.id === hunt.id ? { ...h, status: 'failed' as const } : h));
      setSelectedHunt(prev => prev ? { ...prev, status: 'failed' } : prev);
    }
  };

  // Field Picker Modal Component
  const FieldPickerModal = () => {
    if (!showFieldModal) return null;

    const isFieldPicker = activeFieldInput?.fieldType === 'field';

    if (isFieldPicker) {
      return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl shadow-2xl overflow-hidden animate-in zoom-in duration-200 w-[450px]">
            <div className="p-4 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/50">
              <h3 className="text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400">Select Field</h3>
              <button onClick={closeFieldModal} className="text-zinc-500 hover:text-white transition-colors text-lg leading-none">✕</button>
            </div>

            <div className="max-h-[400px] overflow-y-auto">
              {fieldCatalog.mostUsed.length > 0 && (
                <div>
                  <div className="p-3 bg-zinc-900/20 border-b border-zinc-800">
                    <h4 className="text-[10px] font-black uppercase tracking-widest text-[#00D4AA]">Most Used</h4>
                  </div>
                  <div className="p-2">
                    {fieldCatalog.mostUsed.map((item) => (
                      <div
                        key={item.id}
                        onClick={() => selectFieldValue(item.id)}
                        className="p-3 mb-1 rounded-xl hover:bg-zinc-800 cursor-pointer border border-transparent hover:border-[#00D4AA]/30 transition-all flex items-center justify-between"
                      >
                        <div className="min-w-0 pr-3">
                          <div className="text-[11px] font-bold text-zinc-300 truncate">{item.label}</div>
                          <div className="text-[9px] text-zinc-600 font-mono truncate">{item.id}</div>
                        </div>
                        <span className="text-[9px] text-zinc-600 uppercase">{item.type}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {fieldCatalog.others.length > 0 && (
                <div>
                  <div className="p-3 bg-zinc-900/20 border-b border-zinc-800 border-t">
                    <h4 className="text-[10px] font-black uppercase tracking-widest text-zinc-500">Others</h4>
                  </div>
                  <div className="p-2">
                    {fieldCatalog.others.map((item) => (
                      <div
                        key={item.id}
                        onClick={() => selectFieldValue(item.id)}
                        className="p-3 mb-1 rounded-xl hover:bg-zinc-800 cursor-pointer border border-transparent hover:border-zinc-700 transition-all flex items-center justify-between"
                      >
                        <div className="min-w-0 pr-3">
                          <div className="text-[11px] font-bold text-zinc-300 truncate">{item.label}</div>
                          <div className="text-[9px] text-zinc-600 font-mono truncate">{item.id}</div>
                        </div>
                        <span className="text-[9px] text-zinc-600 uppercase">{item.type}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="p-3 bg-zinc-900/50 border-t border-zinc-800 text-[9px] text-zinc-500 uppercase font-bold tracking-tight">
              Fields from zeek_field_catalog.json • Source: {logicGroups[0]?.source || 'conn.log'}
            </div>
          </div>
        </div>
      );
    } else {
      // Value picker — only boolean presets for boolean fields
      return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl shadow-2xl overflow-hidden animate-in zoom-in duration-200 w-[350px]">
            <div className="p-4 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/50">
              <h3 className="text-[11px] font-black uppercase tracking-[0.2em] text-zinc-400">Select Value</h3>
              <button onClick={closeFieldModal} className="text-zinc-500 hover:text-white transition-colors text-lg leading-none">✕</button>
            </div>
            <div className="p-2">
              {valueCatalog.length > 0 ? valueCatalog.map((item) => (
                <div
                  key={item.id}
                  onClick={() => selectFieldValue(item.id)}
                  className="p-3 mb-1 rounded-xl hover:bg-zinc-800 cursor-pointer border border-transparent hover:border-emerald-500/30 transition-all"
                >
                  <div className="text-[11px] font-bold text-zinc-300">{item.id}</div>
                  <div className="text-[9px] text-zinc-500 mt-1">{item.desc}</div>
                </div>
              )) : (
                <div className="p-3 text-[10px] text-zinc-500">
                  No predefined values for this field type. Enter the value manually.
                </div>
              )}
            </div>
          </div>
        </div>
      );
    }
  };



  const Breadcrumbs = ({ current }: { current: string }) => (
    <div className="flex items-center gap-2 text-xs text-zinc-500 font-medium ">
      <span className="cursor-pointer hover:text-emerald-400 transition-colors" onClick={() => setView('history')}>
        THREAT HUNTING
      </span>
      {current !== 'RECIPES' && (
        <>
          <span>/</span>
          <span className="text-emerald-400 uppercase">{current} </span>
        </>
      )}
    </div>
  );

  const ContextHelp = ({ text }: { text: string }) => (
    <div className="group relative inline-block">
      <HelpCircle size={12} className="text-zinc-600 cursor-help" />
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-48 p-3 bg-zinc-800 border border-zinc-700 rounded-xl text-[10px] text-gray-300 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50 shadow-2xl">
        {text}
      </div>
    </div>
  );

  // --- Render Functions ---

  const renderHuntBuilder = () => {
    return (
      <div className="animate-in fade-in duration-500 space-y-6">
        <Breadcrumbs current={editingHuntId ? "Edit Hunt" : "New Hunt"} />

        {/* Field Picker Modal */}
        <FieldPickerModal />

        {/* ═══════ HEADER: Name + Run ═══════ */}
        <div className="flex items-start gap-6">
          <div className="flex-1 space-y-4">
            <input
              type="text"
              value={huntName}
              onChange={(e) => setHuntName(e.target.value)}
              placeholder="Hunt Name — e.g. C2 Beaconing Detection"
              className="w-full bg-transparent text-2xl font-black text-white outline-none placeholder:text-zinc-700 border-b border-zinc-800 pb-3 focus:border-emerald-500/50 transition-colors"
            />
            <textarea
              value={hypothesis}
              onChange={(e) => setHypothesis(e.target.value)}
              placeholder="Describe your hypothesis — What suspicious behavior are you trying to find?"
              className="w-full bg-transparent text-sm text-zinc-400 outline-none placeholder:text-zinc-700 resize-none min-h-[50px] leading-relaxed"
              rows={2}
            />
          </div>
          <button
            onClick={handleRunNewHunt}
            className="bg-emerald-500 hover:bg-emerald-400 text-black px-8 py-3.5 rounded-xl text-sm font-black uppercase tracking-wider transition-all flex items-center gap-2.5 shadow-lg shadow-emerald-500/20 hover:shadow-emerald-500/30 shrink-0"
          >
            <Play size={18} fill="currentColor" /> Run Hunt
          </button>
        </div>

        {/* ═══════ MODE TABS ═══════ */}
        <div className="flex items-center gap-1 bg-zinc-900/50 border border-zinc-800 rounded-xl p-1 w-fit">
          <button
            onClick={() => !lockedHuntMode && setHuntMode('visual')}
            className={`px-5 py-2.5 rounded-lg text-xs font-black uppercase tracking-widest transition-all flex items-center gap-2 ${huntMode === 'visual'
              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
              : lockedHuntMode ? 'text-zinc-700 border border-transparent cursor-not-allowed' : 'text-zinc-500 hover:text-zinc-300 border border-transparent'
              }`}
          >
            {lockedHuntMode && huntMode !== 'visual' && <Lock size={10} />}
            Visual Builder
          </button>
          <button
            onClick={() => !lockedHuntMode && setHuntMode('sql')}
            className={`px-5 py-2.5 rounded-lg text-xs font-black uppercase tracking-widest transition-all flex items-center gap-2 ${huntMode === 'sql'
              ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
              : lockedHuntMode ? 'text-zinc-700 border border-transparent cursor-not-allowed' : 'text-zinc-500 hover:text-zinc-300 border border-transparent'
              }`}
          >
            {lockedHuntMode && huntMode !== 'sql' && <Lock size={10} />}
            SQL Query
          </button>
          {lockedHuntMode && (
            <span className="text-[9px] text-zinc-600 font-bold uppercase ml-2 flex items-center gap-1">
              <Lock size={9} /> Type locked
            </span>
          )}
        </div>

        {/* ═══════ VISUAL BUILDER ═══════ */}
        {huntMode === 'visual' && (
          <div className="space-y-4">
            {/* Log Source + Time Range Row */}
            <div className="bg-zinc-900/40 border border-zinc-800/60 rounded-2xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <Database size={14} className="text-emerald-400" />
                <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">Data Source</span>
              </div>
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-sm text-zinc-500 font-medium">Search</span>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-emerald-500"></span>
                  <select
                    value={logicGroups[0]?.source || `${LOG_SOURCE_NAMES[0]?.toLowerCase()}.log`}
                    onChange={e => setLogicGroups(logicGroups.map((g, i) => i === 0 ? { ...g, source: e.target.value } : g))}
                    className="bg-zinc-950 border border-zinc-800 rounded-xl pl-8 pr-4 py-2.5 text-sm font-bold text-emerald-400 outline-none cursor-pointer hover:border-emerald-500/30 transition-all"
                  >
                    {LOG_SOURCE_NAMES.map(name => (
                      <option key={name} value={`${name.toLowerCase()}.log`}>{name.toLowerCase()}.log</option>
                    ))}
                  </select>
                </div>
                <span className="text-sm text-zinc-500 font-medium">within</span>
                <select
                  value={timeRange}
                  onChange={e => setTimeRange(e.target.value)}
                  className="bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm font-bold text-white outline-none cursor-pointer hover:border-zinc-700 transition-all"
                >
                  {TIME_RANGES.map(tr => (
                    <option key={tr} value={tr}>{tr}</option>
                  ))}
                </select>
                <span className="text-sm text-zinc-500 font-medium">where</span>
              </div>
            </div>

            {/* Conditions — Numbered Style with Accent */}
            <div className="bg-zinc-900/40 border border-zinc-800/60 rounded-2xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <Filter size={14} className="text-amber-400" />
                <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">Conditions</span>
                <span className="text-[9px] text-zinc-700 font-mono ml-auto">{logicGroups[0]?.conditions.filter(c => c.field).length || 0} active</span>
              </div>
              <div className="space-y-2">
                {logicGroups[0]?.conditions.map((cond, idx) => (
                  <div key={cond.id} className="flex items-center gap-3 group relative">
                    {/* Step Number / AND */}
                    <div className="w-10 shrink-0 flex items-center justify-end">
                      {idx > 0 ? (
                        <span className="text-[9px] font-black text-amber-500/70 uppercase tracking-widest">AND</span>
                      ) : (
                        <div className="w-6 h-6 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                          <span className="text-[10px] font-black text-emerald-400">{idx + 1}</span>
                        </div>
                      )}
                    </div>

                    {/* Accent bar */}
                    <div className="w-0.5 h-8 rounded-full bg-gradient-to-b from-emerald-500/40 to-emerald-500/0 shrink-0"></div>

                    {/* Field */}
                    <div className="relative flex-1 max-w-[220px]">
                      <input
                        type="text"
                        value={cond.field}
                        onChange={e => updateCondition(logicGroups[0].id, cond.id, { field: e.target.value })}
                        placeholder="Select field"
                        className="w-full bg-zinc-950 border border-zinc-800 rounded-xl pl-3 pr-9 py-2.5 text-sm font-mono text-emerald-400 outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all"
                      />
                      <button
                        onClick={() => openFieldModal(logicGroups[0].id, cond.id, 'field')}
                        className="absolute right-2 top-1/2 -translate-y-1/2 w-6 h-6 flex items-center justify-center rounded-lg bg-zinc-800 hover:bg-emerald-600 transition-all text-zinc-500 hover:text-white"
                      >
                        <ChevronDown size={12} />
                      </button>
                    </div>

                    {/* Operator */}
                    <select
                      value={cond.operator}
                      onChange={e => updateCondition(logicGroups[0].id, cond.id, { operator: e.target.value })}
                      className="bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2.5 text-sm font-bold text-amber-400 outline-none cursor-pointer hover:border-amber-500/30 transition-all"
                    >
                      {QUERY_OPERATORS.map(op => (
                        <option key={op.value} value={op.value}>{op.label}</option>
                      ))}
                    </select>

                    {/* Value */}
                    <div className="relative flex-1 max-w-[220px]">
                      <input
                        type="text"
                        value={cond.value}
                        onChange={e => updateCondition(logicGroups[0].id, cond.id, { value: e.target.value })}
                        placeholder="value"
                        className="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2.5 text-sm font-mono text-white outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all"
                      />
                    </div>

                    {/* Remove */}
                    <button
                      onClick={() => removeCondition(logicGroups[0].id, cond.id)}
                      className="w-8 h-8 flex items-center justify-center text-zinc-700 hover:text-red-400 transition-all opacity-0 group-hover:opacity-100 rounded-xl hover:bg-red-500/10"
                    >
                      <X size={16} />
                    </button>
                  </div>
                ))}

                {/* Add Condition */}
                <button
                  onClick={() => addCondition(logicGroups[0].id)}
                  className="flex items-center gap-2 text-xs font-bold text-emerald-500 hover:text-emerald-400 uppercase tracking-widest pl-[52px] mt-3 transition-colors group"
                >
                  <div className="w-5 h-5 rounded-lg border border-dashed border-emerald-500/40 flex items-center justify-center group-hover:border-emerald-400 group-hover:bg-emerald-500/10 transition-all">
                    <Plus size={11} />
                  </div>
                  Add Condition
                </button>
              </div>
            </div>

            {/* ═══ Group By + Aggregation ═══ */}
            <div className="bg-zinc-900/40 border border-zinc-800/60 rounded-2xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Layers size={14} className="text-purple-400" />
                  <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">Aggregation</span>
                  <ContextHelp text="Group results by a field and count occurrences. Essential for threat hunting — e.g. find IPs with 100+ DNS queries." />
                </div>
                <button
                  onClick={() => setGroupByEnabled(!groupByEnabled)}
                  className={`relative w-10 h-5 rounded-full transition-all ${groupByEnabled ? 'bg-purple-500' : 'bg-zinc-800'}`}
                >
                  <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow-md transition-all ${groupByEnabled ? 'left-[22px]' : 'left-0.5'}`} />
                </button>
              </div>

              {groupByEnabled && (
                <div className="space-y-3 animate-in slide-in-from-top-2 duration-200">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="text-sm text-zinc-500 font-medium">Group by</span>
                    <select
                      value={groupByField}
                      onChange={e => setGroupByField(e.target.value)}
                      className="bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm font-mono text-purple-400 outline-none cursor-pointer hover:border-purple-500/30 transition-all min-w-[180px]"
                    >
                      <option value="">Select field…</option>
                      {groupByFields.map(f => (
                        <option key={f} value={f}>{f}</option>
                      ))}
                    </select>
                    <span className="text-sm text-zinc-500 font-medium">having count ≥</span>
                    <input
                      type="number"
                      min={0}
                      value={havingThreshold}
                      onChange={e => setHavingThreshold(parseInt(e.target.value) || 0)}
                      className="w-20 bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2.5 text-sm font-mono text-purple-400 outline-none focus:border-purple-500/50 transition-all text-center"
                    />
                  </div>
                  {groupByField && (
                    <div className="flex items-center gap-2 px-3 py-2 bg-purple-500/5 border border-purple-500/10 rounded-xl">
                      <Sparkles size={12} className="text-purple-400" />
                      <span className="text-[10px] text-purple-300/70">
                        Results will show <strong className="text-purple-300">{groupByField}</strong> grouped with occurrence counts{havingThreshold > 0 && <>, filtered to <strong className="text-purple-300">≥ {havingThreshold}</strong> hits</>}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {!groupByEnabled && (
                <div className="text-[10px] text-zinc-700 italic">Enable to aggregate results — e.g. count occurrences per IP, service, or domain</div>
              )}
            </div>

            {/* Query Preview — Syntax Highlighted */}
            <div className="bg-zinc-950/60 border border-zinc-800/40 rounded-2xl px-5 py-3">
              <div className="flex items-center gap-2 mb-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                <span className="text-[9px] font-black text-zinc-600 uppercase tracking-widest">Generated Query</span>
              </div>
              <p className="text-xs font-mono leading-relaxed">
                {(() => {
                  const table = (logicGroups[0]?.source || 'conn.log').replace('.log', '');
                  const validConds = logicGroups[0]?.conditions.filter(c => c.field && c.value) || [];
                  const selectPart = groupByEnabled && groupByField
                    ? <><span className="text-purple-400 font-bold">SELECT</span> <span className="text-zinc-300">{groupByField}</span><span className="text-zinc-600">,</span> <span className="text-blue-400">COUNT</span><span className="text-zinc-600">(*)</span> <span className="text-purple-400">AS</span> <span className="text-cyan-400">occurrence_count</span></>
                    : <><span className="text-purple-400 font-bold">SELECT</span> <span className="text-zinc-500">*</span></>;
                  return (
                    <>
                      {selectPart}
                      {' '}<span className="text-purple-400 font-bold">FROM</span> <span className="text-emerald-400">{table}</span>
                      {validConds.length > 0 && (
                        <>
                          {' '}<span className="text-purple-400 font-bold">WHERE</span>{' '}
                          {validConds.map((c, i) => (
                            <span key={i}>
                              {i > 0 && <span className="text-purple-400"> AND </span>}
                              <span className="text-zinc-300">{c.field}</span>
                              <span className="text-amber-400"> {c.operator} </span>
                              <span className="text-cyan-400">'{c.value}'</span>
                            </span>
                          ))}
                        </>
                      )}
                      {groupByEnabled && groupByField && (
                        <>
                          {' '}<span className="text-purple-400 font-bold">GROUP BY</span> <span className="text-zinc-300">{groupByField}</span>
                          {havingThreshold > 0 && (
                            <> <span className="text-purple-400 font-bold">HAVING</span> <span className="text-blue-400">COUNT</span><span className="text-zinc-600">(*)</span> <span className="text-amber-400">≥</span> <span className="text-cyan-400">{havingThreshold}</span></>
                          )}
                          {' '}<span className="text-purple-400 font-bold">ORDER BY</span> <span className="text-cyan-400">occurrence_count</span> <span className="text-amber-400">DESC</span>
                        </>
                      )}
                    </>
                  );
                })()}
              </p>
            </div>
          </div>
        )}

        {/* ═══════ SQL BUILDER ═══════ */}
        {huntMode === 'sql' && (
          <div className="flex gap-4">
            {/* SQL Editor */}
            <div className="flex-1 bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
              <div className="border-b border-zinc-800 px-5 py-3 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-purple-500"></span>
                  <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">query.sql</span>
                </div>
                <div className="flex items-center gap-2 text-[9px] text-zinc-600">
                  <span>DuckDB SQL</span>
                  <span>•</span>
                  <span>Ctrl+Enter to run</span>
                </div>
              </div>
              <textarea
                className="w-full h-72 bg-black/60 p-5 font-mono text-sm text-emerald-300 focus:outline-none resize-none leading-relaxed"
                value={sqlQuery}
                onChange={(e) => setSqlQuery(e.target.value)}
                placeholder="SELECT src_ip, dst_ip, dst_port, COUNT(*) as total&#10;FROM conn&#10;WHERE dst_port = 443&#10;GROUP BY src_ip, dst_ip, dst_port&#10;ORDER BY total DESC&#10;LIMIT 20"
                spellCheck={false}
              />
              <div className="border-t border-zinc-800 px-5 py-2.5 flex items-center justify-between">
                <select
                  value={timeRange}
                  onChange={e => setTimeRange(e.target.value)}
                  className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-1.5 text-[11px] font-bold text-zinc-400 outline-none cursor-pointer"
                >
                  {TIME_RANGES.map(tr => (
                    <option key={tr} value={tr}>{tr}</option>
                  ))}
                </select>
                <button
                  onClick={() => setSchemaExplorerOpen(!schemaExplorerOpen)}
                  className={`px-3 py-1.5 text-[10px] font-black uppercase tracking-wider rounded-lg border transition-all flex items-center gap-1.5
                    ${schemaExplorerOpen
                      ? 'bg-purple-500/10 border-purple-500/30 text-purple-400'
                      : 'bg-zinc-800 border-zinc-700 text-zinc-400 hover:text-purple-400 hover:border-purple-500/30'
                    }`}
                >
                  <Database size={11} /> Schema
                </button>
                <button
                  onClick={handleRunNewHunt}
                  className="px-4 py-1.5 bg-emerald-500 text-black text-xs font-black uppercase rounded-lg hover:bg-emerald-400 transition-colors flex items-center gap-1.5"
                >
                  <Play size={12} fill="currentColor" /> Run
                </button>
              </div>
            </div>

            {/* Schema Explorer Toggle + Query Library Panel */}
            <div className="w-72 space-y-3 flex flex-col" style={{ maxHeight: '600px' }}>
              {/* Schema Explorer Toggle Button */}
              <button
                onClick={() => setSchemaExplorerOpen(true)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden hover:border-purple-500/30 transition-all group"
              >
                <div className="px-4 py-3.5 flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500/20 to-emerald-500/20 border border-purple-500/20 flex items-center justify-center group-hover:scale-105 transition-transform">
                    <Database size={14} className="text-purple-400" />
                  </div>
                  <div className="text-left flex-1">
                    <div className="text-[10px] font-black text-white uppercase tracking-widest group-hover:text-purple-300 transition-colors">Schema Explorer</div>
                    <p className="text-[9px] text-zinc-500 mt-0.5">Browse all tables & fields</p>
                  </div>
                  <ChevronRight size={14} className="text-zinc-600 group-hover:text-purple-400 group-hover:translate-x-0.5 transition-all" />
                </div>
              </button>

              {/* Example Query Library */}
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden shrink-0">
                <div className="px-4 py-3 flex items-center gap-2">
                  <Sparkles size={14} className="text-amber-400" />
                  <span className="text-[10px] font-black text-white uppercase tracking-widest">Query Library</span>
                </div>
                <div className="border-t border-zinc-800">
                  {[
                    {
                      title: 'Top DNS Queries',
                      desc: 'Find most queried domains',
                      query: `SELECT query, COUNT(*) AS total,\n  COUNT(DISTINCT src_ip) AS unique_hosts\nFROM dns\nGROUP BY query\nORDER BY total DESC\nLIMIT 20`
                    },
                    {
                      title: 'Large Data Transfers',
                      desc: 'Detect potential exfiltration',
                      query: `SELECT src_ip, dst_ip, dst_port,\n  SUM(orig_bytes) AS bytes_out,\n  COUNT(*) AS connections\nFROM conn\nGROUP BY src_ip, dst_ip, dst_port\nHAVING bytes_out > 1000000\nORDER BY bytes_out DESC`
                    },
                    {
                      title: 'DNS + Conn Correlation',
                      desc: 'Match DNS lookups to connections',
                      query: `SELECT d.src_ip, d.query,\n  c.dst_ip, c.dst_port, c.service,\n  c.orig_bytes, d.uid AS dns_uid,\n  c.uid AS conn_uid\nFROM dns d\nJOIN conn c ON d.src_ip = c.src_ip\nLIMIT 50`
                    },
                    {
                      title: 'HTTP Suspicious Agents',
                      desc: 'Find unusual user agents',
                      query: `SELECT user_agent,\n  COUNT(*) AS requests,\n  COUNT(DISTINCT src_ip) AS hosts\nFROM http\nGROUP BY user_agent\nORDER BY requests DESC\nLIMIT 20`
                    },
                  ].map((ex, i) => (
                    <button
                      key={i}
                      onClick={() => setSqlQuery(ex.query)}
                      className="w-full px-4 py-2.5 text-left border-b border-zinc-800/30 last:border-0 hover:bg-purple-500/5 transition-colors group"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-bold text-zinc-300 group-hover:text-purple-300 transition-colors">{ex.title}</span>
                        <ArrowUpRight size={10} className="text-zinc-700 group-hover:text-purple-400 transition-colors" />
                      </div>
                      <p className="text-[9px] text-zinc-600 mt-0.5">{ex.desc}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ═══════ Schema Explorer Slide-Out ═══════ */}
        {schemaExplorerOpen && (
          <SchemaExplorer
            context="hunting"
            onFieldClick={(parquet, tableName) => {
              setSqlQuery(prev => prev + parquet);
            }}
            onClose={() => setSchemaExplorerOpen(false)}
            mode="sidebar"
          />
        )}
        {builderRunning && (
          <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-8 text-center">
            <div className="inline-flex items-center gap-3">
              <div className="w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
              <span className="text-sm text-zinc-400 font-medium">Running hunt...</span>
            </div>
          </div>
        )}

        {builderResults !== null && !builderRunning && (
          <div className="space-y-4">
            {/* Results Header */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className={`text-sm font-black ${builderResults.length > 0 ? 'text-emerald-400' : 'text-zinc-500'}`}>
                  {builderResults.length} results found
                </span>
                {builderQuery && (
                  <span className="text-[9px] text-zinc-600 font-mono bg-zinc-900 px-2 py-1 rounded max-w-[400px] truncate">
                    {builderQuery.substring(0, 80)}...
                  </span>
                )}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleRunNewHunt}
                  className="px-4 py-2 bg-zinc-800 border border-zinc-700 text-zinc-300 text-xs font-bold uppercase rounded-lg hover:bg-zinc-700 transition-colors flex items-center gap-1.5"
                >
                  <RefreshCcw size={12} /> Re-run
                </button>
                <button
                  onClick={handleSaveHunt}
                  className="px-5 py-2 bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-black uppercase rounded-lg transition-colors flex items-center gap-1.5 shadow-lg shadow-emerald-500/20"
                >
                  <Save size={14} /> Save to History
                </button>
              </div>
            </div>

            {/* ═══ Analytical Summary ═══ */}
            {builderResults.length > 0 && (() => {
              const keys = Object.keys(builderResults[0]);
              const numericKeys = keys.filter(k => typeof builderResults[0][k] === 'number');
              const ipKeys = keys.filter(k => k.includes('ip') || k.includes('host') || k === 'source_host');
              const catKeys = keys.filter(k => ['service', 'protocol', 'method', 'rcode_name', 'status_code', 'conn_state', 'qtype_name'].includes(k));

              const topValues: Record<string, { value: string; count: number }[]> = {};
              catKeys.forEach(k => {
                const counts: Record<string, number> = {};
                builderResults.forEach(r => { const v = String(r[k] ?? ''); counts[v] = (counts[v] || 0) + 1; });
                topValues[k] = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([value, count]) => ({ value, count }));
              });

              const uniqueCounts: Record<string, number> = {};
              ipKeys.forEach(k => { uniqueCounts[k] = new Set(builderResults.map(r => r[k]).filter(Boolean)).size; });

              const numAggs: Record<string, { sum: number }> = {};
              numericKeys.slice(0, 3).forEach(k => {
                const vals = builderResults.map(r => Number(r[k]) || 0);
                numAggs[k] = { sum: vals.reduce((a, b) => a + b, 0) };
              });

              return (
                <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Activity size={14} className="text-emerald-400" />
                    <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">Analytical Summary</span>
                    <span className="text-[9px] text-zinc-700 ml-auto">{builderResults.length} total rows</span>
                  </div>
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    {Object.entries(uniqueCounts).slice(0, 2).map(([key, count]) => (
                      <div key={key} className="bg-black/30 rounded-lg p-3">
                        <div className="text-lg font-black text-blue-400">{count}</div>
                        <div className="text-[8px] text-zinc-600 font-bold uppercase">Unique {key.replace(/_/g, ' ')}</div>
                      </div>
                    ))}
                    {Object.entries(numAggs).slice(0, 2).map(([key, agg]) => (
                      <div key={key} className="bg-black/30 rounded-lg p-3">
                        <div className="text-lg font-black text-purple-400">{agg.sum > 1000000 ? `${(agg.sum / 1000000).toFixed(1)}M` : agg.sum > 1000 ? `${(agg.sum / 1000).toFixed(1)}K` : agg.sum.toFixed(0)}</div>
                        <div className="text-[8px] text-zinc-600 font-bold uppercase">Total {key.replace(/_/g, ' ')}</div>
                      </div>
                    ))}
                  </div>
                  {Object.keys(topValues).length > 0 && (
                    <div className="mt-3 pt-3 border-t border-zinc-800/50">
                      <div className="flex flex-wrap gap-4">
                        {Object.entries(topValues).map(([key, vals]) => (
                          <div key={key} className="min-w-[120px]">
                            <div className="text-[8px] text-zinc-600 font-bold uppercase mb-1">{key}</div>
                            {vals.map(v => (
                              <div key={v.value} className="flex items-center gap-2 py-0.5">
                                <div className="flex-1 bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                                  <div className="bg-emerald-500/60 h-full rounded-full" style={{ width: `${(v.count / builderResults.length) * 100}%` }} />
                                </div>
                                <span className="text-[9px] text-zinc-400 font-mono shrink-0">{v.value || 'null'}</span>
                                <span className="text-[8px] text-zinc-600 shrink-0">{v.count}</span>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Results: Grouped Cards + Drawer */}
            {builderResults.length > 0 ? (() => {
              const groupField = getPrimaryGroupField(builderResults);
              const groups = groupField ? groupRowsByField(builderResults, groupField) : null;
              const groupEntries = groups
                ? Object.entries(groups).sort((a, b) => b[1].length - a[1].length)
                : [['—', builderResults]];

              return (
                <div className="flex gap-4">
                  {/* Grouped Cards */}
                  <div className={`flex-1 min-w-0 transition-all duration-300 ${builderDrawerGroup ? 'max-w-[54%]' : ''}`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">
                        {groupEntries.length} unique {groupField || 'groups'} · {builderResults.length} total rows
                      </span>
                      <span className="text-[9px] text-zinc-600">Click a card to inspect evidence</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 xl:grid-cols-3">
                      {groupEntries.slice(0, 18).map(([groupKey, groupRows]) => {
                        const isActive = builderDrawerGroup?.key === groupKey;
                        const previewFields = Object.keys(groupRows[0] || {})
                          .filter(k => k !== groupField && groupRows[0][k] !== null && groupRows[0][k] !== undefined)
                          .slice(0, 2);
                        const countVal = groupRows[0]?.['count'] ?? groupRows[0]?.['COUNT(*)'] ?? groupRows[0]?.['occurrence_count'] ?? null;
                        return (
                          <div
                            key={groupKey}
                            onClick={() => setBuilderDrawerGroup(isActive ? null : { key: groupKey, rows: groupRows as any[] })}
                            className={`rounded-lg border p-3 cursor-pointer transition-all duration-150 ${isActive
                              ? 'border-[#00D4AA]/50 bg-[#00D4AA]/5 shadow-md shadow-[#00D4AA]/10'
                              : 'border-zinc-800 bg-zinc-800/40 hover:border-zinc-700 hover:bg-zinc-800/70'
                              }`}
                          >
                            <div className="font-mono text-xs font-bold text-white truncate mb-1.5" title={groupKey}>{groupKey}</div>
                            <div className="flex items-end justify-between gap-2">
                              <div>
                                {previewFields.map(f => (
                                  <div key={f} className="text-[9px] text-zinc-500 truncate">
                                    <span className="text-zinc-600">{f}: </span>
                                    <span className="text-zinc-400">{String((groupRows[0] as any)[f]).slice(0, 28)}</span>
                                  </div>
                                ))}
                              </div>
                              <div className="shrink-0 text-right">
                                <div className="text-base font-black text-[#00D4AA]">{countVal !== null ? countVal : (groupRows as any[]).length}</div>
                                <div className="text-[8px] text-zinc-600 uppercase">{countVal !== null ? 'count' : 'rows'}</div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    {groupEntries.length > 18 && (
                      <div className="text-center text-[10px] text-zinc-600 pt-2">
                        +{groupEntries.length - 18} more groups — refine your query to narrow results
                      </div>
                    )}
                  </div>

                  {/* Evidence Drawer */}
                  {builderDrawerGroup && (
                    <div className="w-[44%] shrink-0 bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden flex flex-col max-h-[420px] animate-in slide-in-from-right duration-200">
                      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800 shrink-0">
                        <div className="min-w-0">
                          <div className="text-[9px] font-black text-zinc-500 uppercase tracking-widest mb-0.5">Evidence — {builderDrawerGroup.rows.length} rows</div>
                          <div className="font-mono text-sm font-bold text-white truncate" title={builderDrawerGroup.key}>{builderDrawerGroup.key}</div>
                        </div>
                        <button onClick={() => setBuilderDrawerGroup(null)} className="p-1.5 hover:bg-zinc-800 rounded-lg transition-colors shrink-0">
                          <X size={15} className="text-zinc-500" />
                        </button>
                      </div>
                      <div className="flex-1 overflow-y-auto divide-y divide-zinc-800/50">
                        {builderDrawerGroup.rows.slice(0, 50).map((row: any, ri: number) => {
                          const cols = Object.entries(row).filter(([, v]) => v !== null && v !== undefined);
                          return (
                            <div key={ri} className="px-4 py-3 hover:bg-zinc-800/30 transition-colors">
                              <div className="text-[9px] font-black text-zinc-600 uppercase mb-2">Row #{ri + 1}</div>
                              <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                                {cols.map(([key, value]) => (
                                  <div key={key} className="flex flex-col min-w-0">
                                    <span className="text-[8px] uppercase text-zinc-600 font-bold">{key}</span>
                                    <span
                                      className={`text-[10px] font-mono truncate ${key === 'uid' ? 'text-cyan-400 cursor-pointer hover:underline' :
                                        key.includes('ip') || key.includes('_h') ? 'text-blue-300' :
                                          typeof value === 'number' ? 'text-purple-300' : 'text-zinc-300'
                                        }`}
                                      title={String(value)}
                                      onClick={() => key === 'uid' ? handleUidClick(String(value)) : undefined}
                                    >{String(value).slice(0, 40)}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })}
                        {builderDrawerGroup.rows.length > 50 && (
                          <div className="px-4 py-3 text-center text-[10px] text-zinc-600">
                            Showing first 50 of {builderDrawerGroup.rows.length} rows
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })() : (
              <div className="bg-zinc-900/30 border border-zinc-800/50 rounded-xl p-8 text-center">
                <p className="text-sm text-zinc-600">No results matched your query. Try adjusting your conditions.</p>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  // ── Expanded Hunt / Grouped Results / Drawer state ────────────────
  const [expandedHuntId, setExpandedHuntId] = useState<string | null>(null);
  const [expandedResults, setExpandedResults] = useState<Record<string, any[]>>({});
  const [expandedLoading, setExpandedLoading] = useState<string | null>(null);
  const [drawerGroup, setDrawerGroup] = useState<{ key: string; rows: any[] } | null>(null);

  const getPrimaryGroupField = (rows: any[]): string | null => {
    if (!rows?.length) return null;
    const keys = Object.keys(rows[0]);
    const groupCandidates = ['src_ip', 'id_orig_h', 'source_ip', 'orig_ip', 'ip', 'hostname', 'domain', 'query', 'uri', 'username'];
    for (const c of groupCandidates) { if (keys.includes(c)) return c; }
    return keys.find(k => typeof rows[0][k] === 'string') || keys[0] || null;
  };

  const groupRowsByField = (rows: any[], field: string): Record<string, any[]> => {
    const groups: Record<string, any[]> = {};
    for (const row of rows) {
      const key = String(row[field] ?? '—');
      if (!groups[key]) groups[key] = [];
      groups[key].push(row);
    }
    return groups;
  };

  const handleExpandHunt = async (hunt: Hunt) => {
    if (expandedHuntId === hunt.id) {
      setExpandedHuntId(null);
      setDrawerGroup(null);
      return;
    }
    setExpandedHuntId(hunt.id);
    setDrawerGroup(null);
    if (expandedResults[hunt.id]) return;
    setExpandedLoading(hunt.id);
    try {
      const result = await huntApi.run({
        hunt_id: hunt.id,
        query_type: hunt.type as 'sql' | 'visual',
        query: hunt.sqlQuery,
        log_source: hunt.logSource,
        conditions: hunt.conditions,
      });
      setExpandedResults(prev => ({ ...prev, [hunt.id]: result?.results || [] }));
    } catch {
      setExpandedResults(prev => ({ ...prev, [hunt.id]: [] }));
    } finally {
      setExpandedLoading(null);
    }
  };

  const renderHuntHistory = () => {
    const filteredHunts = hunts.filter(h => {
      const matchesSearch = !historySearch || h.name.toLowerCase().includes(historySearch.toLowerCase()) || h.hypothesis.toLowerCase().includes(historySearch.toLowerCase());
      const matchesSource = historySourceFilter === 'all' || h.logSource === historySourceFilter;
      return matchesSearch && matchesSource;
    });
    const totalPages = Math.max(1, Math.ceil(filteredHunts.length / HUNTS_PER_PAGE));
    const paginatedHunts = filteredHunts.slice((historyPage - 1) * HUNTS_PER_PAGE, historyPage * HUNTS_PER_PAGE);

    return (
      <div className="animate-in fade-in duration-500">
        <Breadcrumbs current="HUNT HISTORY" />

        {/* Header */}
        <div className="flex items-start justify-between mt-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-white mb-1">Threat Hunts</h1>
            <p className="text-sm text-zinc-500">Click a hunt to see grouped results — click any group to drill into raw evidence</p>
          </div>
          <button
            onClick={() => { setEditingHuntId(null); setLockedHuntMode(null); setBuilderResults(null); setHuntName(''); setHypothesis(''); setView('builder'); }}
            className="bg-emerald-500 hover:bg-emerald-400 text-black px-6 py-3 rounded-lg text-sm font-bold transition-all flex items-center gap-2"
          >
            <Plus size={18} /> New Hunt
          </button>
        </div>

        {/* Search and Filters */}
        <div className="flex items-center gap-4 mb-6">
          <div className="flex-1 relative">
            <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-600" />
            <input type="text" placeholder="Search hunts..." value={historySearch}
              onChange={e => { setHistorySearch(e.target.value); setHistoryPage(1); }}
              className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-12 pr-4 py-3 text-sm text-white outline-none focus:border-zinc-700" />
          </div>
          <select value={historySourceFilter} onChange={e => { setHistorySourceFilter(e.target.value); setHistoryPage(1); }}
            className="bg-zinc-900 border border-zinc-800 text-sm text-zinc-400 px-4 py-3 rounded-lg outline-none cursor-pointer">
            <option value="all">All Log Sources</option>
            {LOG_SOURCE_NAMES.map(name => <option key={name} value={name}>{name}</option>)}
          </select>
        </div>

        {/* Layout: Hunt list + Result Drawer side-by-side */}
        <div className="flex gap-6 relative">

          {/* Left: Hunt list */}
          <div className={`flex-1 min-w-0 space-y-3 transition-all duration-300 ${drawerGroup ? 'max-w-[55%]' : 'max-w-full'}`}>
            {paginatedHunts.length === 0 ? (
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl px-6 py-12 text-center text-sm text-zinc-500">
                No hunts found. Create your first hunt to get started.
              </div>
            ) : (
              paginatedHunts.map(hunt => {
                const isExpanded = expandedHuntId === hunt.id;
                const isLoading = expandedLoading === hunt.id;
                const rows = expandedResults[hunt.id];
                const groupField = rows?.length ? getPrimaryGroupField(rows) : null;
                const groups = groupField && rows ? groupRowsByField(rows, groupField) : null;
                const groupEntries = groups ? Object.entries(groups).sort((a, b) => b[1].length - a[1].length) : [];

                return (
                  <div key={hunt.id} className={`bg-zinc-900 border rounded-xl overflow-hidden transition-all duration-200 ${isExpanded ? 'border-[#00D4AA]/40 shadow-lg shadow-[#00D4AA]/5' : 'border-zinc-800 hover:border-zinc-700'
                    }`}>

                    {/* Hunt Row — clickable to expand */}
                    <div
                      className="flex items-center gap-4 px-5 py-4 cursor-pointer"
                      onClick={() => handleExpandHunt(hunt)}
                    >
                      {/* Expand indicator */}
                      <div className={`w-5 h-5 flex items-center justify-center rounded transition-transform duration-200 ${isExpanded ? 'text-[#00D4AA]' : 'text-zinc-600'
                        } ${isExpanded ? 'rotate-90' : ''}`}>
                        <ChevronRight size={16} />
                      </div>

                      {/* Name + hypothesis */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-sm font-bold text-white truncate">{hunt.name}</span>
                          <span className={`shrink-0 px-1.5 py-0.5 text-[8px] font-black uppercase tracking-wider rounded ${hunt.type === 'visual' ? 'bg-blue-500/10 border border-blue-500/30 text-blue-400' : 'bg-purple-500/10 border border-purple-500/30 text-purple-400'
                            }`}>{hunt.type === 'visual' ? 'Visual' : 'SQL'}</span>
                          <span className="shrink-0 text-[9px] font-mono text-zinc-500">{hunt.logSource}</span>
                        </div>
                        <p className="text-[10px] text-zinc-600 truncate">{hunt.hypothesis}</p>
                      </div>

                      {/* Status + Matches + Date */}
                      <div className="flex items-center gap-5 shrink-0 text-right">
                        <div>
                          <div className={`text-[9px] font-bold uppercase ${hunt.status === 'completed' ? 'text-emerald-400' : hunt.status === 'running' ? 'text-amber-400' : 'text-red-400'
                            }`}>{hunt.status}</div>
                        </div>
                        <div>
                          <div className="text-base font-black text-white">{hunt.matchesFound}</div>
                          <div className="text-[9px] text-zinc-600 uppercase">matches</div>
                        </div>
                        <div className="text-[10px] text-zinc-500 whitespace-nowrap">
                          {hunt.lastRunAt ? new Date(hunt.lastRunAt).toLocaleDateString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '—'}
                        </div>
                        {/* Actions */}
                        <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                          <button onClick={() => handleRerunHunt(hunt)} title="Re-run"
                            className="p-1.5 bg-zinc-800 border border-zinc-700 text-zinc-400 rounded hover:bg-zinc-700 hover:text-emerald-400 transition-colors">
                            <RefreshCcw size={11} />
                          </button>
                          <button onClick={() => handleCopyHunt(hunt)} title="Copy to builder"
                            className="p-1.5 bg-zinc-800 border border-zinc-700 text-zinc-400 rounded hover:bg-zinc-700 transition-colors">
                            <Copy size={11} />
                          </button>
                          <button onClick={() => handleDeleteHunt(hunt.id)} title="Delete"
                            className="p-1.5 bg-zinc-800 border border-zinc-700 text-red-400/50 rounded hover:bg-red-500/10 hover:border-red-500/30 hover:text-red-400 transition-colors">
                            <Trash2 size={11} />
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Expanded: grouped result cards */}
                    {isExpanded && (
                      <div className="border-t border-zinc-800 px-5 pb-5 pt-4">
                        {isLoading ? (
                          <div className="flex items-center gap-3 py-6 justify-center">
                            <div className="w-5 h-5 border-2 border-[#00D4AA] border-t-transparent rounded-full animate-spin" />
                            <span className="text-sm text-zinc-500">Running hunt against data lake...</span>
                          </div>
                        ) : !rows ? (
                          <div className="text-sm text-zinc-600 py-4 text-center">Results not yet loaded.</div>
                        ) : rows.length === 0 ? (
                          <div className="text-sm text-zinc-600 py-6 text-center">
                            <Database size={24} className="mx-auto mb-2 text-zinc-700" />
                            No matches found in the current data lake for this hunt.
                          </div>
                        ) : (
                          <div>
                            <div className="flex items-center justify-between mb-3">
                              <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">
                                {groupEntries.length} unique {groupField || 'groups'} · {rows.length} total rows
                              </span>
                              <span className="text-[9px] text-zinc-600">Click a card to inspect evidence</span>
                            </div>
                            <div className="grid grid-cols-2 gap-2 xl:grid-cols-3">
                              {groupEntries.slice(0, 18).map(([groupKey, groupRows]) => {
                                const isActive = drawerGroup?.key === groupKey && expandedHuntId === hunt.id;
                                // pick 2 preview fields (not the group field itself)
                                const previewFields = Object.keys(groupRows[0])
                                  .filter(k => k !== groupField && groupRows[0][k] !== null && groupRows[0][k] !== undefined)
                                  .slice(0, 2);
                                // if there's a count column from GROUP BY, show it prominently
                                const countVal = groupRows[0]['count'] ?? groupRows[0]['COUNT(*)'] ?? groupRows[0]['occurrence_count'] ?? null;

                                return (
                                  <div
                                    key={groupKey}
                                    onClick={() => setDrawerGroup(isActive ? null : { key: groupKey, rows: groupRows })}
                                    className={`rounded-lg border p-3 cursor-pointer transition-all duration-150 ${isActive
                                      ? 'border-[#00D4AA]/50 bg-[#00D4AA]/5 shadow-md shadow-[#00D4AA]/10'
                                      : 'border-zinc-800 bg-zinc-800/40 hover:border-zinc-700 hover:bg-zinc-800/70'
                                      }`}
                                  >
                                    {/* Group key */}
                                    <div className="font-mono text-xs font-bold text-white truncate mb-1.5" title={groupKey}>
                                      {groupKey}
                                    </div>
                                    {/* Count or row count */}
                                    <div className="flex items-end justify-between gap-2">
                                      <div>
                                        {previewFields.map(f => (
                                          <div key={f} className="text-[9px] text-zinc-500 truncate">
                                            <span className="text-zinc-600">{f}: </span>
                                            <span className="text-zinc-400">{String(groupRows[0][f]).slice(0, 28)}</span>
                                          </div>
                                        ))}
                                      </div>
                                      <div className="shrink-0 text-right">
                                        <div className="text-base font-black text-[#00D4AA]">
                                          {countVal !== null ? countVal : groupRows.length}
                                        </div>
                                        <div className="text-[8px] text-zinc-600 uppercase">
                                          {countVal !== null ? 'count' : 'rows'}
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                );
                              })}
                              {groupEntries.length > 18 && (
                                <div className="col-span-full text-center text-[10px] text-zinc-600 pt-2">
                                  +{groupEntries.length - 18} more groups — refine your query to narrow results
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}

            {/* Pagination */}
            <div className="flex items-center justify-between pt-2">
              <div className="text-xs text-zinc-600 uppercase tracking-wider">
                Showing {paginatedHunts.length} of {filteredHunts.length} hunts
              </div>
              {totalPages > 1 && (
                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                    <button key={page} onClick={() => setHistoryPage(page)}
                      className={`w-8 h-8 rounded-lg text-xs font-bold transition-colors ${historyPage === page ? 'bg-[#00D4AA] text-black' : 'bg-zinc-900 border border-zinc-800 text-zinc-500 hover:text-white'
                        }`}>{page}</button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right: Evidence Drawer (slides in when a group is selected) */}
          {drawerGroup && (
            <div className="w-[42%] shrink-0 bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden flex flex-col sticky top-4 max-h-[80vh] animate-in slide-in-from-right duration-200">
              {/* Drawer Header */}
              <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800 shrink-0">
                <div className="min-w-0">
                  <div className="text-[9px] font-black text-zinc-500 uppercase tracking-widest mb-0.5">Evidence — {drawerGroup.rows.length} rows</div>
                  <div className="font-mono text-sm font-bold text-white truncate" title={drawerGroup.key}>{drawerGroup.key}</div>
                </div>
                <button onClick={() => setDrawerGroup(null)}
                  className="p-1.5 hover:bg-zinc-800 rounded-lg transition-colors shrink-0">
                  <X size={16} className="text-zinc-500" />
                </button>
              </div>

              {/* Drawer Body: raw rows */}
              <div className="flex-1 overflow-y-auto divide-y divide-zinc-800/50">
                {drawerGroup.rows.slice(0, 50).map((row, ri) => {
                  const cols = Object.entries(row).filter(([, v]) => v !== null && v !== undefined);
                  return (
                    <div key={ri} className="px-4 py-3 hover:bg-zinc-800/30 transition-colors">
                      <div className="text-[9px] font-black text-zinc-600 uppercase mb-2">Row #{ri + 1}</div>
                      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                        {cols.map(([key, value]) => (
                          <div key={key} className="flex flex-col min-w-0">
                            <span className="text-[8px] uppercase text-zinc-600 font-bold">{key}</span>
                            <span className={`text-[10px] font-mono truncate ${key === 'uid' ? 'text-cyan-400 cursor-pointer hover:underline' :
                              key.includes('ip') || key.includes('_h') ? 'text-blue-300' :
                                typeof value === 'number' ? 'text-purple-300' : 'text-zinc-300'
                              }`}
                              title={String(value)}
                              onClick={() => key === 'uid' ? handleUidClick(String(value)) : undefined}
                            >{String(value).slice(0, 40)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
                {drawerGroup.rows.length > 50 && (
                  <div className="px-4 py-3 text-center text-[10px] text-zinc-600">
                    Showing first 50 of {drawerGroup.rows.length} rows
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Hunt runs state for detail view
  const [huntRuns, setHuntRuns] = useState<any[]>([]);
  const [loadingRuns, setLoadingRuns] = useState(false);

  useEffect(() => {
    if (view === 'detail' && selectedHunt) {
      setLoadingRuns(true);
      huntApi.getRuns(selectedHunt.id).then(runs => {
        setHuntRuns(runs || []);
        setLoadingRuns(false);
      }).catch(() => setLoadingRuns(false));
    }
  }, [view, selectedHunt?.id]);

  const renderHuntDetail = () => {
    if (!selectedHunt) return null;

    return (
      <div className="animate-in fade-in duration-500 space-y-8">
        {/* Back + Breadcrumb */}
        <div className="flex items-center gap-4">
          <button
            onClick={() => setView('history')}
            className="p-3 bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-500 hover:text-white transition-all"
          >
            <ArrowLeft size={20} />
          </button>
          <Breadcrumbs current={selectedHunt.name} />
        </div>

        {/* Header */}
        <div>
          <div className="flex items-start justify-between mb-8">
            <div>
              <h1 className="text-2xl font-black text-white mb-2">{selectedHunt.name}</h1>
              <p className="text-sm text-zinc-500 mb-3 max-w-2xl">{selectedHunt.hypothesis}</p>
              <div className="flex items-center gap-4 text-xs text-zinc-500">
                <span className={`px-2 py-0.5 text-[9px] font-black uppercase tracking-wider rounded ${selectedHunt.type === 'visual'
                  ? 'bg-blue-500/10 border border-blue-500/30 text-blue-400'
                  : 'bg-purple-500/10 border border-purple-500/30 text-purple-400'
                  }`}>
                  {selectedHunt.type === 'visual' ? 'Visual Hunt' : 'SQL Hunt'}
                </span>
                <span>Log Source: <span className="text-white font-bold">{selectedHunt.logSource}</span></span>
                <span>•</span>
                <span>Time Range: <span className="text-white font-bold">{selectedHunt.timeRange}</span></span>
                <span>•</span>
                <span>Created {new Date(selectedHunt.createdAt).toLocaleDateString()}</span>
              </div>
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => handleCopyHunt(selectedHunt)}
                className="bg-zinc-800 border border-zinc-700 text-zinc-300 px-5 py-2.5 rounded-lg text-sm font-bold hover:bg-zinc-700 transition-all flex items-center gap-2"
              >
                <Copy size={16} /> Copy
              </button>
              <button
                onClick={() => handleRerunHunt(selectedHunt)}
                className="bg-emerald-500 hover:bg-emerald-400 text-black px-5 py-2.5 rounded-lg text-sm font-bold transition-all flex items-center gap-2"
              >
                <Play size={16} /> Re-run
              </button>
            </div>
          </div>

          {/* HUNT DEFINITION — Visual vs SQL */}
          <section className="bg-[#0f0f10] border border-zinc-800 rounded-xl p-6 mb-6">
            <h3 className="text-xs font-black text-zinc-500 uppercase tracking-widest mb-4">Hunt Definition</h3>

            {selectedHunt.type === 'visual' ? (
              /* ── VISUAL HUNT ── */
              <div className="space-y-4">
                {/* Stage 1 */}
                <div className="p-4 bg-black/40 border border-zinc-800/60 rounded-lg">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-6 h-6 rounded bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
                      <span className="text-emerald-400 font-black text-xs">1</span>
                    </div>
                    <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider">Stage 1 — {selectedHunt.logSource} Detection</span>
                  </div>
                  <div className="space-y-2">
                    {selectedHunt.conditions.map(cond => (
                      <div key={cond.id} className="text-sm text-zinc-300 font-mono">
                        <span className="text-white">{cond.field}</span>
                        <span className="text-emerald-400 mx-2">{cond.operator}</span>
                        <span className="text-white">{cond.value || '...'}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Stage 2 if multi-stage */}
                {selectedHunt.stages.length > 1 && (
                  <>
                    <div className="flex justify-center">
                      <div className="px-4 py-1.5 bg-zinc-900 border border-emerald-500/30 rounded text-[9px] font-black text-emerald-400 uppercase tracking-widest">
                        Correlated within 5 min
                      </div>
                    </div>
                    <div className="p-4 bg-black/40 border border-zinc-800/60 rounded-lg">
                      <div className="flex items-center gap-2 mb-3">
                        <div className="w-6 h-6 rounded bg-purple-500/20 border border-purple-500/40 flex items-center justify-center">
                          <span className="text-purple-400 font-black text-xs">2</span>
                        </div>
                        <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider">Stage 2 — HTTP Correlation</span>
                      </div>
                      <div className="text-sm text-zinc-400">
                        HTTP POST requests observed from the same source within the correlation window.
                      </div>
                    </div>
                  </>
                )}
              </div>
            ) : (
              /* ── SQL HUNT ── */
              <div className="bg-black/60 border border-zinc-800 rounded-lg overflow-hidden">
                <div className="px-4 py-2 border-b border-zinc-800 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-purple-500"></span>
                  <span className="text-[9px] font-black text-zinc-500 uppercase tracking-widest">SQL Query</span>
                </div>
                <pre className="p-4 text-sm text-emerald-300 font-mono whitespace-pre-wrap leading-relaxed max-h-[200px] overflow-y-auto">
                  {selectedHunt.sqlQuery || 'No query defined'}
                </pre>
              </div>
            )}
          </section>

          {/* HUNT RUNS — fetched from API */}
          <section className="bg-[#0f0f10] border border-zinc-800 rounded-lg p-6">
            <h3 className="text-xs font-black text-zinc-500 uppercase tracking-widest mb-4">Hunt Runs</h3>

            {loadingRuns ? (
              <div className="text-xs text-zinc-500 py-4">Loading runs...</div>
            ) : huntRuns.length === 0 ? (
              <div className="text-xs text-zinc-600 py-4">No runs yet. Click Re-run to execute this hunt.</div>
            ) : (
              <div className="space-y-1">
                <div className="grid grid-cols-12 gap-4 px-4 py-2 text-[10px] font-bold text-zinc-600 uppercase tracking-wider">
                  <div className="col-span-3">Executed At</div>
                  <div className="col-span-2">Time Range</div>
                  <div className="col-span-2">Duration</div>
                  <div className="col-span-1">Status</div>
                  <div className="col-span-2">Matches</div>
                  <div className="col-span-2 text-right">Action</div>
                </div>

                {huntRuns.map((run: any, idx: number) => (
                  <div key={run.id || idx} className="grid grid-cols-12 gap-4 px-4 py-3 bg-black/40 rounded-lg items-center hover:bg-zinc-800/30 transition-colors">
                    <div className="col-span-3 text-xs text-zinc-400">
                      {run.created_at ? new Date(run.created_at).toLocaleString('en-US', {
                        month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false
                      }) : '—'}
                    </div>
                    <div className="col-span-2 text-xs text-zinc-500">{selectedHunt.timeRange}</div>
                    <div className="col-span-2 text-xs text-zinc-400">{run.duration}s</div>
                    <div className="col-span-1">
                      <div className="flex items-center gap-1">
                        <div className={`w-1.5 h-1.5 rounded-full ${run.status === 'completed' ? 'bg-emerald-500' : 'bg-red-500'}`} />
                        <span className={`text-[9px] font-bold uppercase ${run.status === 'completed' ? 'text-emerald-400' : 'text-red-400'}`}>{run.status}</span>
                      </div>
                    </div>
                    <div className="col-span-2 text-xs font-bold text-white">{run.matches_found}</div>
                    <div className="col-span-2 text-right">
                      {run.matches_found > 0 ? (
                        <button
                          onClick={() => setFindingsSidebarOpen(true)}
                          className="text-[11px] font-bold text-emerald-400 hover:text-emerald-300 transition-colors flex items-center gap-1 ml-auto"
                        >
                          View Findings <ArrowRight size={12} />
                        </button>
                      ) : (
                        <span className="text-[11px] text-zinc-600">No findings</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      </div>
    );
  };

  const renderExecutionFindings = () => {
    if (!selectedHunt) return null;

    return (
      <div className="animate-in fade-in duration-500 space-y-8">
        <div className="flex items-center gap-4">
          <button
            onClick={() => setView('detail')}
            className="p-3 bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-500 hover:text-white transition-all"
          >
            <ArrowLeft size={20} />
          </button>
          <div>
            <Breadcrumbs current="Hunt Findings" />
          </div>
        </div>

        {/* Header */}
        <div>
          <h1 className="text-2xl font-black text-white mb-2">{selectedHunt.name} — Findings</h1>
          <div className="flex items-center gap-6 text-[12px] text-zinc-500">
            <span className={`px-2 py-0.5 text-[9px] font-black uppercase tracking-wider rounded ${selectedHunt.type === 'visual'
              ? 'bg-blue-500/10 border border-blue-500/30 text-blue-400'
              : 'bg-purple-500/10 border border-purple-500/30 text-purple-400'
              }`}>
              {selectedHunt.type === 'visual' ? 'Visual' : 'SQL'}
            </span>
            <span className="font-bold">{selectedHunt.matchesFound} correlated findings</span>
            <span>•</span>
            <span>Scanned {selectedHunt.dataProcessed} GB</span>
            <span>•</span>
            <span>Completed in {selectedHunt.duration}s</span>
          </div>
        </div>

        {/* Hunt Conditions Summary */}
        <div className="bg-zinc-900/50 border border-zinc-800 rounded-lg px-6 py-4">
          <div className="text-[10px] font-black text-zinc-500 uppercase tracking-widest mb-2">Hunt Conditions</div>
          <div className="flex flex-wrap gap-3">
            <span className="text-xs text-zinc-400">Log Source: <span className="text-white font-bold">{selectedHunt.logSource}</span></span>
            <span className="text-zinc-600">|</span>
            <span className="text-xs text-zinc-400">Time: <span className="text-white font-bold">{selectedHunt.timeRange}</span></span>
            <span className="text-zinc-600">|</span>
            {selectedHunt.conditions.map(c => (
              <span key={c.id} className="text-xs text-zinc-400">
                <span className="text-white font-mono">{c.field}</span>
                <span className="text-emerald-400 mx-1 font-bold">{c.operator}</span>
                <span className="text-white font-mono">{c.value}</span>
              </span>
            ))}
          </div>
        </div>

        {/* Finding Cards */}
        <div className="space-y-3">
          {(selectedHunt.matchesFound === 0) ? (
            <div className="text-center py-12 text-zinc-600 text-sm">No findings for this hunt yet</div>
          ) : (
            <div className="text-center py-12 text-zinc-500 text-sm">Hunt findings will appear here when investigations complete</div>
          )}
        </div>

        {/* Summary */}
        <div className="text-xs text-zinc-600 uppercase tracking-wider">
          {selectedHunt.matchesFound} findings
        </div>
      </div>
    );
  };

  const renderHuntResults = () => {
    if (!selectedHunt) return null;

    return (
      <div className="animate-in fade-in duration-500 space-y-8">
        {/* Header */}
        <div className="flex items-center gap-4">
          <button
            onClick={() => setView('findings')}
            className="p-3 bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-500 hover:text-white transition-all"
          >
            <ArrowLeft size={20} />
          </button>
          <div className="flex-1">
            <div className="flex items-center gap-4 mb-2">
              <h1 className="text-2xl font-black text-white">{selectedHunt.name}</h1>
              <span className={`px-3 py-1 text-xs font-bold uppercase rounded ${selectedHunt.type === 'visual'
                ? 'bg-blue-500/10 border border-blue-500/30 text-blue-400'
                : 'bg-purple-500/10 border border-purple-500/30 text-purple-400'
                }`}>
                {selectedHunt.type === 'visual' ? 'Visual Hunt' : 'SQL Hunt'}
              </span>
            </div>
            <div className="flex items-center gap-4 text-sm text-zinc-500">
              <span>{selectedHunt.id}</span>
              <span>•</span>
              <span>Log Source: {selectedHunt.logSource}</span>
              <span>•</span>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${selectedHunt.status === 'completed' ? 'bg-emerald-500' : 'bg-amber-500'
                  }`} />
                <span>{selectedHunt.status}</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button className="px-4 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm font-bold text-zinc-300 hover:bg-zinc-800 transition-all">
              Last 24 Hours
            </button>
            <button className="px-4 py-2 bg-emerald-500 text-black rounded-lg text-sm font-bold hover:bg-emerald-400 transition-all">
              Actions
            </button>
          </div>
        </div>

        {/* Main Finding Card */}
        <div className="bg-[#0f0f10] border border-[#1e1e20] rounded-xl p-6">
          <h1 className="text-3xl font-black text-white mb-6">C2 Beaconing Detection</h1>

          {/* Entity, Metric, Window */}
          <div className="space-y-3 pb-6 border-b border-zinc-800">
            <div className="flex items-start gap-3">
              <span className="text-sm text-zinc-500 w-20">Entity:</span>
              <span className="text-sm text-white font-medium">10.0.5.42</span>
            </div>
            <div className="flex items-start gap-3">
              <span className="text-sm text-zinc-500 w-20">Metric:</span>
              <span className="text-sm text-white font-medium">
                DNS queries &gt; <span className="text-white font-bold">10</span>
                <span className="text-zinc-500 mx-2">AND</span>
                HTTP POSTs &gt; <span className="text-white font-bold">3</span>
                <span className="text-zinc-500 mx-2">in</span>
                <span className="text-white font-bold">15 minutes</span>
              </span>
            </div>
            <div className="flex items-start gap-3">
              <span className="text-sm text-zinc-500 w-20">Window:</span>
              <span className="text-sm text-white font-medium">13:47 – 14:02</span>
            </div>
          </div>

          {/* Why This Matched */}
          <div className="py-6 border-b border-zinc-800">
            <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-4">Why this matched</h3>
            <div className="space-y-2">
              <div className="flex items-start gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-zinc-500 mt-2" />
                <span className="text-sm text-zinc-300">
                  Domain = <span className="text-white font-medium">duplex.com</span>
                </span>
              </div>
              <div className="flex items-start gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-zinc-500 mt-2" />
                <span className="text-sm text-zinc-300">
                  Queries &gt; <span className="text-white font-bold">10</span>
                  <span className="text-zinc-500 mx-2">AND</span>
                  HTTP POSTs &gt; <span className="text-white font-bold">3</span>
                  <span className="text-zinc-500 mx-2">in</span>
                  <span className="text-white font-bold">15 minutes</span>
                </span>
              </div>
            </div>
          </div>

          {/* Evidence Table */}
          <div className="pt-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-widest">
                Evidence (± 30 minutes)
              </h3>
            </div>

            {/* Table */}
            <div className="bg-black/40 border border-zinc-800 rounded-lg overflow-hidden">
              {/* Table Header */}
              <div className="grid grid-cols-5 gap-4 px-4 py-3 border-b border-zinc-800 bg-zinc-900/30">
                <div className="text-xs font-bold text-zinc-500 uppercase">Time</div>
                <div className="text-xs font-bold text-zinc-500 uppercase">Log</div>
                <div className="text-xs font-bold text-zinc-500 uppercase">Src IP</div>
                <div className="text-xs font-bold text-zinc-500 uppercase">Domain / Dest</div>
                <div className="text-xs font-bold text-zinc-500 uppercase">Method</div>
              </div>

              {/* Table Rows */}
              <div className="divide-y divide-zinc-800">
                <div className="grid grid-cols-5 gap-4 px-4 py-3 hover:bg-zinc-900/20 transition-colors">
                  <div className="text-sm text-zinc-300">13:45:12</div>
                  <div className="text-sm text-zinc-400">DNS</div>
                  <div className="text-sm text-zinc-300">10.0.5.42</div>
                  <div className="text-sm text-zinc-300">duplex.com</div>
                  <div className="text-sm text-zinc-500">-</div>
                </div>

                <div className="grid grid-cols-5 gap-4 px-4 py-3 hover:bg-zinc-900/20 transition-colors">
                  <div className="text-sm text-zinc-300">13:45:35</div>
                  <div className="text-sm text-zinc-400">DNS</div>
                  <div className="text-sm text-zinc-300">10.0.5.42</div>
                  <div className="text-sm text-zinc-300">duplex.com</div>
                  <div className="text-sm text-zinc-500">-</div>
                </div>

                <div className="grid grid-cols-5 gap-4 px-4 py-3 hover:bg-zinc-900/20 transition-colors">
                  <div className="text-sm text-zinc-300">13:46:05</div>
                  <div className="text-sm text-zinc-400">DNS</div>
                  <div className="text-sm text-zinc-300">10.0.5.42</div>
                  <div className="text-sm text-zinc-300">185.XX.XX.XX</div>
                  <div className="text-sm text-white font-medium">POST</div>
                </div>

                <div className="grid grid-cols-5 gap-4 px-4 py-3 hover:bg-zinc-900/20 transition-colors">
                  <div className="text-sm text-zinc-300">13:46:55</div>
                  <div className="text-sm text-zinc-400">HTTP</div>
                  <div className="text-sm text-zinc-300">10.0.5.42</div>
                  <div className="text-sm text-zinc-300">duplex.com</div>
                  <div className="text-sm text-zinc-500">-</div>
                </div>

                <div className="grid grid-cols-5 gap-4 px-4 py-3 hover:bg-zinc-900/20 transition-colors">
                  <div className="text-sm text-zinc-300">13:47:18</div>
                  <div className="text-sm text-zinc-400">DNS</div>
                  <div className="text-sm text-zinc-300">10.0.5.42</div>
                  <div className="text-sm text-zinc-300">duplex.com</div>
                  <div className="text-sm text-zinc-500">-</div>
                </div>
              </div>
            </div>

            {/* Context Window & Actions */}
            <div className="flex items-center justify-between mt-4">
              <div className="flex items-center gap-1">
                <span className="text-xs text-zinc-500">Context window:</span>
                <button className="px-3 py-1 bg-zinc-900 border-b-2 border-[#00D4AA] text-[#00D4AA] text-xs font-bold rounded-t">
                  30m
                </button>
                <button className="px-3 py-1 bg-zinc-900/50 text-zinc-500 text-xs font-bold hover:text-zinc-300 transition-colors">
                  1h
                </button>
                <button className="px-3 py-1 bg-zinc-900/50 text-zinc-500 text-xs font-bold hover:text-zinc-300 transition-colors">
                  24h
                </button>
              </div>

              <div className="flex items-center gap-3">
                <button className="px-4 py-2 bg-zinc-900 border border-zinc-800 text-zinc-300 text-sm font-bold rounded-lg hover:bg-zinc-800 transition-all">
                  Expand context
                </button>
                <button className="px-4 py-2 bg-[#00D4AA] text-black text-sm font-bold rounded-lg hover:bg-[#00c399] transition-all flex items-center gap-2">
                  <Search size={16} />
                  Open in Search
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };


  // State for findings sidebar results
  const [findingsData, setFindingsData] = useState<any[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [expandedFindingIdx, setExpandedFindingIdx] = useState<string | null>(null);
  const [groupLoadCounts, setGroupLoadCounts] = useState<Record<string, number>>({});

  // Fetch findings when sidebar opens
  useEffect(() => {
    if (findingsSidebarOpen && huntRuns.length > 0) {
      const latestRun = huntRuns[0];
      if (latestRun.id) {
        setLoadingFindings(true);
        setGroupLoadCounts({});
        setExpandedFindingIdx(null);
        fetch(`/api/v1/hunting/runs/${latestRun.id}`)
          .then(res => res.ok ? res.json() : null)
          .then(data => {
            if (data) setFindingsData(data.results || data.result_data?.evidence || []);
            setLoadingFindings(false);
          })
          .catch(() => setLoadingFindings(false));
      }
    }
  }, [findingsSidebarOpen]);

  // Group findings by detected source
  const groupFindings = (rows: any[]) => {
    if (!rows || rows.length === 0) return {};
    const keys = rows.length > 0 ? Object.keys(rows[0]) : [];
    const groups: Record<string, { keys: string[]; rows: any[] }> = {};

    // Detect source tables from columns ending in _uid
    const sources = keys.filter(k => k.endsWith('_uid')).map(k => k.replace('_uid', ''));

    if (sources.length > 1) {
      // Multi-log: group columns by source prefix
      const commonKeys = keys.filter(k => {
        return !sources.some(s => k.startsWith(s + '_'));
      });
      sources.forEach(source => {
        const prefix = source + '_';
        const matchingKeys = keys.filter(k => k.startsWith(prefix));
        groups[source] = {
          keys: [...commonKeys, ...matchingKeys],
          rows: rows.map(row => {
            const subset: any = {};
            [...commonKeys, ...matchingKeys].forEach(k => subset[k] = row[k]);
            return subset;
          })
        };
      });
    } else {
      // Single source
      const name = sources[0] || 'results';
      groups[name] = { keys, rows };
    }
    return groups;
  };

  // Build correlation summary
  const buildCorrelationSummary = (rows: any[]) => {
    if (!rows || rows.length === 0) return null;
    const keys = Object.keys(rows[0]);
    const srcKey = keys.find(k => k === 'source_host' || k === 'src_ip');
    const uniqueHosts = srcKey ? new Set(rows.map(r => r[srcKey])).size : 0;
    const uidSources: Record<string, number> = {};
    keys.filter(k => k.endsWith('_uid')).forEach(k => {
      const src = k.replace('_uid', '');
      uidSources[src] = new Set(rows.map(r => r[k]).filter(Boolean)).size;
    });
    return { totalMatches: rows.length, uniqueHosts, sources: uidSources, joinKey: srcKey || '' };
  };

  const navigateToLogs = (uid: string) => {
    window.location.href = `/logs-search?search=${encodeURIComponent(uid)}`;
  };

  const FindingsSidebar = () => {
    if (!findingsSidebarOpen || !selectedHunt) return null;

    const groups = groupFindings(findingsData);
    const summary = buildCorrelationSummary(findingsData);
    const groupNames = Object.keys(groups);
    const PER_GROUP = 6;

    const srcColorMap: Record<string, { text: string; bg: string; border: string }> = {
      conn: { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
      dns: { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
      http: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
      results: { text: 'text-zinc-400', bg: 'bg-zinc-800', border: 'border-zinc-700' },
    };

    return (
      <>
        <div className="fixed inset-0 bg-black/50 z-40" onClick={() => { setFindingsSidebarOpen(false); setExpandedFindingIdx(null); }} />
        <div className="fixed right-0 top-0 h-full w-[600px] bg-[#0a0a0b] border-l border-zinc-800 z-50 flex flex-col animate-in slide-in-from-right duration-300">
          {/* Header */}
          <div className="px-6 py-4 border-b border-zinc-800 shrink-0">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-black text-white mb-0.5">Hunt Findings</h2>
                <div className="flex items-center gap-3 text-[11px] text-zinc-500">
                  <span className="font-bold text-emerald-400">{findingsData.length} matches</span>
                  <span>•</span>
                  <span className="truncate max-w-[280px]">{selectedHunt.name}</span>
                </div>
              </div>
              <button onClick={() => { setFindingsSidebarOpen(false); setExpandedFindingIdx(null); }} className="p-2 hover:bg-zinc-900 rounded-lg">
                <X size={18} className="text-zinc-500" />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {loadingFindings ? (
              <div className="flex items-center justify-center py-12">
                <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
              </div>
            ) : findingsData.length === 0 ? (
              <div className="text-xs text-zinc-600 py-8 text-center">No results available.</div>
            ) : (
              <>
                {/* Correlation Summary */}
                {summary && (
                  <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5">
                    <h3 className="text-[10px] font-black text-zinc-500 uppercase tracking-widest mb-3">Correlation Summary</h3>
                    <div className="grid grid-cols-3 gap-4 mb-3">
                      <div>
                        <div className="text-2xl font-black text-white">{summary.totalMatches}</div>
                        <div className="text-[9px] text-zinc-600 uppercase font-bold">Matches</div>
                      </div>
                      <div>
                        <div className="text-2xl font-black text-emerald-400">{summary.uniqueHosts}</div>
                        <div className="text-[9px] text-zinc-600 uppercase font-bold">Unique Hosts</div>
                      </div>
                      <div>
                        <div className="text-2xl font-black text-blue-400">{groupNames.length}</div>
                        <div className="text-[9px] text-zinc-600 uppercase font-bold">Log Sources</div>
                      </div>
                    </div>
                    {Object.keys(summary.sources).length > 0 && (
                      <div className="flex items-center gap-2 pt-3 border-t border-zinc-800/50 flex-wrap">
                        {summary.joinKey && (
                          <>
                            <span className="text-[9px] text-zinc-600 font-bold">JOIN KEY:</span>
                            <span className="text-[10px] text-cyan-400 font-mono bg-cyan-500/5 border border-cyan-500/20 px-2 py-0.5 rounded">{summary.joinKey}</span>
                          </>
                        )}
                        {Object.entries(summary.sources).map(([src, count]) => {
                          const c = srcColorMap[src] || srcColorMap.results;
                          return (
                            <span key={src} className={`text-[9px] font-bold px-2 py-0.5 rounded ${c.bg} ${c.text} border ${c.border}`}>
                              {count} {src}
                            </span>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}

                {/* Grouped Results */}
                {groupNames.map(source => {
                  const group = groups[source];
                  const loadCount = groupLoadCounts[source] || PER_GROUP;
                  const visible = group.rows.slice(0, loadCount);
                  const hasMore = group.rows.length > loadCount;
                  const remaining = group.rows.length - loadCount;
                  const c = srcColorMap[source] || srcColorMap.results;

                  return (
                    <div key={source} className="space-y-2">
                      {/* Group Header */}
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`w-2 h-2 rounded-full ${c.bg} border ${c.border}`} style={{ boxShadow: '0 0 6px currentColor' }} />
                        <span className={`text-xs font-black uppercase tracking-wider ${c.text}`}>{source}.log</span>
                        <span className="text-[9px] text-zinc-600 font-mono">{group.rows.length} entries</span>
                      </div>

                      {/* Rows */}
                      {visible.map((row: any, idx: number) => {
                        const rk = `${source}-${idx}`;
                        const isExp = expandedFindingIdx === rk;
                        const rKeys = Object.keys(row);
                        const srcIp = row.source_host || row.src_ip || '';
                        const dstIp = row.conn_dest || row.dst_ip || '';
                        const uid = row[`${source}_uid`] || row.uid || '';
                        const label = srcIp && dstIp ? `${srcIp} → ${dstIp}` : rKeys[0] ? `${rKeys[0]}: ${row[rKeys[0]]}` : `#${idx + 1}`;

                        return (
                          <div key={rk} className={`bg-[#0f0f10] border rounded-lg overflow-hidden transition-colors ${isExp ? `${c.border}` : 'border-zinc-800/40 hover:border-zinc-700'}`}>
                            <button onClick={() => setExpandedFindingIdx(isExp ? null : rk)} className="w-full px-4 py-2.5 flex items-center justify-between text-left gap-2">
                              <div className="flex items-center gap-2 min-w-0 flex-1">
                                <span className="text-[8px] font-black text-zinc-700 shrink-0">#{idx + 1}</span>
                                <span className="text-xs text-white font-mono truncate">{label}</span>
                              </div>
                              {uid && (
                                <button onClick={(e) => { e.stopPropagation(); navigateToLogs(String(uid)); }}
                                  className="text-[9px] text-cyan-500 font-mono hover:text-cyan-300 shrink-0 flex items-center gap-0.5" title="Open in Log Search">
                                  <ExternalLink size={8} />{String(uid).substring(0, 10)}..
                                </button>
                              )}
                              <ChevronDown size={11} className={`text-zinc-700 shrink-0 transition-transform ${isExp ? 'rotate-180' : ''}`} />
                            </button>

                            {isExp && (
                              <div className="px-4 pb-3 border-t border-zinc-800/30">
                                <div className="grid grid-cols-2 gap-x-4 gap-y-1 mt-2">
                                  {rKeys.map(key => {
                                    const v = row[key];
                                    return (
                                      <div key={key} className="flex items-start gap-2 py-0.5 text-xs">
                                        <span className="text-zinc-600 font-bold uppercase text-[8px] w-24 shrink-0">{key}</span>
                                        {isUidColumn(key) && v ? (
                                          <button onClick={() => navigateToLogs(String(v))} className="text-cyan-400 font-mono hover:underline break-all text-left flex items-center gap-1">
                                            {String(v)}<ExternalLink size={8} />
                                          </button>
                                        ) : (
                                          <span className="text-zinc-300 font-mono break-all">{String(v ?? 'null')}</span>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}

                      {/* Load More */}
                      {hasMore && (
                        <button
                          onClick={() => setGroupLoadCounts(prev => ({ ...prev, [source]: (prev[source] || PER_GROUP) + PER_GROUP }))}
                          className={`w-full py-2 text-[10px] font-bold uppercase tracking-wider rounded-lg border border-dashed transition-colors ${c.border} ${c.text} hover:${c.bg}`}
                        >
                          Load {Math.min(PER_GROUP, remaining)} more {source} entries ({remaining} remaining)
                        </button>
                      )}
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </div>
      </>
    );
  };

  return (
    <div className="min-h-screen text-white">
      <div className="max-w-[1300px] mx-auto px-6">
        {view === 'builder' && renderHuntBuilder()}
        {view === 'history' && renderHuntHistory()}
        {view === 'detail' && renderHuntDetail()}
        {view === 'results' && renderHuntResults()}
        <FindingsSidebar />
      </div>

      {/* UID Detail Drawer */}
      {uidDrawerOpen && (
        <>
          <div
            className="fixed inset-0 bg-black/50 z-40"
            onClick={() => setUidDrawerOpen(false)}
          />
          <div className="fixed right-0 top-0 h-full w-[520px] bg-[#0a0a0b] border-l border-zinc-800 z-50 flex flex-col animate-in slide-in-from-right duration-300">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center">
                  <Fingerprint size={16} className="text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-sm font-black text-white uppercase tracking-wider">Zeek Log Entry</h3>
                  {uidDrawerData && (
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded ${uidDrawerData.table === 'conn' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                        : uidDrawerData.table === 'dns' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          : uidDrawerData.table === 'http' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                            : 'bg-zinc-800 text-zinc-400 border border-zinc-700'
                        }`}>
                        {uidDrawerData.table}.log
                      </span>
                      <span className="text-[10px] text-zinc-600 font-mono">{uidDrawerData.uid}</span>
                    </div>
                  )}
                </div>
              </div>
              <button
                onClick={() => setUidDrawerOpen(false)}
                className="p-2 hover:bg-zinc-900 rounded-lg transition-colors"
              >
                <X size={18} className="text-zinc-500" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto p-6">
              {uidDrawerLoading ? (
                <div className="flex items-center justify-center py-12">
                  <div className="w-5 h-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                </div>
              ) : uidDrawerData ? (
                <div className="space-y-1">
                  {Object.entries(uidDrawerData.fields).map(([key, value]) => (
                    <div key={key} className="flex items-start gap-4 py-2 px-3 rounded-lg hover:bg-zinc-900/50 transition-colors group">
                      <span className="text-[10px] font-black text-zinc-500 uppercase tracking-wider w-36 shrink-0 pt-0.5">{key}</span>
                      <span className={`text-xs font-mono break-all ${key === 'uid' ? 'text-cyan-400'
                        : key === 'src_ip' || key === 'id_orig_h' ? 'text-blue-300'
                          : key === 'dst_ip' || key === 'id_resp_h' ? 'text-amber-300'
                            : typeof value === 'number' ? 'text-purple-300'
                              : 'text-zinc-300'
                        }`}>
                        {value === null || value === undefined ? (
                          <span className="text-zinc-700 italic">null</span>
                        ) : (
                          String(value)
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-sm text-zinc-600">
                  UID not found in any log source
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default ThreatHuntingPage;

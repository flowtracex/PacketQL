import React, { useState, useMemo, useEffect, useRef } from 'react';
import { Search, ChevronRight, ChevronDown, X, Copy, Check, Database } from 'lucide-react';
import {
    getLogSources, getFieldsForSource, getFieldsForContext,
    type LogField, type FieldContext, type GroupedFields
} from '../../constants/fieldCatalogUtils';

// ─── Props ───────────────────────────────────────────────────
interface SchemaExplorerProps {
    context?: FieldContext;
    selectedSource?: string;
    onFieldClick?: (parquet: string, tableName: string) => void;
    mode?: 'sidebar' | 'modal';
    onClose?: () => void;
    className?: string;
}

// ─── Table Metadata ──────────────────────────────────────────
const TABLE_META: Record<string, { desc: string; use: string }> = {
    conn: { desc: 'Network connection records', use: 'C2 beaconing, lateral movement, exfiltration detection' },
    dns: { desc: 'DNS queries & responses', use: 'DNS tunneling, DGA domains, exfiltration over DNS' },
    http: { desc: 'HTTP request/response metadata', use: 'Malware downloads, suspicious uploads, web activity' },
    ssl: { desc: 'SSL/TLS handshake details', use: 'Expired certs, self-signed CAs, JA3 fingerprinting' },
    dhcp: { desc: 'DHCP lease assignments', use: 'IP tracking, rogue DHCP server detection' },
    smtp: { desc: 'Email traffic metadata', use: 'Phishing delivery, data exfiltration via email' },
    ftp: { desc: 'FTP file transfer activity', use: 'Unauthorized data movement, file transfer monitoring' },
    ssh: { desc: 'SSH connection details', use: 'Brute force, unauthorized remote access' },
    files: { desc: 'File analysis metadata', use: 'File transfers, hash lookups, malware detection' },
    x509: { desc: 'X.509 certificate details', use: 'Certificate validation, CA chain analysis' },
    pe: { desc: 'Portable Executable analysis', use: 'Malware analysis, suspicious binary detection' },
    sip: { desc: 'SIP/VoIP signaling', use: 'VoIP monitoring, toll fraud, unauthorized calls' },
    snmp: { desc: 'SNMP management traffic', use: 'Network device monitoring, unauthorized discovery' },
    rdp: { desc: 'Remote Desktop Protocol', use: 'Unauthorized remote access, BlueKeep scanning' },
    smb: { desc: 'SMB/CIFS file sharing', use: 'Lateral movement, ransomware propagation' },
    kerberos: { desc: 'Kerberos authentication', use: 'Kerberoasting, golden/silver ticket attacks' },
    ntlm: { desc: 'NTLM authentication', use: 'Pass-the-hash, NTLM relay attacks' },
    dce_rpc: { desc: 'DCE/RPC remote procedure calls', use: 'Lateral movement via WMI/DCOM, PsExec' },
    dpd: { desc: 'Dynamic Protocol Detection', use: 'Protocol mismatches, tunneled traffic' },
    notice: { desc: 'Zeek notices & alerts', use: 'Zeek-generated security notices' },
    weird: { desc: 'Protocol anomalies', use: 'Malformed packets, unusual protocol behavior' },
    software: { desc: 'Software version detection', use: 'Service inventory, vulnerable version detection' },
    tunnel: { desc: 'Tunnel encapsulation', use: 'GRE, IP-in-IP, Teredo tunnel detection' },
    syslog: { desc: 'Syslog messages', use: 'System log correlation with network events' },
};

// ─── Table Colors ─────────────────────────────────────────────
const TABLE_COLORS: Record<string, string> = {
    conn: '#3b82f6', dns: '#10b981', http: '#f59e0b', ssl: '#a855f7',
    dhcp: '#06b6d4', smtp: '#ef4444', ftp: '#f97316', ssh: '#ec4899',
    files: '#8b5cf6', x509: '#14b8a6', pe: '#64748b', sip: '#e879f9',
    snmp: '#84cc16', rdp: '#fb923c', smb: '#38bdf8', kerberos: '#facc15',
    ntlm: '#fb7185', dce_rpc: '#a78bfa', dpd: '#2dd4bf', notice: '#fbbf24',
    weird: '#f87171', software: '#34d399', tunnel: '#818cf8', syslog: '#c084fc',
};
const getTableColor = (name: string) => TABLE_COLORS[name.toLowerCase()] || '#71717a';

// ─── Type label ───────────────────────────────────────────────
const typeLabel = (type: string): { label: string; cls: string } => {
    const t = type.toLowerCase();
    if (t.includes('string') || t === 'varchar' || t === 'text') return { label: 'str', cls: 'text-emerald-500' };
    if (t.includes('bigint')) return { label: 'int64', cls: 'text-blue-400' };
    if (t.includes('int')) return { label: 'int', cls: 'text-blue-400' };
    if (t.includes('float') || t.includes('double')) return { label: 'float', cls: 'text-amber-400' };
    if (t.includes('bool')) return { label: 'bool', cls: 'text-purple-400' };
    if (t.includes('timestamp') || t.includes('time')) return { label: 'time', cls: 'text-cyan-400' };
    return { label: t.slice(0, 5), cls: 'text-zinc-500' };
};

// ─── Field Row — single clean line ────────────────────────────
const FieldRow: React.FC<{
    field: LogField;
    tableName: string;
    onClick?: (parquet: string, tableName: string) => void;
    highlight?: boolean;
}> = ({ field, tableName, onClick, highlight }) => {
    const [copied, setCopied] = useState(false);
    const { label: tLabel, cls: tCls } = typeLabel(field.type);

    const handleCopy = (e: React.MouseEvent) => {
        e.stopPropagation();
        navigator.clipboard.writeText(field.parquet);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };

    return (
        <div
            onClick={() => onClick?.(field.parquet, tableName)}
            className={`group flex items-baseline gap-0 px-4 py-1.5 transition-colors
                ${highlight ? 'bg-emerald-500/5' : ''}
                ${onClick ? 'cursor-pointer hover:bg-zinc-800/40' : 'hover:bg-zinc-800/20'}`}
        >
            {/* field name — fixed width column */}
            <span className={`w-44 shrink-0 text-[11px] font-mono font-semibold truncate
                ${highlight ? 'text-emerald-300' : 'text-zinc-200'}`}
                title={field.parquet}>
                {field.parquet}
            </span>

            {/* type label — fixed width */}
            <span className={`w-12 shrink-0 text-[9px] font-bold font-mono ${tCls}`}>
                {tLabel}
            </span>

            {/* description — takes remaining space */}
            <span className="flex-1 text-[10px] text-zinc-500 truncate leading-tight">
                {field.description || field.label || ''}
            </span>

            {/* copy on hover */}
            <button
                onClick={handleCopy}
                className="opacity-0 group-hover:opacity-100 transition-opacity ml-2 p-0.5 rounded shrink-0"
                title="Copy"
            >
                {copied
                    ? <Check size={11} className="text-emerald-400" />
                    : <Copy size={11} className="text-zinc-600 hover:text-zinc-300" />
                }
            </button>
        </div>
    );
};

// ─── Field Group — plain text divider ─────────────────────────
const FieldGroup: React.FC<{
    label: string;
    fields: LogField[];
    tableName: string;
    onFieldClick?: (parquet: string, tableName: string) => void;
    searchFilter?: LogField[];
    defaultOpen?: boolean;
}> = ({ label, fields, tableName, onFieldClick, searchFilter, defaultOpen = true }) => {
    const [open, setOpen] = useState(defaultOpen);
    const display = searchFilter
        ? fields.filter(f => searchFilter.some(sf => sf.parquet === f.parquet))
        : fields;

    if (display.length === 0) return null;

    return (
        <div>
            <button
                onClick={() => setOpen(!open)}
                className="w-full flex items-center gap-2 px-4 py-1.5 hover:bg-zinc-800/20 transition-colors"
            >
                {open
                    ? <ChevronDown size={10} className="text-zinc-700 shrink-0" />
                    : <ChevronRight size={10} className="text-zinc-700 shrink-0" />
                }
                <span className="text-[9px] font-black uppercase tracking-[0.18em] text-zinc-600">{label}</span>
                <span className="text-[9px] text-zinc-700 font-mono ml-auto">{display.length}</span>
            </button>
            {open && (
                <div>
                    {display.map(f => (
                        <FieldRow
                            key={f.parquet}
                            field={f}
                            tableName={tableName}
                            onClick={onFieldClick}
                            highlight={!!searchFilter}
                        />
                    ))}
                </div>
            )}
        </div>
    );
};

// ─── Main Component ──────────────────────────────────────────
const SchemaExplorer: React.FC<SchemaExplorerProps> = ({
    context,
    selectedSource,
    onFieldClick,
    mode = 'sidebar',
    onClose,
    className = '',
}) => {
    const [search, setSearch] = useState('');
    const [expandedTables, setExpandedTables] = useState<string[]>(
        selectedSource ? [selectedSource.toLowerCase()] : []
    );
    const searchRef = useRef<HTMLInputElement>(null);

    const allSources = useMemo(() => getLogSources(), []);

    const tableData = useMemo(() => {
        return allSources.map(name => {
            const fields: GroupedFields = context
                ? getFieldsForContext(name, context)
                : getFieldsForSource(name);
            return {
                name: name.toLowerCase(),
                fields,
                allFields: [...fields.mostUsed, ...fields.enriched, ...fields.others],
            };
        });
    }, [allSources, context]);

    const filteredTables = useMemo(() => {
        if (!search) return tableData;
        const q = search.toLowerCase();
        return tableData
            .map(t => {
                const nameMatch = t.name.includes(q);
                const matchingFields = t.allFields.filter(f =>
                    f.parquet.includes(q) ||
                    (f.label && f.label.toLowerCase().includes(q)) ||
                    f.name.toLowerCase().includes(q) ||
                    (f.description && f.description.toLowerCase().includes(q))
                );
                if (nameMatch || matchingFields.length > 0) {
                    return { ...t, filteredFields: nameMatch ? t.allFields : matchingFields };
                }
                return null;
            })
            .filter(Boolean) as (typeof tableData[0] & { filteredFields?: LogField[] })[];
    }, [tableData, search]);

    const toggleTable = (name: string) => {
        setExpandedTables(prev =>
            prev.includes(name) ? prev.filter(t => t !== name) : [...prev, name]
        );
    };

    useEffect(() => {
        if (search) setExpandedTables(filteredTables.map(t => t.name));
    }, [search]);

    useEffect(() => {
        setTimeout(() => searchRef.current?.focus(), 100);
    }, []);

    const totalFields = useMemo(() => tableData.reduce((s, t) => s + t.allFields.length, 0), [tableData]);
    const matchedCount = useMemo(() => {
        if (!search) return totalFields;
        return filteredTables.reduce((s, t) => s + ((t as any).filteredFields?.length || t.allFields.length), 0);
    }, [filteredTables, search, totalFields]);

    // ─── Panel content ────────────────────────────────────────
    const content = (
        <div className={`flex flex-col h-full bg-zinc-950 ${className}`}>

            {/* Header */}
            <div className="px-4 py-3.5 border-b border-zinc-800 flex items-center justify-between shrink-0">
                <div className="flex items-center gap-2.5">
                    <Database size={14} className="text-zinc-500" />
                    <div>
                        <span className="text-xs font-bold text-zinc-300">Schema Explorer</span>
                        <span className="text-[10px] text-zinc-600 ml-2">
                            {filteredTables.length} tables · {matchedCount} fields
                            {context && <> · <span className="text-emerald-400">{context}</span></>}
                        </span>
                    </div>
                </div>
                {onClose && (
                    <button onClick={onClose} className="p-1.5 hover:bg-zinc-800 rounded-lg transition-colors text-zinc-600 hover:text-zinc-300">
                        <X size={15} />
                    </button>
                )}
            </div>

            {/* Search */}
            <div className="px-3 py-2.5 border-b border-zinc-800 shrink-0">
                <div className="relative">
                    <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
                    <input
                        ref={searchRef}
                        type="text"
                        placeholder={onFieldClick ? "Search fields — click to insert" : "Search fields, tables, descriptions..."}
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-8 pr-8 py-2 text-[11px] text-zinc-300 outline-none focus:border-zinc-600 transition-all placeholder:text-zinc-700"
                    />
                    {search && (
                        <button
                            onClick={() => setSearch('')}
                            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-700 hover:text-zinc-400"
                        >
                            <X size={12} />
                        </button>
                    )}
                </div>
                {search && (
                    <p className="text-[9px] text-zinc-600 mt-1.5 px-1">
                        <span className="text-zinc-400 font-bold">{matchedCount}</span> fields in{' '}
                        <span className="text-zinc-400 font-bold">{filteredTables.length}</span> tables
                    </p>
                )}
            </div>

            {/* Column header */}
            <div className="flex items-center gap-0 px-4 py-1 border-b border-zinc-900 shrink-0">
                <span className="w-44 shrink-0 text-[8px] font-black uppercase tracking-widest text-zinc-700">Field</span>
                <span className="w-12 shrink-0 text-[8px] font-black uppercase tracking-widest text-zinc-700">Type</span>
                <span className="flex-1 text-[8px] font-black uppercase tracking-widest text-zinc-700">Description</span>
            </div>

            {/* Table list */}
            <div className="flex-1 overflow-y-auto">
                {filteredTables.map(table => {
                    const isExpanded = expandedTables.includes(table.name);
                    const color = getTableColor(table.name);
                    const meta = TABLE_META[table.name];
                    const hasFilteredFields = (table as any).filteredFields as LogField[] | undefined;

                    return (
                        <div key={table.name} className="border-b border-zinc-800/30">
                            {/* Table row */}
                            <button
                                onClick={() => toggleTable(table.name)}
                                className="w-full text-left px-3 py-2.5 hover:bg-zinc-900/60 transition-colors flex items-center gap-2.5 group"
                            >
                                {isExpanded
                                    ? <ChevronDown size={12} className="text-zinc-600 shrink-0" />
                                    : <ChevronRight size={12} className="text-zinc-600 shrink-0" />
                                }
                                <div
                                    className="w-2 h-2 rounded-full shrink-0"
                                    style={{ backgroundColor: color }}
                                />
                                <span className="text-[12px] font-bold text-zinc-300 group-hover:text-white transition-colors font-mono">
                                    {table.name}
                                </span>
                                {meta && (
                                    <span className="text-[10px] text-zinc-600 truncate flex-1 text-left">
                                        {meta.desc}
                                    </span>
                                )}
                                <span className="text-[9px] text-zinc-700 font-mono shrink-0 ml-auto">
                                    {hasFilteredFields
                                        ? <><span className="text-emerald-500">{hasFilteredFields.length}</span>/{table.allFields.length}</>
                                        : table.allFields.length
                                    }
                                </span>
                            </button>

                            {/* Expanded content */}
                            {isExpanded && (
                                <div className="bg-zinc-950/60">
                                    {/* SOC use case — compact single line */}
                                    {meta?.use && (
                                        <div className="px-4 py-1.5 border-b border-zinc-900/80">
                                            <span className="text-[9px] text-zinc-600 uppercase font-bold tracking-widest mr-2">Use:</span>
                                            <span className="text-[9px] text-zinc-500 leading-relaxed">{meta.use}</span>
                                        </div>
                                    )}

                                    <FieldGroup
                                        label="Most Used"
                                        fields={table.fields.mostUsed}
                                        tableName={table.name}
                                        onFieldClick={onFieldClick}
                                        searchFilter={hasFilteredFields}
                                        defaultOpen={true}
                                    />
                                    <FieldGroup
                                        label="Enriched"
                                        fields={table.fields.enriched}
                                        tableName={table.name}
                                        onFieldClick={onFieldClick}
                                        searchFilter={hasFilteredFields}
                                        defaultOpen={true}
                                    />
                                    <FieldGroup
                                        label="Other Fields"
                                        fields={table.fields.others}
                                        tableName={table.name}
                                        onFieldClick={onFieldClick}
                                        searchFilter={hasFilteredFields}
                                        defaultOpen={false}
                                    />

                                    {table.allFields.length === 0 && (
                                        <p className="px-4 py-4 text-[10px] text-zinc-700 italic text-center">
                                            No fields{context ? ` for "${context}"` : ''}
                                        </p>
                                    )}
                                </div>
                            )}
                        </div>
                    );
                })}

                {filteredTables.length === 0 && (
                    <div className="px-6 py-10 text-center">
                        <p className="text-xs text-zinc-600">No matches for "{search}"</p>
                    </div>
                )}
            </div>

            {/* Footer */}
            <div className="px-4 py-2 border-t border-zinc-800/50 text-[9px] text-zinc-700 flex items-center justify-between shrink-0">
                <span>zeek_field_catalog.json</span>
                <span className="text-zinc-800">{tableData.length} log sources</span>
            </div>
        </div>
    );

    if (mode === 'sidebar') {
        return (
            <div className="fixed inset-0 z-50 flex">
                <div
                    className="flex-1 bg-black/50 backdrop-blur-sm"
                    onClick={onClose}
                    style={{ animation: 'fadeIn 0.15s ease-out' }}
                />
                <div
                    className="w-[460px] h-full bg-zinc-950 border-l border-zinc-800 shadow-2xl flex flex-col"
                    style={{ animation: 'slideInRight 0.2s ease-out' }}
                >
                    {content}
                </div>
                <style>{`
                    @keyframes slideInRight { from { transform: translateX(100%); } to { transform: translateX(0); } }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                `}</style>
            </div>
        );
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
            style={{ animation: 'fadeIn 0.15s ease-out' }}>
            <div
                className="bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden w-[520px] max-h-[85vh] flex flex-col"
                style={{ animation: 'scaleIn 0.2s ease-out' }}
            >
                {content}
            </div>
            <style>{`
                @keyframes scaleIn { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
                @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            `}</style>
        </div>
    );
};

export default SchemaExplorer;

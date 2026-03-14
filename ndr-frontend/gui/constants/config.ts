/**
 * Centralized configuration constants for the RaceflowX NDR platform.
 * All hardcoded values (severities, statuses, MITRE tactics, etc.)
 * are defined here so every page and component references one source.
 */

// ─── Severity ────────────────────────────────────────────────
export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_COLORS: Record<Severity, string> = {
    critical: '#e11d48',
    high: '#f59e0b',
    medium: '#3b82f6',
    low: '#6b7280',
};

export const SEVERITY_BG: Record<Severity, string> = {
    critical: 'bg-[#e11d4820]',
    high: 'bg-[#f59e0b20]',
    medium: 'bg-[#3b82f620]',
    low: 'bg-[#6b728020]',
};

// ─── Alert Status ────────────────────────────────────────────
export const ALERT_STATUSES = ['new', 'investigating', 'resolved', 'dismissed', 'suppressed'] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

export const ALERT_STATUS_COLORS: Record<AlertStatus, string> = {
    new: '#ef4444',
    investigating: '#f59e0b',
    resolved: '#10b981',
    dismissed: '#6b7280',
    suppressed: '#8b5cf6',
};

// ─── Investigation Status ────────────────────────────────────
export const INVESTIGATION_STATUSES = ['new', 'active', 'escalated', 'on-hold', 'closed'] as const;
export type InvestigationStatus = (typeof INVESTIGATION_STATUSES)[number];

export const INVESTIGATION_STATUS_COLORS: Record<InvestigationStatus, string> = {
    new: '#ef4444',
    active: '#f59e0b',
    escalated: '#e11d48',
    'on-hold': '#8b5cf6',
    closed: '#10b981',
};

// ─── Verdict ─────────────────────────────────────────────────
export const VERDICTS = ['true_positive', 'false_positive', 'benign', 'pending'] as const;
export type Verdict = (typeof VERDICTS)[number];

export const VERDICT_LABELS: Record<Verdict, string> = {
    true_positive: 'True Positive',
    false_positive: 'False Positive',
    benign: 'Benign',
    pending: 'Pending',
};

export const VERDICT_COLORS: Record<Verdict, string> = {
    true_positive: '#e11d48',
    false_positive: '#6b7280',
    benign: '#10b981',
    pending: '#f59e0b',
};

// ─── MITRE ATT&CK Tactics (ordered by kill chain) ───────────
export const MITRE_TACTICS = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
] as const;
export type MitreTactic = (typeof MITRE_TACTICS)[number];

/** Subset shown in quick-filter dropdowns */
export const MITRE_TACTIC_FILTERS = [
    'all',
    'Command & Control',
    'Lateral Movement',
    'Exfiltration',
    'Defense Evasion',
    'Credential Access',
    'Initial Access',
] as const;

export const MITRE_TACTIC_COLORS: Record<string, string> = {
    'Initial Access': '#ef4444',
    'Execution': '#f97316',
    'Persistence': '#f59e0b',
    'Privilege Escalation': '#eab308',
    'Defense Evasion': '#84cc16',
    'Credential Access': '#22c55e',
    'Discovery': '#3b82f6',
    'Lateral Movement': '#f97316',
    'Collection': '#8b5cf6',
    'Command and Control': '#e11d48',
    'Exfiltration': '#eab308',
    'Impact': '#dc2626',
};

// ─── Kill Chain Stages (with example techniques) ─────────────
export const KILL_CHAIN_STAGES = [
    { name: 'Initial Access', tech: ['T1566 Phishing', 'T1190 Exploit Public App'] },
    { name: 'Execution', tech: ['T1059 Command Scripting', 'T1204 User Execution'] },
    { name: 'Persistence', tech: ['T1053 Scheduled Task', 'T1547 Boot Autostart'] },
    { name: 'Defense Evasion', tech: ['T1055 Process Injection', 'T1070 Indicator Removal'] },
    { name: 'Lateral Movement', tech: ['T1021 Remote Services', 'T1080 Taint Shared Content'] },
    { name: 'Exfiltration', tech: ['T1041 Exfil Over C2', 'T1567 Exfil to Cloud'] },
] as const;

// ─── Rule Types ──────────────────────────────────────────────
export const RULE_TYPES = ['custom_query', 'threshold', 'ml'] as const;
export type RuleType = (typeof RULE_TYPES)[number];

export const RULE_TYPE_LABELS: Record<RuleType, string> = {
    custom_query: 'Custom Query',
    threshold: 'Threshold',
    ml: 'ML / Behavioral',
};

export const RULE_SOURCES = ['system', 'custom'] as const;
export type RuleSource = (typeof RULE_SOURCES)[number];

// ─── Log Types ───────────────────────────────────────────────
export const LOG_TYPES = ['dns', 'http', 'tls', 'flow', 'smb', 'dhcp'] as const;
export type LogType = (typeof LOG_TYPES)[number];

export const LOG_TYPE_COLORS: Record<LogType, string> = {
    dns: '#3b82f6',
    http: '#10b981',
    tls: '#f59e0b',
    flow: '#8b5cf6',
    smb: '#ef4444',
    dhcp: '#6b7280',
};

// ─── Log Severity ────────────────────────────────────────────
export const LOG_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type LogSeverity = (typeof LOG_SEVERITIES)[number];

// ─── Asset Types ─────────────────────────────────────────────
export const ASSET_TYPES = ['server', 'workstation', 'network_device', 'iot', 'unknown'] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export const ASSET_TYPE_LABELS: Record<AssetType, string> = {
    server: 'Server',
    workstation: 'Workstation',
    network_device: 'Network Device',
    iot: 'IoT',
    unknown: 'Unknown',
};

// ─── Risk Levels ─────────────────────────────────────────────
export const RISK_LEVELS = ['critical', 'high', 'medium', 'low'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const RISK_FILTER_OPTIONS = ['all', 'critical', 'high', 'medium'] as const;
export type RiskFilter = (typeof RISK_FILTER_OPTIONS)[number];

// ─── Use Case Categories ─────────────────────────────────────
export const USE_CASE_CATEGORIES = [
    { id: 'MALWARE', label: 'Malware', color: 'red' },
    { id: 'EXFILTRATION', label: 'Exfiltration', color: 'blue' },
    { id: 'LATERAL_MOVEMENT', label: 'Lateral Movement', color: 'orange' },
    { id: 'RECONNAISSANCE', label: 'Reconnaissance', color: 'purple' },
] as const;

// ─── Coverage Source Types ───────────────────────────────────
export const COVERAGE_SOURCES = ['FLOW', 'DNS', 'SSL', 'HTTP', 'INTEL'] as const;
export type CoverageSourceType = (typeof COVERAGE_SOURCES)[number];

// ─── Time Ranges ─────────────────────────────────────────────
export const TIME_RANGES = ['Last 15m', 'Last 1h', 'Last 6h', 'Last 24h', 'Last 7d', 'Custom'] as const;
export const API_TIME_RANGES = ['1h', '24h', '7d', '30d'] as const;

// ─── Hunt Types ──────────────────────────────────────────────
export const HUNT_TYPES = ['visual', 'sql'] as const;
export type HuntType = (typeof HUNT_TYPES)[number];

// ─── Data Sources for Threat Hunting ─────────────────────────
export const HUNT_DATASOURCES = [
    { id: 'zeek_dns', label: 'Zeek DNS Logs', icon: 'Globe' },
    { id: 'zeek_http', label: 'Zeek HTTP Logs', icon: 'Globe' },
    { id: 'zeek_ssl', label: 'Zeek SSL/TLS Logs', icon: 'Shield' },
    { id: 'zeek_conn', label: 'Zeek Conn Logs', icon: 'Network' },
    { id: 'netflow', label: 'NetFlow Records', icon: 'Activity' },
    { id: 'alerts', label: 'Alert History', icon: 'AlertTriangle' },
] as const;

// ─── Protocol Names ──────────────────────────────────────────
export const PROTOCOLS = ['HTTP/HTTPS', 'DNS', 'SSH', 'SMB', 'RDP', 'TLS', 'DHCP', 'Other'] as const;

// ─── System Health Statuses ──────────────────────────────────
export const HEALTH_STATUSES = ['healthy', 'degraded', 'critical', 'unknown'] as const;
export type HealthStatus = (typeof HEALTH_STATUSES)[number];

// ─── Query Builder Operators ─────────────────────────────────
export const QUERY_OPERATORS = [
    { value: '==', label: 'equals' },
    { value: '!=', label: 'not equals' },
    { value: 'contains', label: 'contains' },
    { value: '>', label: 'greater than' },
    { value: '<', label: 'less than' },
    { value: 'in', label: 'in' },
    { value: 'not_in', label: 'not in' },
] as const;

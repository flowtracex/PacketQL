/**
 * Frontend API Service for RaceflowX NDR
 *
 * Connects to Django REST API for production data.
 * Falls back gracefully when API is unavailable.
 */

// @ts-ignore - Vite env may not have types in all configs
export const API_BASE = (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_API_URL) || '/api/v1';

// ─── Helpers ─────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T | null> {
    try {
        const res = await fetch(`${API_BASE}${path}`, {
            headers: {
                'Content-Type': 'application/json',
                ...options?.headers,
            },
            ...options,
        });
        if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
        return await res.json();
    } catch (error) {
        console.warn(`[API] ${path} failed:`, error);
        return null;
    }
}

// ─── Hunt API ────────────────────────────────────────────────────────

export interface HuntApiResponse {
    hunts: any[];
    total: number;
    page: number;
    page_count: number;
}

export interface HuntRunResponse {
    results: any[];
    total: number;
    executionTime: string;
    query: string;
    error?: string;
}

export const huntApi = {
    /**
     * List all hunts with optional filters and pagination.
     */
    list: (params?: { search?: string; status?: string; log_source?: string; page?: number; limit?: number }) => {
        const query = new URLSearchParams();
        if (params?.search) query.set('search', params.search);
        if (params?.status) query.set('status', params.status);
        if (params?.log_source) query.set('log_source', params.log_source);
        if (params?.page) query.set('page', String(params.page));
        if (params?.limit) query.set('limit', String(params.limit));
        return apiFetch<HuntApiResponse>(`/hunting/hunts?${query.toString()}`);
    },

    /**
     * Get a single hunt by ID.
     */
    get: (id: string) => apiFetch<any>(`/hunting/hunts/${id}`),

    /**
     * Save (create or update) a hunt.
     */
    save: (data: any) =>
        apiFetch<any>(`/hunting/hunts`, {
            method: 'POST',
            body: JSON.stringify(data),
        }),

    /**
     * Update an existing hunt.
     */
    update: (id: string, data: any) =>
        apiFetch<any>(`/hunting/hunts/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        }),

    /**
     * Delete a hunt.
     */
    delete: (id: string) =>
        apiFetch<any>(`/hunting/hunts/${id}`, {
            method: 'DELETE',
        }),

    /**
     * Run a hunt (execute query against Parquet data).
     */
    run: (params: { hunt_id?: string; query_type: 'sql' | 'visual'; query?: string; log_source?: string; conditions?: any[]; source_id?: string }) =>
        apiFetch<HuntRunResponse>(`/hunting/run`, {
            method: 'POST',
            body: JSON.stringify(params),
        }),

    /**
     * Get run history for a hunt.
     */
    getRuns: (huntId: string) => apiFetch<any[]>(`/hunting/hunts/${huntId}/runs`),
};

// ─── Log API ─────────────────────────────────────────────────────────

export const logApi = {
    /**
     * Search logs with filters.
     */
    search: (params: { source?: string; search?: string; time_range?: string; page?: number; limit?: number }) => {
        const query = new URLSearchParams();
        if (params.source) query.set('source', params.source);
        if (params.search) query.set('search', params.search);
        if (params.time_range) query.set('time_range', params.time_range);
        if (params.page) query.set('page', String(params.page));
        if (params.limit) query.set('limit', String(params.limit));
        return apiFetch<any>(`/logs/?${query.toString()}`);
    },

    /**
     * Get log analytics (source stats, top talkers, protocol distribution).
     */
    analytics: () => apiFetch<any>(`/logs/analytics/`),

    /**
     * Get available log sources.
     */
    sources: () => apiFetch<any[]>(`/logs/sources/`),
};

// ─── Detection API ───────────────────────────────────────────────────

export const detectionApi = {
    // Incidents (UC completions)
    incidents: (params?: {
        page?: number;
        limit?: number;
        search?: string;
        severity?: string[];
        status?: string[];
        category?: string;
        time_range?: string;
    }) => {
        const query = new URLSearchParams();
        if (params?.page) query.set('page', String(params.page));
        if (params?.limit) query.set('limit', String(params.limit));
        if (params?.search) query.set('search', params.search);
        if (params?.time_range) query.set('time_range', params.time_range);
        if (params?.category && params.category !== 'all') query.set('category', params.category);
        if (params?.severity?.length) {
            params.severity.forEach((s) => query.append('severity[]', s));
        }
        if (params?.status?.length) {
            params.status.forEach((s) => query.append('status[]', s));
        }
        return apiFetch<any>(`/detections/incidents?${query.toString()}`);
    },
    incidentDetail: (id: number) => apiFetch<any>(`/detections/incidents/${id}`),

    // Alerts (standalone signals)
    alerts: (params?: {
        page?: number;
        limit?: number;
        search?: string;
        severity?: string[];
        status?: string[];
        category?: string;
        mitre_tactic?: string;
        time_range?: string;
    }) => {
        const query = new URLSearchParams();
        if (params?.page) query.set('page', String(params.page));
        if (params?.limit) query.set('limit', String(params.limit));
        if (params?.search) query.set('search', params.search);
        if (params?.time_range) query.set('time_range', params.time_range);
        if (params?.category && params.category !== 'all') query.set('category', params.category);
        if (params?.mitre_tactic) query.set('mitre_tactic', params.mitre_tactic);
        if (params?.severity?.length) {
            params.severity.forEach((s) => query.append('severity[]', s));
        }
        if (params?.status?.length) {
            params.status.forEach((s) => query.append('status[]', s));
        }
        return apiFetch<any>(`/detections/alerts?${query.toString()}`);
    },
    alertDetail: (id: number) => apiFetch<any>(`/detections/alerts/${id}`),

    // Forensic drill-down (ftx_ids → contributing logs)
    contributingLogs: (ftxIds: string) => apiFetch<any>(`/detections/logs?ftx_ids=${encodeURIComponent(ftxIds)}`),

    // Overview stats
    overview: () => apiFetch<any>(`/detections/overview`),
    stats: (timeRange?: string) => {
        const q = timeRange ? `?time_range=${encodeURIComponent(timeRange)}` : '';
        return apiFetch<any>(`/detections/stats${q}`);
    },
};

// ─── Dashboard API ───────────────────────────────────────────────────

export const dashboardApi = {
    stats: () => apiFetch<any>(`/dashboard/stats/`),
    overview: () => apiFetch<any>(`/dashboard/overview/`),
};

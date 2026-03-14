/**
 * Centralized runtime configuration for the NDR platform.
 *
 * APP_MODE is first seeded from the Vite build-time env (falling back to 'production').
 * On startup, the app immediately calls /api/v1/system/config to get the live value
 * from the backend so no rebuild is required when .env changes.
 *
 * Downstream code should always read CONFIG.APP_MODE — never process.env.APP_MODE directly.
 */

export const CONFIG = {
  API_BASE_URL: '/api/v1',
  IS_PRODUCTION: true,
  DEFAULT_REFRESH_INTERVAL: 30000, // 30s
  MODE: (process.env.NDR_MODE || 'lite') as 'lite' | 'full',

  /**
   * Platform mode: 'production' | 'demo' | 'testing'
   * Seeded at build time via Vite. Overridden at runtime by initRuntimeConfig().
   * - production: all data from real API. No mock fallbacks.
   * - demo:       mock fallbacks allowed when API fails.
   * - testing:    same as production — no mock fallbacks.
   */
  APP_MODE: (process.env.APP_MODE || 'production') as 'production' | 'demo' | 'testing',
};

/**
 * Fetch APP_MODE from the live backend API and update CONFIG in-place.
 * Call this once at application startup (e.g. in main.tsx / App.tsx).
 * If the API is unreachable, the build-time value from .env is retained.
 */
export const initRuntimeConfig = async (): Promise<void> => {
  try {
    const res = await fetch(`${CONFIG.API_BASE_URL}/system/config`);
    if (!res.ok) return;
    const data = await res.json();
    if (data.app_mode && ['production', 'demo', 'testing'].includes(data.app_mode)) {
      CONFIG.APP_MODE = data.app_mode;
      console.log(`[CONFIG] Runtime APP_MODE loaded from API: ${CONFIG.APP_MODE}`);
    }
  } catch {
    console.warn(`[CONFIG] Could not fetch runtime config — using build-time APP_MODE: ${CONFIG.APP_MODE}`);
  }
};

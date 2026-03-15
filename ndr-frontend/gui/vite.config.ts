import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  // Load env from the root /opt/ndr directory where .env lives
  const envDir = path.resolve(__dirname, '../../');
  const env = loadEnv(mode, envDir, '');
  const apiProxyTarget = env.VITE_API_PROXY_TARGET || env.VITE_API_URL || 'http://127.0.0.1:8010';

  return {
    server: {
      port: 3000,
      host: '0.0.0.0',
      proxy: {
        '/api/v1': {
          target: apiProxyTarget,
          changeOrigin: true,
          secure: false,
        }
      },
    },
    plugins: [react()],
    define: {
      'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
      'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY),
      'process.env.NDR_MODE': JSON.stringify(env.NDR_MODE || 'lite'),
      'process.env.APP_MODE': JSON.stringify(env.APP_MODE || 'production')
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      }
    }
  };
});

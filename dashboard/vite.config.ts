import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite dev server proxies /v2 and /admin to the registry + scanner backend.
// In production the SPA is built and served behind the same origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/v2': { target: 'http://localhost:5000', changeOrigin: true, ws: true },
      '/admin': { target: 'http://localhost:5000', changeOrigin: true },
    },
  },
});

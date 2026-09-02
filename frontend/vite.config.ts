import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The built app is served by Flask from /static/ui/. index.html is served
// verbatim at "/" (and SPA fallback routes), so asset URLs must be absolute.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  base: '/static/ui/',
  build: {
    outDir: '../static/ui',
    emptyOutDir: true,
    manifest: false,
    rollupOptions: {
      output: {
        manualChunks: {
          charts: ['recharts'],
          graph: ['react-force-graph-2d'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:5005',
      '/agent': 'http://localhost:5005',
      '/socket.io': { target: 'http://localhost:5005', ws: true },
    },
  },
});

/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';

// El portal se sirve bajo /portal/ (nginx). En desarrollo, las llamadas a la API se
// reenvían al backend FastAPI (variable VITE_API_PROXY, por defecto el mock local).
export default defineConfig({
  base: '/portal/',
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, 'src') } },
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      ['/portal/api', '/portal/auth', '/portal/data', '/feeds'].map((p) => [
        p,
        { target: process.env.VITE_API_PROXY ?? 'http://127.0.0.1:8791', changeOrigin: true },
      ]),
    ),
  },
  build: {
    sourcemap: false,
    // Las fuentes nunca se incrustan como data: (la CSP de nginx solo permite font-src 'self').
    assetsInlineLimit: (file: string) => (/\.(woff2?|ttf|otf)$/.test(file) ? false : undefined),
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('node_modules/recharts') || id.includes('node_modules/d3-')) return 'charts';
          if (id.includes('node_modules/marked') || id.includes('node_modules/dompurify')) return 'md';
          if (
            id.includes('node_modules/react') ||
            id.includes('node_modules/@radix-ui') ||
            id.includes('node_modules/scheduler')
          )
            return 'react';
          return undefined;
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
  },
});

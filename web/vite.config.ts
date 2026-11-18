import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The build is embedded into the Go binary (web/embed.go). The Go server
// serves /assets/* with immutable caching and falls back to index.html for
// client-side routes.
const backend = process.env.ENTREPOT_URL ?? 'http://localhost:8080';

export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    // dist/ is inside the project root; empty it explicitly (postbuild
    // recreates dist/.gitkeep, which go:embed and git rely on).
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router'],
          mantine: ['@mantine/core', '@mantine/hooks', '@mantine/notifications'],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': backend,
      '/auth': backend,
      '/repository': backend,
      '/v2': backend,
    },
  },
});

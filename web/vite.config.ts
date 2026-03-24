import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  root: '.',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        landing: resolve(__dirname, 'index.html'),
        scan: resolve(__dirname, 'scan.html'),
      },
    },
  },
});

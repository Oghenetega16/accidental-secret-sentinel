import { defineConfig } from 'vite';
import { resolve } from 'path';
import { fileURLToPath } from 'url';

// __dirname is not available in ESM — derive it from import.meta.url
const __dirname = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      input: {
        // TS entries only — HTML files stay at project root and reference
        // the built JS files in dist/ directly via <script src="dist/...">
        background: resolve(__dirname, 'src/background/service-worker.ts'),
        content:    resolve(__dirname, 'src/content/content.ts'),
        popup:      resolve(__dirname, 'src/popup/popup.ts'),
        panel:      resolve(__dirname, 'src/devtools/panel.ts'),
        options:    resolve(__dirname, 'src/options/options.ts'),
        relay:      resolve(__dirname, 'src/content/relay.ts'),
        'devtools-init': resolve(__dirname, 'src/devtools/devtools-init.ts'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
      },
    },
    // Keep output readable during development
    minify: false,
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
});
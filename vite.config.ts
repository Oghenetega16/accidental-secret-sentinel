import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background/service-worker.ts'),
        content: resolve(__dirname, 'src/content/content.ts'),
        intercept: resolve(__dirname, 'src/content/fetch-intercept.ts'), // <-- Add this
        popup: resolve(__dirname, 'popup.html'),
        // options: resolve(__dirname, 'options.html'),
        devtools: resolve(__dirname, 'devtools.html'),
      },
      output: {
        manualChunks: undefined,
        inlineDynamicImports: true,
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
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
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup/index.html'),
        devtools: resolve(__dirname, 'devtools/devtools.html'),
        panel: resolve(__dirname, 'devtools/panel.html'),
        background: resolve(__dirname, 'background/background.js'),
        content: resolve(__dirname, 'content/content.js'),
        heuristics: resolve(__dirname, 'background/heuristics.js'),
        devtoolsScript: resolve(__dirname, 'devtools/devtools.js')
      },
      output: {
        entryFileNames: (assetInfo) => {
          if (['background', 'content', 'heuristics'].includes(assetInfo.name)) {
            return `${assetInfo.name}/${assetInfo.name}.js`;
          }
          if (assetInfo.name === 'devtoolsScript') return 'devtools/devtools.js';
          return 'assets/[name]-[hash].js';
        }
      }
    }
  }
});

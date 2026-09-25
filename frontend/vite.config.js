import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig(() => {
  // Dev server only: /api/* is proxied to the local backend (override with
  // BACKEND_URL). Production builds call VITE_API_URL directly (see api.js).
  const backendUrl = process.env.BACKEND_URL || 'http://127.0.0.1:8001';
  const wsBackendUrl = backendUrl.replace(/^http/, 'ws');

  return {
    plugins: [
      tailwindcss(),
      react(),
    ],
    server: {
      proxy: {
        '/api': {
          target: backendUrl,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, '')
        },
        '/ws': {
          target: wsBackendUrl,
          ws: true,
          changeOrigin: true
        }
      }
    }
  }
})


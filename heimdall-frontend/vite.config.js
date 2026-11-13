import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { compression } from 'vite-plugin-compression2'

export default defineConfig({
  plugins: [
    react(),
    // Pre-compressed assets: static hosts serve .br/.gz without spending CPU per request.
    compression({ algorithm: 'brotliCompress', exclude: [/\.(br|gz)$/, /\.(woff2|png)$/], threshold: 1024 }),
    compression({ algorithm: 'gzip', exclude: [/\.(br|gz)$/, /\.(woff2|png)$/], threshold: 1024 }),
  ],
  build: {
    target: 'es2020',
    cssCodeSplit: true,
    reportCompressedSize: true,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
        },
      },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true, rewrite: (path) => path.replace(/^\/api/, '') },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})

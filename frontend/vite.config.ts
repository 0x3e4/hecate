import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { manualChunks } from './vite/chunk-split'

// The config runs in Node; declared here instead of pulling in @types/node for one field.
declare const process: { env: Record<string, string | undefined> };

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        // Docker Compose default; VITE_PROXY_TARGET points a local dev server at another backend
        target: process.env.VITE_PROXY_TARGET || "http://backend:8000",
        changeOrigin: true
      }
    }
  },
  build: {
     rollupOptions: {
        output: { manualChunks },
      },
    outDir: "dist"
  }
});

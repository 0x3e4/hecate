import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { manualChunks } from './vite/chunk-split'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://backend:8000",
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

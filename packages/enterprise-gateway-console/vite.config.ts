import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: process.env.VITE_AGENTNEXUS_GATEWAY_API_TARGET ?? "http://127.0.0.1:8080",
        changeOrigin: true
      },
      "/v1": {
        target: process.env.VITE_AGENTNEXUS_GATEWAY_AGENT_TARGET ?? "http://127.0.0.1:8081",
        changeOrigin: true
      }
    }
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test-setup.ts"
  }
});

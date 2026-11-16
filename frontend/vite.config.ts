import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: Object.fromEntries(
      ["/api", "/health", "/mcp", "/.well-known", "/metrics"].map((path) => [
        path,
        { target: process.env.GATEWAY_PROXY ?? "http://127.0.0.1:8000" },
      ]),
    ),
  },
});

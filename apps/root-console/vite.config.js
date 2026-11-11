import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv } from "vite";

// Separate app, separate origin (port 5174). In development `/api` is proxied to the API so the HttpOnly platform session
// cookie is first-party to this app. Deployment is out of scope.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  return {
    plugins: [react(), tailwindcss()],
    resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
    server: {
      port: 5174,
      strictPort: true,
      proxy: {
        "/api": { target: env.VITE_DEV_API_TARGET || "http://localhost:3000", changeOrigin: false },
      },
    },
  };
});

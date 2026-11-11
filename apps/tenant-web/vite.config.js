import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv } from "vite";

// In development the browser talks to the Vite origin and `/api` is proxied to the API, so the HttpOnly session cookie
// is first-party and no CORS preflight is needed. Production serves both behind one origin (deployment is out of scope).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  return {
    plugins: [react(), tailwindcss()],
    resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        "/api": { target: env.VITE_DEV_API_TARGET || "http://localhost:3000", changeOrigin: false },
      },
    },
  };
});

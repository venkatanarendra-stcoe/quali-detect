import { defineConfig } from "prisma/config";

// With a Prisma config file the CLI no longer reads .env by itself: load packages/db/.env here when it exists.
try {
  process.loadEnvFile(new URL("./.env", import.meta.url));
} catch {
  // no .env file: DATABASE_URL must come from the environment
}

export default defineConfig({
  schema: "prisma/schema",
  migrations: { path: "prisma/migrations", seed: "node prisma/seed.js" },
});

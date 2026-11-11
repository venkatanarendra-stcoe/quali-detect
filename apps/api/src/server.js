import { buildApp } from "./app.js";
import { ConfigError, describeConfig, loadConfig } from "./config/index.js";

let config;
try {
  config = loadConfig();
} catch (error) {
  if (!(error instanceof ConfigError)) throw error;
  console.error(error.message);
  process.exit(1);
}

const app = await buildApp({ config });

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, async () => {
    app.log.info({ signal }, "Shutting down");
    await app.close();
    process.exit(0);
  });
}

try {
  await app.listen({ host: config.http.host, port: config.http.port });
  app.log.info(describeConfig(config), "API started");
} catch (error) {
  app.log.fatal({ err: error }, "API failed to start");
  process.exit(1);
}

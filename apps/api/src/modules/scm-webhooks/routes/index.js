import { z } from "zod";
import { apiErrorSchema, createSuccessSchema } from "@qmentisai/contracts";
import { OPENAPI_TAG } from "../constants/index.js";

const receivedSchema = createSuccessSchema(z.object({ received: z.literal(true) }));

/**
 * The GitHub webhook endpoint: PUBLIC and unauthenticated by session; the HMAC signature (`X-Hub-Signature-256`) is the
 * authentication. The route kit reads the raw body, applies the `webhook` rate-limit profile and never runs session auth.
 * @param {ReturnType<typeof import("../controllers/index.js").createWebhookController>} controller
 * @param {{ webhookBodyLimitBytes: number }} settings
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const webhookRoutes = (controller, settings) =>
  async function webhooks(app) {
    app.post(
      "/webhooks/github",
      {
        config: { audience: "public" },
        webhook: { limitBytes: settings.webhookBodyLimitBytes },
        rateLimit: "webhook",
        schema: {
          tags: [OPENAPI_TAG],
          summary:
            "GitHub App webhook (authenticated by X-Hub-Signature-256; every validly signed delivery answers 202)",
          response: { 202: receivedSchema, 400: apiErrorSchema, 401: apiErrorSchema },
        },
      },
      controller.receive,
    );
  };

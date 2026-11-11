import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError, ValidationError } from "../../../errors/app-error.js";
import { DELIVERY_ID, EVENT_NAME } from "../constants/index.js";

/**
 * HTTP adapter of the GitHub webhook. Order is the security contract: signature over the raw bytes FIRST, then parse, then
 * header validation, then ingestion. Any validly signed delivery is answered `202 { received: true }` regardless of what
 * happened to it.
 * @param {{ service: ReturnType<typeof import("../services/index.js").createWebhookService>, logger: import("pino").Logger }} deps
 */
export function createWebhookController({ service, logger }) {
  return {
    receive: async (request, reply) => {
      const raw = request.body;
      if (!Buffer.isBuffer(raw) || raw.length === 0)
        throw new AppError(
          ERROR_CODES.UNSUPPORTED_MEDIA_TYPE,
          "The request content type is not supported.",
        );
      if (!service.verifySignature(raw, request.get("x-hub-signature-256"))) {
        logger.warn(
          { metric: "scm_webhook_signature_failures_total", ip: request.ip },
          "GitHub webhook signature rejected",
        );
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, "The signature is not valid.");
      }
      let payload;
      try {
        payload = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new ValidationError(
          [{ path: "", code: "invalid_json", message: "The body is not valid JSON." }],
          { source: "body" },
        );
      }
      const deliveryId = request.get("x-github-delivery");
      const event = request.get("x-github-event");
      if (
        !DELIVERY_ID.test(deliveryId ?? "") ||
        !EVENT_NAME.test(event ?? "") ||
        typeof payload !== "object" ||
        payload === null ||
        Array.isArray(payload)
      )
        throw new ValidationError(
          [
            {
              path: "headers",
              code: "invalid_headers",
              message: "Missing or malformed delivery headers.",
            },
          ],
          { source: "headers" },
        );
      await service.ingest({ deliveryId, event, payload, raw });
      return reply.code(202).success({ received: true });
    },
  };
}

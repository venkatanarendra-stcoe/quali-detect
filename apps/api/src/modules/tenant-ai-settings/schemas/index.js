import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";

/** PUT body. Strict: an unknown key (including `tenantId`) is a 400, never ignored. */
export const updateAiSettingsBodySchema = z.object({ externalConsent: z.boolean() }).strict();

/** No query parameters: a `tenantId` there is a 400. */
export const noQuerySchema = z.object({}).strict();

/** The tenant's AI settings. Never carries the model name, a base URL or any key. */
export const aiSettingsResponseSchema = createSuccessSchema(
  z.object({
    externalConsent: z.boolean(),
    assistant: z.object({
      configured: z.boolean(),
      providerKind: z.enum(["local", "external"]).nullable(),
    }),
    updatedAt: z.string().nullable(),
    consentChangedAt: z.string().nullable(),
  }),
);

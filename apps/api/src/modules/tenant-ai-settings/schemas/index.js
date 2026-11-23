import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";

/**
 * PUT body. Strict: an unknown key (including `tenantId`) is a 400, never ignored. At least one of the two consent tiers is sent
 * (ADR-013 addendum): `externalConsent` (metadata) and `codeSnippetConsent` (source excerpts, implies the first).
 */
export const updateAiSettingsBodySchema = z
  .object({ externalConsent: z.boolean().optional(), codeSnippetConsent: z.boolean().optional() })
  .strict()
  .refine((b) => b.externalConsent !== undefined || b.codeSnippetConsent !== undefined, {
    message: "Send externalConsent, codeSnippetConsent or both.",
  })
  .refine((b) => !(b.externalConsent === false && b.codeSnippetConsent === true), {
    path: ["codeSnippetConsent"],
    message: "Code excerpts need the metadata consent.",
  });

/** No query parameters: a `tenantId` there is a 400. */
export const noQuerySchema = z.object({}).strict();

/** The tenant's AI settings. Never carries the model name, a base URL or any key. */
export const aiSettingsResponseSchema = createSuccessSchema(
  z.object({
    externalConsent: z.boolean(),
    codeSnippetConsent: z.boolean(),
    assistant: z.object({
      configured: z.boolean(),
      providerKind: z.enum(["local", "external"]).nullable(),
    }),
    updatedAt: z.string().nullable(),
    consentChangedAt: z.string().nullable(),
    consentChangedBy: z.object({ displayName: z.string() }).strict().nullable(),
  }),
);

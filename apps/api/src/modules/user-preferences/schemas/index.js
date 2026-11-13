import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";
import { accentKeySchema } from "@qmentisai/shared";
import { atLeastOne } from "../../../lib/http.js";

/**
 * PUT body: the preferences to set. Strict (an unknown field, including `userId` or `tenantId`, is a 400) and never empty.
 * Preferences not sent keep their value.
 */
export const updatePreferencesBodySchema = atLeastOne(
  z.object({ accent: accentKeySchema }).partial(),
);

/** No query parameters: a `userId` or `tenantId` there is a 400, never ignored silently. */
export const noQuerySchema = z.object({}).strict();

/** Preferences as the client sees them: every preference always has a value (the default when never chosen). */
export const preferencesResponseSchema = createSuccessSchema(z.object({ accent: accentKeySchema }));

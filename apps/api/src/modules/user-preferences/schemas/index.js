import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";
import { accentKeySchema } from "@qmentisai/shared";
import { atLeastOne } from "../../../lib/http.js";

/**
 * PUT body: the preferences to set. Strict (an unknown field, including `userId` or `tenantId`, is a 400) and never empty.
 * Preferences not sent keep their value.
 */
export const updatePreferencesBodySchema = atLeastOne(
  z.object({ accent: accentKeySchema, defaultWorkspaceId: z.string().uuid().nullable() }).partial(),
);

/** No query parameters: a `userId` or `tenantId` there is a 400, never ignored silently. */
export const noQuerySchema = z.object({}).strict();

/** Preferences as the client sees them: every preference always has a value (the default when never chosen). */
export const preferencesResponseSchema = createSuccessSchema(
  z.object({ accent: accentKeySchema, defaultWorkspaceId: z.string().uuid().nullable() }),
);

/**
 * Where the signed-in user lands (`GET /me/landing`): decided at request time from the caller's CURRENT permissions.
 * `workspace` carries the workspace id (the dashboard of that workspace), `overview` is the Organization Overview and
 * `none` means nothing is accessible (the client shows its empty state). Never a name, count or any other workspace data.
 */
export const landingResponseSchema = createSuccessSchema(
  z.object({
    target: z.enum(["workspace", "overview", "none"]),
    workspaceId: z.string().uuid().nullable(),
  }),
);

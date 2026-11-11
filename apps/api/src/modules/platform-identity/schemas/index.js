import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";

export const platformLoginBodySchema = z
  .object({
    email: z.string().trim().toLowerCase().email().max(254),
    password: z.string().min(1).max(256),
  })
  .strict();

const platformUserDto = z.object({
  id: z.string(),
  email: z.string(),
  name: z.string(),
  status: z.string(),
});

export const platformMfaBodySchema = z
  .object({
    code: z
      .string()
      .trim()
      .regex(/^\d{6}$/, "Enter the 6-digit code."),
  })
  .strict();

/** `mfaRequired` is always true for platform sign-in: the session is unusable until `POST /auth/mfa/verify` succeeds. */
export const platformLoginResponseSchema = createSuccessSchema(
  z.object({ platformUser: platformUserDto, mfaRequired: z.literal(true) }),
);
export const platformMfaResponseSchema = createSuccessSchema(
  z.object({ platformUser: platformUserDto, mfaVerified: z.literal(true) }),
);
export const platformLogoutResponseSchema = createSuccessSchema(
  z.object({ loggedOut: z.literal(true) }),
);
export const platformMeResponseSchema = createSuccessSchema(
  z.object({
    platformUser: platformUserDto,
    role: z.object({ key: z.string(), name: z.string() }),
    permissions: z.array(z.string()),
    session: z.object({ expiresAt: z.string(), authMethod: z.string(), mfaVerified: z.boolean() }),
  }),
);

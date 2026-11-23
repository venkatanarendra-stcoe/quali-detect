import {
  FINDINGS_LIMITS as L,
  FINDING_SEVERITIES,
  hasCredentialShape,
  pullRequestUrlSchema,
} from "@qmentisai/shared";
import { z } from "zod";
import { CREDENTIAL_SHAPE_TEXT } from "../constants/index.js";

/**
 * Form schemas of the Findings dialogs (React Hook Form). They mirror the FROZEN request schemas of `@qmentisai/shared` for
 * length and credential shape so the user sees the refusal before sending; the service parses the body with the shared schema
 * again, and the server a third time. Messages are plain sentences (SCREENS 1, 5).
 */

const text = (min, max, minMessage) =>
  z
    .string()
    .trim()
    .min(min, minMessage ?? `Enter at least ${min} characters.`)
    .max(max, `Use at most ${max.toLocaleString()} characters.`)
    .refine((v) => !hasCredentialShape(v), CREDENTIAL_SHAPE_TEXT);
const optionalText = (max) =>
  z
    .string()
    .trim()
    .max(max, `Use at most ${max.toLocaleString()} characters.`)
    .refine((v) => !hasCredentialShape(v), CREDENTIAL_SHAPE_TEXT);

export const decisionFormSchema = z
  .object({
    decision: z.enum(["true_positive", "false_positive"], {
      errorMap: () => ({ message: "Choose true positive or false positive." }),
    }),
    rationale: text(L.rationaleMin, L.rationaleMax),
    severityOverride: z.enum(["", ...FINDING_SEVERITIES]),
  })
  .superRefine((v, ctx) => {
    if (v.severityOverride && v.decision !== "true_positive")
      ctx.addIssue({
        code: "custom",
        path: ["severityOverride"],
        message: "A severity override only applies to a true positive.",
      });
  });

const DAY = 86_400_000;
/** `YYYY-MM-DD` of today plus `days` in the user's calendar. @param {number} days */
export const dateInDays = (days) => {
  const d = new Date(Date.now() + days * DAY);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};
/** End of the chosen local day as an ISO instant. @param {string} day */
export const expiryInstant = (day) => new Date(`${day}T23:59:59`).toISOString();

export const exceptionFormSchema = z
  .object({
    kind: z.enum(["accept_risk", "suppress"]),
    justification: text(L.justificationMin, L.justificationMax),
    compensatingControls: optionalText(L.compensatingControlsMax),
    expiresAt: z.string(),
    requestedApproverUserId: z.string(),
  })
  .superRefine((v, ctx) => {
    const issue = (message) => ctx.addIssue({ code: "custom", path: ["expiresAt"], message });
    if (!v.expiresAt) {
      if (v.kind === "accept_risk") issue("Choose an expiry date.");
      return;
    }
    const at = new Date(`${v.expiresAt}T23:59:59`).getTime();
    if (Number.isNaN(at)) return issue("Enter the date as YYYY-MM-DD.");
    const days = (at - Date.now()) / DAY;
    const max = v.kind === "accept_risk" ? L.acceptRiskMaxDays : L.suppressMaxDays;
    if (days < 0) issue("Choose a date from tomorrow on.");
    else if (days > max + 1) issue(`Choose a date within ${max} days.`);
  });

export const submitFixSchema = z.object({
  pullRequestUrl: z
    .string()
    .trim()
    .refine(
      (v) => v === "" || pullRequestUrlSchema.safeParse(v).success,
      "Enter an https link without credentials.",
    ),
  ticketKey: z
    .string()
    .trim()
    .refine(
      (v) => v === "" || /^[A-Z][A-Z0-9]{1,9}-[0-9]{1,8}$/.test(v),
      "Use a key like SEC-123.",
    ),
  note: optionalText(L.remediationNoteMax),
});

export const assignFormSchema = z.object({
  assigneeUserId: z.string().min(1, "Choose who will fix this."),
  note: optionalText(L.assignmentNoteMax),
});

export const commentFormSchema = z.object({
  body: text(1, L.commentMax, "Write a comment first."),
});
export const requiredCommentSchema = z.object({
  comment: text(1, L.approvalCommentMax, "A comment is required to reject."),
});
export const optionalCommentSchema = z.object({ comment: optionalText(L.approvalCommentMax) });
export const reasonSchema = z.object({ reason: text(1, 500, "Give a reason.") });

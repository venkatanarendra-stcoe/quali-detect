import { advisoryOutputSchema, cleanAdvisoryReasoning } from "@qmentisai/shared";
import { SUBMIT_ADVICE_TOOL } from "./constants.js";
import { redactExtraShapes } from "./harden.js";

/**
 * Whole-output-or-nothing validation of the model's answer (docs/modules/findings/SPEC.md 9.3.6, FPA-S05). Exactly ONE tool call, named
 * `submit_advice`, whose input passes the strict schema (unknown keys, an out-of-range confidence, an over-long reasoning, a wrong
 * suggestion each make the ENTIRE output invalid). Free text beside the call is ignored and never stored. The reasoning is credential
 * redacted, control and bidirectional characters stripped and whitespace collapsed; an empty result is invalid.
 * @param {{ toolCalls: Array<{ name: string, input: unknown }>, text: string }} collected
 * @returns {{ ok: true, value: { suggestion: string, confidence: number, reasoning: string } } | { ok: false }}
 */
export function validateAdvice({ toolCalls, text }) {
  if (!Array.isArray(toolCalls) || typeof text !== "string") return { ok: false };
  if (toolCalls.length !== 1) return { ok: false };
  const [call] = toolCalls;
  if (!call || call.name !== SUBMIT_ADVICE_TOOL) return { ok: false };
  const parsed = advisoryOutputSchema.safeParse(call.input);
  if (!parsed.success) return { ok: false };
  const reasoning = redactExtraShapes(cleanAdvisoryReasoning(parsed.data.reasoning))
    .replace(/\s+/g, " ")
    .trim();
  if (reasoning === "") return { ok: false };
  return { ok: true, value: { ...parsed.data, reasoning } };
}

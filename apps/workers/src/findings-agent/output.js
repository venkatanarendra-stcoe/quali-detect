import { advisoryOutputSchema, cleanAdvisoryReasoning } from "@qmentisai/shared";
import { SUBMIT_ADVICE_TOOL } from "./constants.js";
import { redactExtraShapes } from "./harden.js";

/**
 * Whole-output-or-nothing validation of the model's answer (docs/modules/findings/SPEC.md 9.3.6, FPA-S05). Every tool call must be the
 * single tool `submit_advice`; the FIRST call must pass the strict schema (unknown keys, an out-of-range confidence, an over-long
 * reasoning, a wrong suggestion each make the ENTIRE output invalid) and is the answer. A later call to the same tool is ignored: real
 * models repeat the call after the tool result, and a repeat must not spoil a good first one (the loop also stops at the first valid
 * call, see `isAdviceComplete`). A call to any OTHER tool, anywhere, invalidates the whole output. Free text beside the call is ignored
 * and never stored. The reasoning is credential redacted, control and bidirectional characters stripped and whitespace collapsed; an
 * empty result is invalid.
 * @param {{ toolCalls: Array<{ name: string, input: unknown }>, text: string }} collected
 * @returns {{ ok: true, value: { suggestion: string, confidence: number, reasoning: string } } | { ok: false }}
 */
export function validateAdvice({ toolCalls, text }) {
  if (!Array.isArray(toolCalls) || typeof text !== "string") return { ok: false };
  if (toolCalls.length < 1) return { ok: false };
  if (toolCalls.some((c) => !c || c.name !== SUBMIT_ADVICE_TOOL)) return { ok: false };
  const [call] = toolCalls;
  const parsed = advisoryOutputSchema.safeParse(call.input);
  if (!parsed.success) return { ok: false };
  const reasoning = redactExtraShapes(cleanAdvisoryReasoning(parsed.data.reasoning))
    .replace(/\s+/g, " ")
    .trim();
  if (reasoning === "") return { ok: false };
  return { ok: true, value: { ...parsed.data, reasoning } };
}

/**
 * The loop's stop test: true once the calls collected so far already hold a VALID first `submit_advice` (the answer is final).
 * @param {{ toolCalls: Array<{ name: string, input: unknown }>, text: string }} collected
 */
export const isAdviceComplete = (collected) => validateAdvice(collected).ok;

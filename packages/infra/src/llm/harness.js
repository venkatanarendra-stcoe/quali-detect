import { LLMError, toolResultMessage } from "./types.js";

/**
 * @typedef {{ inputTokens: number, outputTokens: number, latencyMs: number, turns: number }} HarnessUsage
 * @typedef {{ status: "ok" | "timeout" | "error" | "invalid_output" | "aborted", value?: unknown, text: string,
 *             usage: HarnessUsage, provider: import("./types.js").LLMProviderInfo | null }} HarnessResult
 */

/**
 * The bounded tool-calling loop of ADR-013 section 3, shared by the scan decision agent and (later) the Findings advisory agent.
 *
 * - ONE overall timeout (`timeoutMs`, combined with the caller's `signal`) is shared by every turn.
 * - At most `maxTurns` calls of `provider.complete`, temperature 0, `maxOutputTokens` per call.
 * - Turn 1 is `userData` (serialised as JSON, passed as DATA; the caller's system prompt says so). When the model asks for tools,
 *   ALL calls of ALL turns are collected, nothing is executed (the harness has no file, network or shell capability and offers
 *   only the `tools` the caller passed), and the loop answers with one documented tool-result user message
 *   (`toolResultMessage`) so the conversation can end. The loop ends on a turn without tool calls or at the turn cap.
 * - The collected `{ toolCalls, text }` goes to `validate`, which returns `{ ok: true, value }` or `{ ok: false }`. A validation
 *   failure (or a throw) is `invalid_output` and the WHOLE output is discarded.
 * - It NEVER throws for a model or provider failure. A failure in any turn discards what earlier turns collected.
 * - Logs (injected `logger`) carry the status, counts, durations and token counts only: never a prompt, a response body or a tool
 *   input. Errors are reduced to a code.
 * @param {{
 *   provider: import("./types.js").LLMProvider, system: string, userData: unknown,
 *   tools: import("./types.js").LLMTool[], maxTurns: number, timeoutMs: number, maxOutputTokens: number,
 *   signal?: AbortSignal,
 *   validate: (collected: { toolCalls: import("./types.js").LLMToolCall[], text: string }) => { ok: true, value?: unknown } | { ok: false },
 *   logger?: { info?: Function, warn?: Function },
 * }} options
 * @returns {Promise<HarnessResult>}
 */
export async function runBoundedToolLoop({
  provider,
  system,
  userData,
  tools,
  maxTurns,
  timeoutMs,
  maxOutputTokens,
  signal,
  validate,
  logger,
}) {
  const started = Date.now();
  const usage = { inputTokens: 0, outputTokens: 0, latencyMs: 0, turns: 0 };
  const info = provider?.info ? { id: provider.info.id, model: provider.info.model } : null;
  const finish = (status, extra = {}) => {
    usage.latencyMs = Date.now() - started;
    const result = { status, text: extra.text ?? "", usage: { ...usage }, provider: info };
    if (status === "ok") result.value = extra.value;
    logger?.[status === "ok" ? "info" : "warn"]?.(
      {
        llmStatus: status,
        errorCode: extra.errorCode,
        provider: info?.id,
        model: info?.model,
        turns: usage.turns,
        inputTokens: usage.inputTokens,
        outputTokens: usage.outputTokens,
        latencyMs: usage.latencyMs,
      },
      "LLM tool loop finished",
    );
    return result;
  };

  if (!Number.isInteger(maxTurns) || maxTurns < 1 || !(timeoutMs > 0) || !(maxOutputTokens > 0))
    return finish("error", { errorCode: "bad_bounds" });
  if (signal?.aborted) return finish("aborted");

  const timeout = AbortSignal.timeout(timeoutMs);
  const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
  /** @type {Array<{ role: "user" | "assistant", content: string }>} */
  const messages = [{ role: "user", content: JSON.stringify(userData) }];
  /** @type {import("./types.js").LLMToolCall[]} */
  const collected = [];
  let text = "";

  for (let turn = 0; turn < maxTurns; turn += 1) {
    if (signal?.aborted) return finish("aborted");
    if (timeout.aborted) return finish("timeout");
    let result;
    usage.turns += 1;
    try {
      result = await provider.complete({
        system,
        messages,
        tools,
        maxOutputTokens,
        temperature: 0,
        signal: combined,
      });
    } catch (error) {
      // The adapters see only the combined signal, so classify by which source fired.
      if (signal?.aborted) return finish("aborted");
      if (timeout.aborted || (error instanceof LLMError && error.code === "timeout"))
        return finish("timeout");
      if (error instanceof LLMError && error.code === "aborted") return finish("aborted");
      // An answer the adapter could not parse (for example malformed tool-call JSON) is the model's output, not an outage.
      if (error instanceof LLMError && error.code === "invalid_response")
        return finish("invalid_output", { errorCode: "invalid_response" });
      return finish("error", { errorCode: error instanceof LLMError ? error.code : "unexpected" });
    }
    if (signal?.aborted) return finish("aborted");
    const toolCalls = Array.isArray(result?.toolCalls) ? result.toolCalls : null;
    if (!toolCalls || typeof result?.text !== "string")
      return finish("invalid_output", { errorCode: "invalid_response" });
    usage.inputTokens += Number(result.usage?.inputTokens) || 0;
    usage.outputTokens += Number(result.usage?.outputTokens) || 0;
    if (result.text.trim() !== "") text = result.text;
    collected.push(...toolCalls);
    if (toolCalls.length === 0) break;
    messages.push(
      {
        role: "assistant",
        content: result.text.trim() !== "" ? result.text : "Requesting the tool calls below.",
      },
      toolResultMessage("tool_calls", { recorded: toolCalls.length }),
    );
  }

  let verdict;
  try {
    verdict = validate({ toolCalls: collected, text });
  } catch {
    verdict = { ok: false };
  }
  if (verdict?.ok !== true) return finish("invalid_output", { errorCode: "validation", text });
  return finish("ok", { value: verdict.value, text });
}

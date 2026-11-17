import { count, isPlainObject, postJson } from "./http.js";
import { LLMError } from "./types.js";

/**
 * Anthropic Messages API adapter (non-streaming, tool use). The key goes only in the `x-api-key` header.
 * @param {{ baseUrl: string, model: string, apiKey: string, timeoutMs: number, fetchImpl?: typeof fetch }} options
 * @returns {import("./types.js").LLMProvider}
 */
export function createAnthropicProvider({ baseUrl, model, apiKey, timeoutMs, fetchImpl = fetch }) {
  const url = `${baseUrl.replace(/\/+$/, "")}/v1/messages`;
  return Object.freeze({
    info: Object.freeze({ id: /** @type {const} */ ("anthropic"), model }),
    async complete({ system, messages, tools, maxOutputTokens, temperature, signal }) {
      const body = {
        model,
        max_tokens: maxOutputTokens,
        system,
        messages: messages.map(({ role, content }) => ({ role, content })),
        ...(temperature === undefined ? {} : { temperature }),
        ...(tools?.length
          ? {
              tools: tools.map((t) => ({
                name: t.name,
                description: t.description,
                input_schema: t.inputSchema,
              })),
            }
          : {}),
      };
      const json = /** @type {any} */ (
        await postJson({
          fetchImpl,
          url,
          headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
          body,
          signal,
          timeoutMs,
          provider: "anthropic",
        })
      );
      if (!isPlainObject(json) || !Array.isArray(json.content))
        throw new LLMError("invalid_response", { provider: "anthropic" });
      let text = "";
      const toolCalls = [];
      for (const block of json.content) {
        if (!isPlainObject(block))
          throw new LLMError("invalid_response", { provider: "anthropic" });
        if (block.type === "text" && typeof block.text === "string") text += block.text;
        else if (block.type === "tool_use") {
          if (typeof block.name !== "string" || !isPlainObject(block.input))
            throw new LLMError("invalid_response", { provider: "anthropic" });
          toolCalls.push({ name: block.name, input: block.input });
        }
      }
      return {
        text,
        toolCalls,
        stopReason: typeof json.stop_reason === "string" ? json.stop_reason : "unknown",
        usage: {
          inputTokens: count(json.usage?.input_tokens),
          outputTokens: count(json.usage?.output_tokens),
        },
      };
    },
  });
}

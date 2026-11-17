import { count, isPlainObject, parseToolArguments, postJson } from "./http.js";
import { LLMError } from "./types.js";

/**
 * Ollama `/api/chat` adapter (non-streaming, tools). Local provider: no key. The base URL is deployment configuration.
 * @param {{ baseUrl: string, model: string, timeoutMs: number, fetchImpl?: typeof fetch }} options
 * @returns {import("./types.js").LLMProvider}
 */
export function createOllamaProvider({ baseUrl, model, timeoutMs, fetchImpl = fetch }) {
  const url = `${baseUrl.replace(/\/+$/, "")}/api/chat`;
  return Object.freeze({
    info: Object.freeze({ id: /** @type {const} */ ("ollama"), model }),
    async complete({ system, messages, tools, maxOutputTokens, temperature, signal }) {
      const body = {
        model,
        stream: false,
        messages: [
          { role: "system", content: system },
          ...messages.map(({ role, content }) => ({ role, content })),
        ],
        options: {
          num_predict: maxOutputTokens,
          ...(temperature === undefined ? {} : { temperature }),
        },
        ...(tools?.length
          ? {
              tools: tools.map((t) => ({
                type: "function",
                function: { name: t.name, description: t.description, parameters: t.inputSchema },
              })),
            }
          : {}),
      };
      const json = /** @type {any} */ (
        await postJson({ fetchImpl, url, headers: {}, body, signal, timeoutMs, provider: "ollama" })
      );
      const message = isPlainObject(json) ? json.message : null;
      if (!isPlainObject(message)) throw new LLMError("invalid_response", { provider: "ollama" });
      const rawCalls = message.tool_calls ?? [];
      if (!Array.isArray(rawCalls)) throw new LLMError("invalid_response", { provider: "ollama" });
      const toolCalls = rawCalls.map((call) => {
        if (!isPlainObject(call) || typeof call.function?.name !== "string")
          throw new LLMError("invalid_response", { provider: "ollama" });
        return {
          name: call.function.name,
          input: parseToolArguments(call.function.arguments ?? {}, "ollama"),
        };
      });
      return {
        text: typeof message.content === "string" ? message.content : "",
        toolCalls,
        stopReason: typeof json.done_reason === "string" ? json.done_reason : "unknown",
        usage: { inputTokens: count(json.prompt_eval_count), outputTokens: count(json.eval_count) },
      };
    },
  });
}

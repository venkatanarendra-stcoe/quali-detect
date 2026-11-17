import { count, isPlainObject, parseToolArguments, postJson } from "./http.js";
import { LLMError } from "./types.js";

/**
 * OpenAI chat completions adapter (non-streaming, function tools). Arguments arrive as a JSON string and are parsed and
 * checked to be an object. The key goes only in the `Authorization` header.
 * @param {{ baseUrl: string, model: string, apiKey: string, timeoutMs: number, fetchImpl?: typeof fetch }} options
 * @returns {import("./types.js").LLMProvider}
 */
export function createOpenAIProvider({ baseUrl, model, apiKey, timeoutMs, fetchImpl = fetch }) {
  const url = `${baseUrl.replace(/\/+$/, "")}/v1/chat/completions`;
  return Object.freeze({
    info: Object.freeze({ id: /** @type {const} */ ("openai"), model }),
    async complete({ system, messages, tools, maxOutputTokens, temperature, signal }) {
      const body = {
        model,
        max_completion_tokens: maxOutputTokens,
        messages: [
          { role: "system", content: system },
          ...messages.map(({ role, content }) => ({ role, content })),
        ],
        ...(temperature === undefined ? {} : { temperature }),
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
        await postJson({
          fetchImpl,
          url,
          headers: { authorization: `Bearer ${apiKey}` },
          body,
          signal,
          timeoutMs,
          provider: "openai",
        })
      );
      const choice = isPlainObject(json) && Array.isArray(json.choices) ? json.choices[0] : null;
      const message = choice?.message;
      if (!isPlainObject(message)) throw new LLMError("invalid_response", { provider: "openai" });
      const rawCalls = message.tool_calls ?? [];
      if (!Array.isArray(rawCalls)) throw new LLMError("invalid_response", { provider: "openai" });
      const toolCalls = rawCalls.map((call) => {
        if (!isPlainObject(call) || typeof call.function?.name !== "string")
          throw new LLMError("invalid_response", { provider: "openai" });
        return {
          name: call.function.name,
          input: parseToolArguments(call.function.arguments, "openai"),
        };
      });
      return {
        text: typeof message.content === "string" ? message.content : "",
        toolCalls,
        stopReason: typeof choice.finish_reason === "string" ? choice.finish_reason : "unknown",
        usage: {
          inputTokens: count(json.usage?.prompt_tokens),
          outputTokens: count(json.usage?.completion_tokens),
        },
      };
    },
  });
}

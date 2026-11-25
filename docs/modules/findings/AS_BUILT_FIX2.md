# Findings: fix round 2 (live FP-agent run), 2026-11-25

Found by the first run of the advisory agent against a real Ollama endpoint (gpt-oss:20b, qwen2.5, llama3.2), which no stub had caught.

| # | Defect | Fix |
|---|---|---|
| 1 | `findings-agent/main.js` created a lazily connected Redis client (`enableOfflineQueue: false`) and never connected it; with `REDIS_URL` set the first advisory failed non-retryably ("Stream isn't writeable"). | `runWorker` accepts `beforeStart`; the agent passes a `pingRedis` check, so a Redis that is down fails the START (exit 1, like every other worker) and the client is connected before the first message. Reconnects use the shared client's retry strategy. |
| 2 | Every real model calls `submit_advice` again after the tool result; the validator required exactly one call, so a good first answer was discarded (`invalid_output`). | `runBoundedToolLoop` takes an optional `isComplete`; the agent stops at the first valid call (one provider request, no tool-result turn). `validateAdvice` takes the FIRST call as the answer, ignores later `submit_advice` calls, and still rejects any other tool name anywhere and a bad first call. The scan-decision agent is unchanged (it passes no `isComplete`). |
| 3 | Output cap 400 tokens per call: too small for a reasoning model that thinks before it emits the call. | Default 1,024, `FINDINGS_AGENT_MAX_OUTPUT_TOKENS` (128 to 8,192). |

Tests: `FPA-S05` extended (the repeat on turn 2 with the stub's `allTurns` mode, two calls in one answer, valid then another tool, a bad first call, the validator directly). A real-model-shaped transcript is now in the suite.

## Close-out round (same day)

| # | Change | Where |
|---|---|---|
| 4 | An Ollama is "local, no consent" only on a loopback host (`localhost`, `127.0.0.1`, `::1`); any other host, a LAN address included, is external and needs both consents (`consent_required` with none, metadata only with the first, the excerpt with both). Also applies to the scan decision agent's consent gate (shared `resolveLLMProvider`) and the `providerKind` of `GET /settings/ai`. A non-loopback Ollama needs no vendor key, so the "hosted provider in production" refusal stays for vendors only. | `providerKindFor` in `packages/infra/src/llm/types.js`; `resolve.js`, both runtimes, the AI settings mapper |
| 5 | A manual retry after a row without advice is a new attempt (`retry` joins the input hash, at most 10 per hour); `ok` rows keep the dedup. | `apps/workers/src/findings-agent/advise.js` |

Tests (inside `FPA-S03b` and `FPA-S06`, check count unchanged): the kind of 9 base URLs and the vendors; a LAN Ollama with both consents off (nothing requested), with the first only (no excerpt on the wire), with the second only (nothing), with both (excerpt); manual retry after a 500 and after an invalid answer, the `ok` dedup, the non-manual duplicate.

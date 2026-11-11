# ADR-010: Progressive sign-in and MFA throttling (no hard account lock)

- **Status:** Accepted and implemented (2026-11-11, on the product owner's instruction; `AUTHORIZATION.md` Q24)
- **Supersedes:** the earlier MFA rule (5 wrong codes per user per 15 minutes, after which even the right code was refused until the window ended) and the fixed-window login limit (10 per IP+account, 50 per IP, per 15 minutes).

## Context

A hard per-account lock lets anyone who knows an account's password or e-mail lock the real user out (a denial of service), and fixed windows are easy to wait out. The six-digit second factor is the weakest secret in the system, so its guess rate must be bounded tightly without ever locking the account.

## Decision

1. **Both limits apply, always:** a counter **per account** (the submitted e-mail, or the platform user id for MFA) and a counter **per client IP**. A request is refused if either is waiting.
2. **Progressive, capped delay, no lock.** The first `freeAttempts` failures cost nothing; each further failure arms a wait before the next attempt is evaluated: `baseDelay * 2^(n-1)`, never above `cap`. A refusal is `429 RATE_LIMITED` with `details.retryAfterSeconds`.
3. **Only evaluated failures count.** Attempts refused during a wait do not extend it (otherwise spamming would be a lock). A success clears the account's counter; the IP counter decays by itself (`decay`, default 24 h after the last failure).
4. **No account enumeration.** The account key is derived from the submitted identifier whether or not an account exists, the same Redis operations run in both cases, the 429 body is identical, and the cap notification runs in the background. The mock provider already compares the password for unknown users. `THR-003` and `THR-009` enforce this (status, error body, retry hint, comparable timing).
5. **Cap reached:** when an account's streak first reaches the cap, an audit entry is written for the real account (`auth.throttle_cap_reached` in each active tenant's audit log, `platform.auth.throttle_cap_reached` for platform users) and the event `identity.account.throttle_cap_reached` is emitted. The event is written to the transactional outbox (ADR-011), one per tenant the account belongs to or one tenant-less event for platform accounts, and delivered to the notification worker, which currently only logs it (no e-mail address travels in the message). **Open:** the delivery channel and wording (the notification module).
6. The IP counter tolerates `ipFreeMultiplier` times the free attempts (default 10) for shared offices and NAT. The global per-IP request limit (`RATE_LIMIT_*`) is separate.

## Defaults (all configurable, `AUTH_THROTTLE_*`; values are **Open** until the owner sets them)

| | free failures | base delay | cap |
|---|---|---|---|
| Password sign-in (tenant and platform) | 5 | 10 s | 900 s |
| MFA code | 3 | 30 s | 3600 s |

Decay 86400 s; IP multiplier 10.

## Why the cap keeps 6-digit MFA brute force impractical

MFA defaults: 3 free failures, base 30 s, cap 3600 s. After the 3 free failures the waits are 30, 60, 120, 240, 480, 960, 1920 s, then 3600 s (the cap is reached at the 11th failure). Attempts made by time `t` are 4 immediately, then at 30 s, 90 s, 210 s, 450 s, 930 s, 1890 s, 3810 s, then one every 3600 s.

- **Guesses per account per 24 hours: 11 + floor((86400 - 3810) / 3600) = 33.**
- The streak does not reset while failures keep coming (decay is 24 h from the last failure), and **a different IP does not help**: the account counter is global. The bound is per account, however many addresses the attacker has.
- One six-digit code has 10^6 possibilities. Per day the chance of hitting a single static code is 33 / 10^6 = 3.3 x 10^-5; reaching 50% needs about 10^6 x ln 2 / 33 = 21,000 days (about 57 years). If a time-based code with a +/-1 step tolerance replaces the mock (3 valid values), roughly 19 years. Without throttling, 100 guesses per second would take about 2.8 hours.
- Attacking N accounts costs N times as much per account; the per-account bound does not weaken.
- Sign-in passwords (10 s base, 900 s cap, 5 free): about 106 guesses per account per day, acceptable for passwords with real entropy.

**Residual risk (accepted):** an attacker who keeps failing can hold a victim's account at the cap, so the real user may wait up to the cap (1 hour for MFA) between attempts, but is never locked and the wait never grows past it. There is no administrative reset yet (**Open**).

## Consequences

- New limiter methods (`blockedFor`, `recordFailure`, `clearFailures`) in `@qmentisai/infra` and the in-memory development limiter; `auth/login-throttle.js` rewritten; the two sign-in services record failures and successes; no API contract change besides what `429` already documented.
- Nine security-suite checks (`THR-001..009`) and one control; ADR-008 counts are 77 checks and 17 controls.

## Related

`docs/AUTHORIZATION.md` (Q24, section 16), ADR-008, `docs/decisions/OPEN_DECISIONS.md`.

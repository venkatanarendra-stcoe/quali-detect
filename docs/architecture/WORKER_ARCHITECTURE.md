# QmentisAI Worker Architecture

## Purpose

Workers handle asynchronous and long-running work outside the API request lifecycle.

## Initial worker types

| Worker | Responsibilities |
|---|---|
| Pipeline | Execution orchestration and state transitions |
| Analysis | Repository change and dependency analysis |
| Scan | Scan engine task execution and result ingestion |
| Notification | Email and external notifications |
| Usage | Usage metering and aggregation |
| Scheduler | Scheduled pipeline triggers |

## Job envelope

Every message should include, where applicable:
- message ID
- event type and schema version
- tenant ID
- workspace ID
- repository ID
- pipeline ID
- execution ID
- task ID
- correlation ID
- created timestamp
- actor or system initiator
- payload

## Processing rules

- Validate message schema.
- Validate tenant and resource ownership.
- Check tenant lifecycle and entitlements before protected work.
- Make handlers idempotent.
- Persist state transitions.
- Retry only transient failures.
- Use dead-letter handling and operational visibility.
- Preserve correlation IDs.
- Never trust tenant identifiers solely because they appear in a message.

## Retry classification

Automatically retry transient network, service, rate-limit and infrastructure failures with bounded exponential backoff and jitter.

Do not automatically retry invalid credentials, invalid configuration, unsupported targets or permission-denied failures without remediation.

## Cancellation and recovery

Persist cancellation requests and execution state. Support configured immediate or graceful cancellation where the operation permits it. On worker restart, recover eligible queued or interrupted work without duplicating side effects.

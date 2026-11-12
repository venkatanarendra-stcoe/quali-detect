# QmentisAI Overall System Architecture

## 1. Architecture style

Recommended initial architecture:
- Modular monolith for backend business capabilities.
- Separate API and worker entry points.
- Separate Tenant Application and Root Console frontends.
- Shared PostgreSQL database with strict logical boundaries.
- Redis for cache and coordination.
- RabbitMQ for durable asynchronous jobs.
- Provider adapters for integrations and scan engines.

Do not split every domain into a microservice at the start.

## 2. Logical architecture

```mermaid
flowchart TB
  subgraph Clients
    T[Tenant Application<br/>React + Vite]
    R[Root Console<br/>React + Vite]
  end

  subgraph Backend
    API["API (Express 5 per ADR-007)"]
    ID[Identity and Authorization]
    ORG[Organization and Workspace]
    ENG[Repository and Pipeline]
    INT[Integration Adapters]
    ANA[Repository Analysis]
    SCAN[Scan Orchestration]
    FIND[Finding Intelligence]
    WF[Review and Remediation]
    PLAT[Platform and Entitlements]
  end

  subgraph Async
    MQ[RabbitMQ]
    PW[Pipeline Worker]
    AW[Analysis Worker]
    SW[Scan Worker]
    NW[Notification Worker]
    UW[Usage Worker]
    SCH[Scheduler Worker]
  end

  subgraph Data
    DB[(PostgreSQL)]
    REDIS[(Redis)]
    OBJ[(Object Storage)]
  end

  T --> API
  R --> API
  API --> ID
  API --> ORG
  API --> ENG
  API --> INT
  API --> PLAT
  API --> MQ
  MQ --> PW
  MQ --> AW
  MQ --> SW
  MQ --> NW
  MQ --> UW
  MQ --> SCH
  PW --> SCAN
  AW --> ANA
  SW --> SCAN
  API --> DB
  PW --> DB
  AW --> DB
  SW --> DB
  API --> REDIS
  SCAN --> FIND
  FIND --> WF
  SCAN --> OBJ
```

## 3. Application boundaries

### Root Console
Platform-level administration only. It must not use tenant-facing permissions as a substitute for platform authorization.

### Tenant Application
Tenant users operate within tenant and workspace permissions. Every request must be scoped to the authenticated tenant and authorized resource.

### Backend
One initial application (Express 5 per ADR-007) with domain modules. Platform and tenant modules are logically separated.

### Workers
Independent process entry points consuming durable messages. They reuse domain services and contracts but do not bypass authorization, tenant status or entitlement checks.

## 4. Repository-to-pipeline relationship

One repository may have N pipelines. Each matching event creates a separate execution for each matching pipeline. Immutable repository metadata or diff artifacts may be reused only when repository version and access constraints match. Execution records and finding identities remain pipeline-specific.

## 5. Data ownership

- Platform-owned records: tenant provisioning, plans, subscriptions, platform users and global configuration.
- Tenant-owned records: workspaces, repositories, pipelines, scans, findings, reviews and tenant integrations.
- Shared technical services must preserve ownership context in queries, messages, cache keys, exports and real-time events.

## 6. Architectural constraints

- PostgreSQL is the source of truth for durable business state.
- RabbitMQ is the durable asynchronous transport.
- Redis is not the only store for execution state.
- Socket.IO communicates authorized updates; it is not the source of truth.
- Repository content and external payloads are untrusted input.
- AI analysis must receive bounded context and must not execute repository instructions.

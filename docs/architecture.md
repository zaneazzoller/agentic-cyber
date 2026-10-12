# Architecture and delivery plan

## Runtime flow

1. A connector normalizes a vulnerability or detection into `finding.received` and produces it to Kafka.
2. A Kafka consumer validates the envelope, creates the durable workflow record, and invokes the configured LangGraph.
3. Agent nodes may gather evidence using allowlisted adapters. They send a minimal, classified evidence bundle to vLLM and return JSON-only results.
4. The service stores agent outputs and an outgoing workflow event in one PostgreSQL transaction.
5. An outbox worker publishes that event to Kafka. A Splunk publisher consumes approved events and posts an enrichment through HEC.

## Agent order and dependency rules

The initial graph is intentionally sequential to make each decision auditable:

`NIST -> CISA -> Network Overseer -> Network Expert -> POA&M -> final gate`

The configuration loader defines the graph nodes. The next graph increment should add explicit conditional/parallel branches: CISA and asset lookup can run concurrently after initial evidence collection; urgent KEV/mandate findings should route to an expedited human-review node; insufficient evidence should route to a collection/retry node rather than drafting a POA&M.

## Data boundaries

- Kafka holds versioned, correlation-keyed workflow events. Use Schema Registry with Protobuf or Avro before production.
- PostgreSQL is authoritative for workflow state, evidence pointers, agent outputs, review decisions, and the transactional outbox.
- Splunk remains an evidence source and reporting sink; it must never become the workflow source of truth.
- vLLM receives only the specific, redacted evidence needed by an agent. Prompts, model profile names, and configuration versions must be persisted with agent runs in the production schema.
- All agent profiles use a local vLLM endpoint. The optional vLLM API key is for the local, air-gapped endpoint only; do not put it in YAML, source code, Kafka, PostgreSQL, Splunk, or application logs.

## Agent-owned tool capabilities

Each agent configuration grants its own named tool bindings, including the tool's purpose and required input schema. The common `tools.yaml` registry only defines adapter type, query template, timeout, result limit, and data classification; it never declares which agent receives a tool. Graph construction resolves and validates an agent's declared bindings, then attaches only those capabilities to that agent node.

Until an adapter is implemented, invoking its bound tool returns an explicit `not_configured` result with no evidence. This allows local workflow validation while ensuring a model cannot mistake an unavailable data source for a successful query.

## Imported synthetic sources and passive reachability

The local dataset importer reads only the supplied ZIP's JSON artifacts and stores assets, directed topology edges, vulnerability alerts, manifest content, and mitigation examples in PostgreSQL. It never executes archive content. The source label remains `synthetic`, so it can be distinguished from a future production source throughout the workflow.

`network_reachability_crawl` is granted only to the Network Expert. It starts with the finding's affected asset (or a matched synthetic alert target), performs a bounded four-hop traversal across explicitly imported directed edges, and evaluates each hop against normalized firewall-policy records. An `allow` rule permits traversal; `deny` and `unknown` decisions are captured as evidence but terminate that branch. Results contain the matching firewall device, rule ID, priority, source/destination zone and CIDR, protocol, port, action, and traversal decision. Its result is stored as workflow evidence and is visible from the workflow detail endpoint. It is passive topology-and-policy analysis—not a live network scan, a connectivity test, or proof of isolation—and every result carries that limitation.

## Security controls required before production

- TLS/mTLS and ACLs for Kafka; least-privilege service principals for PostgreSQL and Splunk.
- Secrets loaded from an approved secret manager, not `.env`.
- Fixed saved-search/query templates; never execute raw SPL sourced from a finding or model output.
- Evidence classification, retention limits, secrets/PII redaction, and prompt-injection handling for untrusted logs.
- JSON schema validation and confidence thresholds for all model outputs.
- Human approval before final POA&M publication or any remediation action.
- Tracing with correlation IDs, while excluding raw sensitive prompt bodies from logs.

## Audit logging

The application emits JSON audit events for API requests, workflow transitions, agent lifecycle, bound-tool invocation, database persistence, Kafka/outbox activity, Splunk dispatch/publish activity, and LLM calls. Events use `workflow_id` and `correlation_id` where available. The logger has an explicit field allowlist; raw prompts, model output, evidence bodies, SQL/SPL, URLs, tokens, credentials, and HEC payloads are never recorded.

## Next implementation milestones

1. **Database migrations and retention:** Replace development `create_all` with Alembic revisions, add indexes/retention rules, store prompt and config hashes, and test upgrades/rollbacks.
2. **Kafka hardening:** The runnable intake and transactional outbox workers now provide basic local execution. Add retry schedules, dead-letter handling, idempotency keys at the consumer boundary, Schema Registry, ACLs, and worker health/metrics before production. Keep `finding_id`/`workflow_id` as partition keys.
3. **Evidence/tool registry:** Implement allowlisted CISA KEV, NIST 800-53 catalog, CVE, asset/CMDB, network topology, and Splunk saved-search adapters. Each tool must return normalized evidence references and enforce classification/least privilege.
4. **Agent output contracts:** Add Pydantic schemas per specialist, JSON-schema constrained decoding, validation retries, citations, and explicit low-confidence/insufficient-evidence routes.
5. **Dynamic graph behavior:** Parallelize independent evidence/CISA work, route known-exploited or mandated findings to expedited human review, and checkpoint/resume every graph transition.
6. **Review and publication:** Add reviewer identities/decisions, immutable approval history, POA&M versioning, and a Splunk HEC publisher that only consumes approved output events.
7. **Security controls:** Add secret-manager integration, mTLS/Kafka ACLs, data redaction, prompt-injection defenses, RBAC, evidence retention, and audit dashboards.
8. **Production verification:** Add Testcontainers integration tests for PostgreSQL/Kafka, mocked vLLM/Splunk contract tests, load/failure recovery tests, metrics, alerts, runbooks, and a deployment pipeline.

# Security Agentic Workflow

A configuration-driven cybersecurity workflow that consumes findings from Kafka, coordinates specialist agents with LangGraph, stores durable workflow evidence in PostgreSQL, and enriches Splunk with approved outputs.

## Current foundation

- Versioned Pydantic contracts for Kafka events and agent results.
- Dynamic LangGraph assembly from YAML agent configuration.
- Ordered workflow: NIST control mapping, CISA mandate assessment, network oversight, network expertise, and POA&M drafting.
- PostgreSQL models and an outbox table for reliable Kafka publication.
- Adapter for local vLLM's OpenAI-compatible API and Splunk REST/HEC.
- A deterministic local model mode so the orchestration is testable before infrastructure is connected.
- Audit-safe LLM call logs containing agent/model/timing/status metadata but never prompts, evidence, credentials, or model output.
- Agent-owned tool bindings: each agent YAML declares its own typed capabilities, while the shared registry only resolves adapter metadata and safe execution limits.
- JSON audit events for workflow/API lifecycle, agents, tools, database persistence, Kafka/outbox, and Splunk. Events share workflow and correlation IDs where available and exclude raw source data.

## Air-gapped deployment — quick path

The application does not require internet access while it is running. Build one transfer kit on an
approved connected Linux/WSL preparation host, verify it, then move the code repository and transfer
kit into the disconnected environment. Do not copy a `.venv`; it is operating-system and Python-version
specific.

### 1. Prepare the connected host

Use Linux x86_64 with Python **3.11** and Docker. The target host must use the same CPU architecture.
Install Docker and the NVIDIA Container Toolkit on the target separately; NVIDIA drivers and kernel
components are host-specific and cannot be safely copied in this bundle.

Stage the three model directories below in one `model-store` directory. You must have an authorized
source and license acceptance for Llama; this project does not bypass model-gating or license controls.

```text
model-store/
├── llama-3.2-1b-instruct/          # the local model served by vLLM
└── nist/
    ├── all-mpnet-base-v2/          # optional SentenceTransformer retrieval model
    └── ms-marco-MiniLM-L6-v2/      # optional cross-encoder reranker
```

If the model directories are not already available from your validated local vLLM/cache setup, download
them only on the connected preparation host. Authenticate to the approved model registry first and do
not place registry credentials or tokens in this repository, `.env`, or the transfer kit.

```bash
export MODEL_STORE=/srv/security-workflow-model-store
python3.11 -m pip install --upgrade huggingface_hub
hf download meta-llama/Llama-3.2-1B-Instruct \
  --local-dir "$MODEL_STORE/llama-3.2-1b-instruct"
hf download sentence-transformers/all-mpnet-base-v2 \
  --local-dir "$MODEL_STORE/nist/all-mpnet-base-v2"
hf download cross-encoder/ms-marco-MiniLM-L6-v2 \
  --local-dir "$MODEL_STORE/nist/ms-marco-MiniLM-L6-v2"
```

The Llama command succeeds only after the account has been authorized for its license. If you do not
need semantic NIST retrieval initially, omit the two `nist` model downloads; the lexical/CWE mapper
remains available.

Use the exact vLLM image tag that you already validated locally. On the connected host, create the
bundle; this downloads every Linux wheel (including transitive dependencies), pulls PostgreSQL, Kafka,
and that vLLM image, and exports the images and staged models with SHA-256 checksums.

```bash
cd /path/to/security-agentic-workflow
chmod +x scripts/create_airgap_bundle.sh scripts/install_airgap_bundle.sh
docker image ls --format '{{.Repository}}:{{.Tag}}' | grep vllm
VLLM_IMAGE='your-exact-vllm-image:tag' \
MODEL_STORE='/absolute/path/to/model-store' \
./scripts/create_airgap_bundle.sh /media/transfer/security-workflow-airgap-kit
```

The bundle intentionally fails if `VLLM_IMAGE` is omitted. Pinning the image prevents a later `latest`
tag from silently changing the model server. If the optional NIST models are not available, omit
`MODEL_STORE`; the application remains usable and the mapper transparently uses lexical/CWE retrieval.

### 2. Transfer and install offline

Transfer both the repository and `security-workflow-airgap-kit` through your approved media process.
On the disconnected Linux host, verify checksums, load the images, unpack the models, and create an
offline virtual environment:

```bash
cd /opt/security-workflow
chmod +x scripts/install_airgap_bundle.sh
./scripts/install_airgap_bundle.sh /media/transfer/security-workflow-airgap-kit
cp .env.example .env
chmod 600 .env
```

Edit `.env` before startup. Set a non-default `POSTGRES_PASSWORD` and update the password in
`DATABASE_URL` to exactly the same value. Set `VLLM_IMAGE` to the tag in
`security-workflow-airgap-kit/images/images.txt` and `VLLM_MODEL_DIR` to the absolute path of the
transferred `models/llama-3.2-1b-instruct` directory. Leave `HF_HUB_OFFLINE=1` and
`TRANSFORMERS_OFFLINE=1` enabled.

Start the three local containers and the API:

```bash
docker compose -f docker-compose.airgap.yml --env-file .env up -d
source .venv/bin/activate
uvicorn security_workflow.api:app --app-dir src --host 127.0.0.1 --port 8001
```

In a second terminal, verify the installation and submit a test finding:

```bash
cd /opt/security-workflow
source .venv/bin/activate
pytest -q
curl -sS http://127.0.0.1:8000/v1/models
curl -sS -X POST http://127.0.0.1:8001/validate-workflow \
  -H 'Content-Type: application/json' \
  -d '{
    "finding_id": "airgap-smoke-001",
    "cve_id": "CVE-2022-1388",
    "title": "Air-gap workflow smoke test",
    "severity": "high",
    "affected_assets": ["test-web-01"],
    "source_system": "manual-test"
  }'
```

The first test can run without NVD/NIST/CISA snapshots, but the deterministic NIST and CISA outputs
will correctly report missing source data. Load approved snapshots before operational use, using the
connected-zone import process described below. Never connect the processing runtime to the internet to
refresh them.

### Contents and limits of the transfer kit

- `wheels/` — Linux Python 3.11 wheels for the application, tests, SentenceTransformer, and every
  resolver-selected dependency, including PyTorch.
- `images/runtime-images.tar` — PostgreSQL 16 Alpine, Apache Kafka 3.8.0, and the exact selected vLLM
  image; load it with Docker, never pull it offline.
- `models/models.tar` — present only when `MODEL_STORE` was supplied. It contains the model layout shown
  above. Llama weights must come from an authorized distribution path.
- `SHA256SUMS` — integrity checks performed before installation.

This transfer kit does not include an operating system, Docker Engine, GPU driver, NVIDIA Container
Toolkit, or a PostgreSQL backup. Use your organization’s approved OS and GPU installation media, and
take a PostgreSQL backup separately when migrating real workflow data.

## Connected development quick start

1. Copy `.env.example` to `.env`, set `VLLM_BASE_URL` and `VLLM_MODEL_NAME` for your local vLLM server.
2. Start dependencies: `docker compose up -d`.
3. Create and activate a Python 3.11+ virtual environment.
4. Install: `pip install -e ".[dev]"`.
5. Run tests: `pytest`.

In `development`, the API creates the local PostgreSQL tables when it starts. Production deployments must use reviewed Alembic migrations. The Kafka consumer remains intentionally disabled until the intake worker is implemented and deployed.

## Local model provider

All agents use the local vLLM profiles `security-reasoning` or `security-fast`, both configured for `meta-llama/Llama-3.2-1B-Instruct` by default. There is no OpenAI client, OpenAI endpoint, or OpenAI API-key setting in this codebase.

For a local vLLM model, set `VLLM_BASE_URL` to the OpenAI-compatible API root (normally `http://127.0.0.1:8000/v1`) and set `VLLM_MODEL_NAME` to the exact served model name returned by `GET /v1/models`. The application constructs the final `/chat/completions` URL itself; do not put that final path in `VLLM_BASE_URL`.

The local client intentionally does not use vLLM's JSON-constrained decoding. Some model/backend combinations fail inside the XGrammar engine when `response_format` is requested. The workflow instead instructs the model to return JSON, accepts common fenced JSON variants, and marks a non-JSON response for human review rather than failing the workflow.

## Inspecting persisted runs

`POST /validate-workflow` now writes a `workflows` record, five `agent_runs`, and an outbox event. Its response contains the `workflow_id`; retrieve the durable result with `GET /workflows/{workflow_id}`. For a local database shell, use `docker compose exec postgres psql -U security_workflow -d security_workflow`.

## Synthetic data and passive network reachability

The supplied Cato synthetic dataset can be imported into PostgreSQL without executing anything contained in the ZIP. Only its declared JSON files are read; bundled Python files and README text are ignored.

```bash
python -m security_workflow.datasets.importer \
  --archive /mnt/c/Users/Zane/Downloads/cato_synthetic_datasets_export.zip
```

The imported data is available only through agent-owned tool bindings. The Network Expert receives a passive directed-graph traversal named `network_reachability_crawl`, which defaults to four hops. It evaluates every directed topology hop against an imported synthetic firewall-policy rule and returns shortest allowed paths, allowed blast radius, and the denied/unknown hops with their matching rule IDs. It does not send packets, scan ports, query DNS, or prove live connectivity. The returned evidence and warnings explicitly label it as synthetic topology-and-policy analysis, and a missing graph edge or rule is never treated as proof of isolation or denial.

Other local synthetic tools provide vulnerability alerts, asset inventory, topology, matching manifests, and advisory historical mitigations. Live Splunk, CMDB, CISA, CVE, and NIST adapters remain deliberately unconfigured until their approved integrations are added.

## Official NIST and CISA snapshots

The workflow never reaches the internet while processing a finding. Instead, run the following command
from an approved connected ingestion host to download authoritative records into PostgreSQL; the
air-gapped runtime then reads only those local snapshots:

```bash
python -m security_workflow.datasets.official_sources --cve-id CVE-2022-1388
```

It downloads the official NIST SP 800-53 Rev. 5 OSCAL catalog, CISA's KEV JSON catalog, and the
selected CVE records from the NVD 2.0 API. Each normalized record retains snapshot URL, hash, version,
and retrieval time. `NVD_API_KEY` is optional for small refreshes and can be supplied only to the
connected refresh host for higher API limits.

The deterministic NIST mapper and the CISA agent use these official snapshots. The organization-approved
CVE-to-control mapping repository intentionally remains empty until your governance team supplies
reviewed mappings; the mapper therefore produces candidates rather than asserting a violation. CMDB and
Splunk still use clearly labelled simulation adapters until approved connectors are implemented.

## Deterministic NIST candidate mapping

The first graph node is a deterministic mapper, not an LLM agent. It integrates the supplied
ACAS-to-NIST mapper's conservative CWE candidate expansion with local lexical relevance ranking against
the official NIST OSCAL controls loaded in PostgreSQL. It uses ACAS finding fields and the local NVD
description/CWEs, excludes sensitive plugin output from ranking, and records candidate score/reasons plus
the supporting control text. Each result remains `UNASSESSED`: neither a relevance score nor a CWE rule
is evidence of a control deficiency. The CISA agent receives this durable mapping output as before.

The mapper also supports the archive's optional SentenceTransformer retrieval and cross-encoder reranking.
Install it with `pip install -e ".[dev,nist-mapper]"` on a connected preparation host, then stage the
model cache (or update `config/tools.yaml` with absolute local model directories) before deploying into
the air-gapped environment. The runtime uses `local_files_only=True` and `trust_remote_code=False`: it
never downloads a model while a finding is processed. It caches embeddings only for public NIST catalog
passages under `data/nist_embedding_cache`; finding embeddings are kept in memory and never written to
disk. If either optional package or a staged model is unavailable, the mapper records a runtime warning
and safely uses the lexical/CWE candidate path instead. Cross-encoder values are bounded ranking features,
not confidence or proof of a control violation.

## ACAS/Nessus finding intake

`POST /validate-workflow` and Kafka finding events accept common ACAS/Nessus fields directly: plugin
identity, synopsis, `vulnerability_description` (also accepts `vuln_description` or `description`),
solution, plugin output, risk factor, CVSS score/vector, exploit indicators, STIG severity, host and
service identity, CPE/package/version details, and scan identifiers/timestamps. If `affected_assets`
is omitted, `host_fqdn` and `host_ip` become the asset selectors for CMDB, topology, and reachability
enrichment. Preserve source-specific fields that have no normalized home in the `raw` object.

## Kafka workers

The API is useful for local testing. For Kafka-driven execution, run the intake and outbox workers in separate terminals after PostgreSQL and Kafka are available:

```bash
security-workflow-worker intake
security-workflow-worker outbox
```

The intake worker consumes `security.finding.received.v1`, creates the PostgreSQL workflow record, executes the graph, and commits the Kafka offset only after successful processing. The outbox worker publishes committed `review.required` or `poam.generated` records to Kafka and only marks them published after a broker acknowledgement. Use `--once` with either command for one local polling cycle.

With both workers running, `POST /submit-finding` publishes a validated `finding.received` event to Kafka. `POST /validate-workflow` remains the direct, synchronous development route.
# Agentic_cyber

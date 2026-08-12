# SentinelX

AI-powered, terminal-first **Linux Security Operations Center (SOC)** monitoring
and investigation platform. SentinelX watches a Linux host's security logs,
detects suspicious activity with a hybrid deterministic + LLM detection engine,
investigates findings with a LangGraph multi-agent workflow, enriches them with
threat intelligence and MITRE ATT&CK context, validates evidence before it
reaches a human, and produces a professional investigation report.

> **Build status:** Phase 1 (Project Foundation) complete. See
> [Build Phases](#build-phases) below for what's implemented vs. planned.

## Problem

Small security teams and independent researchers rarely have a full SOC stack.
Existing tools are either raw log viewers (no reasoning) or "AI wrapper"
chatbots (no structure, no evidence trail, prone to hallucination). Neither is
trustworthy enough to act on.

## Solution

SentinelX combines **deterministic security engineering** (log parsing, Sigma
rules, IOC extraction, risk formulas) with **LLM reasoning** (correlation,
MITRE mapping, evidence review) in a structured, auditable pipeline. Every AI
claim must reference supporting evidence; nothing destructive ever executes
without a human approving it first.

## Architecture

```
Linux Host
  -> Log Collection (auth.log / syslog / journalctl / auditd)
  -> Log Normalization (deterministic parsers -> normalized event schema)
  -> Detection (Sigma rules + thresholds + LLM fallback)
  -> Threat Intelligence (VirusTotal / AbuseIPDB / OpenCTI, cached in Redis)
  -> Correlation (attack-chain reasoning)
  -> MITRE ATT&CK Mapping (RAG over Qdrant, not memorized knowledge)
  -> Risk Scoring (deterministic formula + LLM explanation)
  -> Evidence Validation (rejects/flags unsupported claims)
  -> Human Approval (required before any response recommendation is actionable)
  -> Report Generation (PDF, FACT vs. AI INFERENCE vs. RECOMMENDATION)
```

The investigation pipeline is implemented as a **LangGraph** state machine with
conditional routing (e.g. skipping threat-intel lookups when there are no
IOCs), parallel indicator enrichment, retries, checkpointing, and a human
approval interrupt.

### Why a modular monolith, not microservices

One Linux host, one operator, one deployable unit. Microservices would add
operational overhead (service discovery, network calls, distributed tracing)
without a corresponding benefit at this scale. Each concern (collectors,
detection, agents, graph, threat intel, storage) is still a clearly separated
Python package, so it can be extracted into a service later if the project
ever needs multi-host, multi-tenant deployment.

### Why deterministic-first

Log parsing, IOC extraction, and risk scoring have exact right answers.
Asking an LLM to parse a `sshd` log line is slower, more expensive, and less
reliable than a regex the maintainer can read and test. The LLM is reserved
for the parts of the job that actually require judgment: is this sequence of
events an attack chain, does this behavior map to a MITRE technique, is this
conclusion actually supported by evidence.

## Features (target state — see Build Phases for current status)

- Continuous multi-source Linux log monitoring with graceful degradation
- Deterministic IOC/entity extraction (IPs, hashes, users, domains, paths)
- Hybrid detection engine: Sigma/threshold rules + LLM reasoning fallback
- LangGraph multi-agent investigation workflow with conditional routing
- Threat intelligence enrichment with caching and mock/demo fallback
- Attack-chain correlation across separate low-signal events
- MITRE ATT&CK mapping grounded in RAG (Qdrant), not model memory
- Hybrid deterministic + LLM risk scoring with stored reasoning
- Evidence validation layer that can say "insufficient evidence"
- Human-approval-gated incident response recommendations (never auto-executed)
- Professional PDF investigation reports (Fact / Inference / Recommendation)
- Cross-case memory: past investigations inform new ones
- Live terminal SOC dashboard (Textual) and full Typer CLI
- Bundled sample logs so the whole pipeline is demoable without a real attack

## Installation

Requires Python 3.11+.

```bash
git clone <this-repo>
cd sentinelx
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,reports]"
```

The `ai` extra (`pip install -e ".[ai]"`) pulls in LangGraph, LangChain,
LangSmith, Anthropic, and Qdrant — added starting in Phase 4, kept optional so
`doctor`/`config`/CLI scaffolding stay usable without those heavier deps.

## Configuration

```bash
cp .env.example .env
# edit .env — every optional integration can be left blank
```

SentinelX is designed to run in a degraded/demo state when integrations are
missing:

| Missing | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | AI reasoning stages unavailable; deterministic stages still run |
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` | Threat intel agent falls back to a mock provider |
| `OPENCTI_URL` / `OPENCTI_API_KEY` | OpenCTI enrichment skipped |
| `LANGSMITH_API_KEY` | Tracing disabled, everything else unaffected |

Run `sentinelx config validate` to check your configuration, and
`sentinelx config show` to see the effective settings (secrets masked).

## Running SentinelX

```bash
sentinelx --help
sentinelx doctor          # environment + connectivity diagnostics
sentinelx status          # configuration / readiness snapshot
sentinelx monitor         # live dashboard (Phase 2 + 10)
sentinelx investigate     # run the LangGraph workflow (Phase 4-9)
sentinelx alerts          # list findings (Phase 3)
sentinelx report          # generate/view a PDF report (Phase 9)
sentinelx config show
sentinelx config validate
```

Infrastructure (Postgres, Redis, Qdrant) is provisioned via Docker Compose —
see `docker/docker-compose.yml` (added starting Phase 2).

## Sample investigation

Once Phase 10 lands, `sentinelx investigate --sample` (or
`sentinelx monitor --sample`) will replay bundled synthetic logs covering SSH
brute force, successful compromise, privilege escalation, and a suspicious
post-escalation command — enough to exercise the full pipeline without a real
attack.

## CLI commands

| Command | Purpose | Status |
|---|---|---|
| `sentinelx monitor` | Live SOC dashboard / monitoring daemon | Phase 2 + 10 |
| `sentinelx investigate` | Run/resume the LangGraph investigation workflow | Phase 4-9 |
| `sentinelx report` | Generate/view a PDF investigation report | Phase 9 |
| `sentinelx alerts` | List active alerts/findings | Phase 3 |
| `sentinelx status` | Configuration/readiness snapshot | **Done** |
| `sentinelx config show/validate` | View/validate configuration | **Done** |
| `sentinelx doctor` | Environment + connectivity diagnostics | **Done** |

## Agent architecture

Supervisor, Detection, Threat Intelligence, Correlation, MITRE Mapping, Risk
Scoring, Evidence Validation, Incident Response, and Report Generation agents,
each a separate module under `sentinelx/agents/`, orchestrated by a LangGraph
state machine under `sentinelx/graph/`. See the master build prompt in
`docs/` for the full per-agent specification. Implementation begins Phase 4.

## Database architecture

PostgreSQL tables: `users`, `investigations`, `log_sources`,
`agent_findings` (the audit trail of every agent's output), `threat_intel_cache`,
`mitre_mappings`, `reports`, `case_feedback`, `memory_summaries`. Schema and
migrations (Alembic) land starting Phase 2/4 alongside the components that
need them.

## Security considerations

- No secrets in source control; everything is environment-driven (`.env`,
  never committed — see `.gitignore`)
- No AI-generated shell commands are ever executed
- No automated response actions (host isolation, IP blocking, account
  disabling) — recommendations only, gated behind human approval
- All LLM output consumed by downstream agents is structured and validated,
  never passed as uncontrolled free text
- `sentinelx doctor` surfaces misconfiguration before it becomes a runtime
  failure

## Limitations (current, Phase 1)

- Monitoring, detection, the LangGraph workflow, threat intel, correlation,
  MITRE mapping, risk scoring, evidence validation, reporting, and the
  Textual dashboard are **not implemented yet** — their CLI commands exist as
  stubs that explain what's coming and exit cleanly.
- No database schema/migrations yet.
- No Docker Compose file yet (added Phase 2).

## Future improvements

Multi-host monitoring, automated (approved) response execution, a full web
dashboard, additional log sources (cloud provider logs, EDR), and richer
cross-case learning from analyst feedback — all explicitly out of scope for
V1 by design (see the master build prompt).

## Build phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Project foundation: package, config, CLI, logging, tests | **Done** |
| 2 | Linux monitoring: collectors, normalization, event schema | Next |
| 3 | Detection: Sigma, deterministic rules, IOC extraction | Planned |
| 4 | LangGraph: shared state, supervisor, detection agent | Planned |
| 5 | Threat intelligence: VirusTotal, AbuseIPDB, caching | Planned |
| 6 | Correlation: attack-chain reasoning | Planned |
| 7 | MITRE + RAG: Qdrant, knowledge ingestion, mapping | Planned |
| 8 | Risk + validation: scoring, evidence validation | Planned |
| 9 | Human approval + reports: interrupts, PDF generation | Planned |
| 10 | Terminal dashboard + hardening: Textual, sample demo, Docker, docs | Planned |

## Development

```bash
pip install -e ".[dev,reports]"
pytest
ruff check sentinelx tests
black sentinelx tests
mypy sentinelx
```

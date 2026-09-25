# SentinelX Architecture

## Overview
SentinelX is a terminal-first, continuously running Linux security monitoring daemon with AI-powered investigation capabilities.

## Principles
1. Build a real SOC monitoring system first.
2. AI where AI genuinely provides reasoning value (not log parsing).
3. Deterministic first, AI fallback.
4. Human-in-the-loop for all destructive actions.

## Technology Choices
- Language: Python
- CLI: Typer
- TUI: Textual, Rich
- Database: PostgreSQL (structured storage)
- Cache/Queues: Redis
- Vector DB: Qdrant
- Orchestration: LangGraph
- LLM: Anthropic/Claude (Initial)
- Container: Docker

## Architecture
- Log Collection: Deterministic parsers for auth.log, syslog, journalctl, auditd.
- Detection: Hybrid (Sigma + Deterministic patterns first, LLM as fallback).
- Agents (LangGraph): Supervisor -> Threat Intel -> Correlation -> MITRE Mapping -> Validation -> Investigation.
- Output: Terminal dashboard (Textual), structured reports.

## Failure Handling
- Log collector failure does not terminate others.
- Threat Intel uses cache or marks unenriched on failure.
- LLM falls back to deterministic.
- Evidence Validation acts as anti-hallucination guardrail.

## M2: Log Collection Architecture
- **Supported Sources:** `auth.log`, `syslog`, `journalctl`, `auditd`.
- **Collector Architecture:** Handled asynchronously via `CollectionManager`. `FileCollector` uses inode/size tracking for robust log rotation handling. `JournalCollector` streams via JSON output with auto-reconnect.
- **Normalization:** Logs parsed into `NormalizedEvent` schema deterministically. 
- **Persistence:** Events stored in PostgreSQL. Idempotent insertion (`ON CONFLICT DO NOTHING`) with SHA-256 event ID generation prevents duplication during process restart.
- **Unavailable Sources:** Graceful fail-open; missing logs merely pause their specific collector and don't halt the daemon.
- **Permission Requirements:** Collectors read files. Elevated permissions may be needed for `/var/log/audit/audit.log` or others depending on deployment.
- **Testing:** Handled by exhaustive unit testing covering process crashes, log rotation, truncations, and malformed inputs.

## M6: Correlation and MITRE ATT&CK Architecture
- **Pipeline Position:** Downstream asynchronous enrichment following M5 Threat Intelligence.
- **Correlation Agent:** Converts canonical finding context into vector embeddings via OpenAI API, queries Qdrant for semantic similarity, applies temporal window filtering (`CORRELATION_WINDOW_SECONDS`), and clusters related findings.
- **MITRE Mapping Agent:** Performs structured AI-assisted classification via Anthropic Claude.
- **Deterministic Validation:** LLM output is strictly intercepted and validated against a local static MITRE catalog (`mitre_catalog.json`). Unknown or invalid tactic/technique IDs are rejected before persistence.
- **Persistence Boundary:** Scoped `UPDATE` on `Finding.correlations` and `Finding.mitre_tags` only. Deterministic M3 fields (`severity`, `rule_id`, `evidence`, `raw_log`) are immutable.
- **Failure Isolation:** Non-blocking asynchronous queue; Qdrant, OpenAI, or Anthropic failures fail open without impacting M2 collection or M3 detection.

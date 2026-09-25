# SentinelX Roadmap

## Philosophy
- Milestones must be executed sequentially.
- No rushing to AI features until the deterministic monitoring foundation is solid.
- A milestone is only complete when all success criteria are met.

## Milestones

### M1 - Project Skeleton & Connectivity (Completed)
- Setup repository, configuration, CLI stub, Docker Compose (PostgreSQL, Redis, Qdrant).
- Success: `sentinelx doctor` successfully connects to all services.

### M2 - Log Collection & Normalization (Completed)
- Watch auth.log, syslog, journalctl, auditd deterministically.
- Persist to PostgreSQL.

### M3 - Deterministic Detection (Completed)
- Sigma rules, deterministic detection engine. No LLM yet.

### M4 - Terminal Dashboard V1 (Completed)
- Textual UI showing events and detections by polling DB.

### M5 - Agent Layer Part 1 (Completed)
- LangGraph Supervisor, Threat Intelligence Agent (VirusTotal, AbuseIPDB).

### M6 - Correlation + MITRE (Completed)
- Correlation agent, Qdrant RAG, MITRE mapping.

### M7 - Investigation + Reporting + Human Approval
- Investigation agent, evidence validation, LangGraph interrupt for human approval, report generation.

### M8 - Packaging, CLI Polish, CI/CD, Documentation
- uv packaging, MkDocs, GitHub Actions.

### M9 - Hardening & Demo Polish
- Final polish, demo scenario setup.

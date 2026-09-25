# SentinelX

A terminal-first, continuously running Linux security monitoring daemon with AI-powered investigation capabilities.

## Architecture Summary
SentinelX is designed as a local monitoring tool for Linux systems. The fundamental pipeline is:
Continuous Log Monitoring → Deterministic Parsing → Detection → AI Investigation → Human Review → Report

## Current Milestone: M1 - Project Skeleton & Connectivity
This project is currently at the M1 stage. It establishes the base Typer CLI, configuration management, structlog setup with secret redaction, SQLAlchemy 2.x + Alembic foundation, and checks connectivity to required external services (PostgreSQL, Redis, Qdrant) via Docker Compose.

## Prerequisites
- Python 3.10+
- Docker & Docker Compose
- `uv` (recommended for dependency management)

## Setup Instructions

1. **Clone the repository** (or navigate to the checkout).
2. **Set up the environment**:
   ```bash
   cp .env.example .env
   # Modify .env if necessary
   ```
3. **Start the infrastructure**:
   ```bash
   docker compose up -d
   ```
4. **Install dependencies**:
   ```bash
   uv pip install -e .[dev]
   ```
5. **Verify connectivity**:
   ```bash
   sentinelx doctor
   ```

## CLI Commands (M1)
- `sentinelx monitor`: (Stub) Starts the continuous monitoring daemon.
- `sentinelx status`: (Stub) Shows current daemon status.
- `sentinelx doctor`: Checks connectivity to PostgreSQL, Redis, and Qdrant.
- `sentinelx config`: (Stub) Displays current configuration.
- `sentinelx investigate`: (Stub) Triggers investigation for a case.
- `sentinelx report`: (Stub) Generates a report for a case.
- `sentinelx alerts`: (Stub) Lists recent alerts.

## Development Commands
- Tests: `pytest`
- Format: `black .`
- Lint: `ruff check .`
- Types: `mypy src/sentinelx`

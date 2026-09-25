# ADR Index

## ADR-001: Architecture Pattern
Use Modular Monolith.

## ADR-002: Language and Tools
Python 3.11+, Typer for CLI, Textual for TUI.

## ADR-003: LLM Integration
Initial integration targets Anthropic Claude. Use provider abstractions to support Ollama or others later.

## ADR-004: Agent Orchestration
Use LangGraph to handle routing and shared state. Avoid unbounded agent loops.

## ADR-005: Security and Human-in-the-Loop
No automatic execution of destructive actions. AI recommendations must be interrupted for Human Approval.

## ADR-006: UI Model
Terminal-first (Textual). Do not introduce web dashboards or React/FastAPI as primary interfaces in V1.

## ADR-007: Vector Database
Qdrant supersedes Chroma for V1 vector retrieval. Keep retrieval behind an abstraction layer.

## ADR-008: Database ORM and Migrations
SQLAlchemy 2.x is the ORM/model layer. Alembic is the schema migration mechanism.

## ADR-009: Ingestion Strategy
SentinelX V1 uses at-least-once ingestion with deterministic event IDs and idempotent persistence. Do not attempt exactly-once distributed delivery.

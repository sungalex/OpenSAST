# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**OpenSAST** is an open-source SAST (Static Application Security Testing) tool designed to detect the 49 security weaknesses defined in Korea's Ministry of Public Administration and Security (MOIS) guidelines for public sector software development.

### Core Design Principles

- **Multi-engine orchestration**: Combines multiple open-source SAST engines (Opengrep, CodeQL, SpotBugs, Bandit, ESLint, gosec) to maximize detection and minimize false positives.
  **The engine set is scheduled to change**: [ADR-0001](docs/adr/0001-unified-analysis-pipeline.md)
  (Accepted 2026-08-26) drops CodeQL and ESLint for Joern. Not implemented yet —
  do not remove those adapters until ADR-0002 is revised and accepted.
- **CWE-based rule mapping**: Maps all 49 MOIS security weakness items to CWE IDs
- **LLM-based false positive filtering**: Uses AI (Ollama/Gemma locally, Claude API for cloud) to classify results — it **annotates, never removes**, original findings
- **YAML-based custom rules**: Extensible rule system for Opengrep

## Documentation map

Docs are split by *when they are true* — see [ADR-0007](docs/adr/0007-documentation-architecture.md).
Keep this file in sync with `docs/ARCHITECTURE.md`; it is a summary, not a second source of truth.

| Question | Document |
|---|---|
| What exists right now | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (as-built) |
| Why it was built this way | [`docs/adr/`](docs/adr/README.md) |
| What is planned | [`docs/ROADMAP.md`](docs/ROADMAP.md) |
| How to use it | [`docs/guide/`](docs/guide/README.md) |
| What it looked like back then | [`docs/reviews/`](docs/reviews/) (frozen) |
| **Every document, classified** | [`docs/README.md`](docs/README.md) |

**Write an ADR** when a change is hard to reverse, real alternatives existed, or
someone will later ask "why is it like this?"

**Before writing one, read [`docs/adr/README.md`](docs/adr/README.md) and take the
next unused number.** Numbering is by creation order and the directory is not
empty — 0001/0002/0004 date from 2026-04. Do not assume a clean slate; a
collision there once required a one-time renumber, recorded in that README.

## Architecture

### 2-Pass Analysis Model

1. **1st Pass (Fast)**: Opengrep, Bandit, ESLint, gosec — engines within a pass run concurrently
2. **2nd Pass (Deep)**: CodeQL and SpotBugs
3. **3rd Stage**: LLM triage — false positive probability, rationale, remediation

Partial results are never silent: a skipped 2nd pass or a truncated triage is
recorded in `ScanResult.notes`.

### System Layers

- **Frontend**: React + TypeScript + Tailwind CSS
- **API**: FastAPI. Routes are thin adapters whose contract is to inject an
  `ActorContext` into services — see the authorization rule below
- **Orchestrator**: Celery + Redis
- **Data**: PostgreSQL (results), Redis (cache/queue), local filesystem (`.opensast-work/`)
- **LLM**: Ollama + Gemma (offline), Claude API (online)

### Authorization — read this before touching routes

Services **require** an `ActorContext`; passing `None` raises `TypeError`.
`BaseService._org_filter()` defaults to **deny** — it only passes rows matching
the actor's `organization_id`. Full access requires `ActorContext.system()`.

- HTTP routes: `Depends(get_actor)` or `Depends(require_actor(*roles))`
- Unauthenticated paths (login attempts): `ActorContext.anonymous()`
- CLI / Celery / bootstrap: `ActorContext.system(reason=...)`

Never construct a service without an actor to "make it work". See
[ADR-0005](docs/adr/0005-authorization-boundary.md).

### Configuration — single source of truth

`opensast/config.py` is the only source of truth for settings. Never hardcode a
limit, timeout, or path in a service or middleware — read it from `Settings`.
Docs describe that file; if they disagree, the code wins.
See [ADR-0006](docs/adr/0006-configuration-single-source.md).

### Schema changes

`alembic/versions/` is the production path. Revision `0001` is **frozen explicit
DDL** — never reintroduce `Base.metadata.create_all()` there, it breaks the whole
chain. `db/migrate.py::auto_migrate()` is a development-only fallback, disabled
in the cloud profile.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend API | Python 3.12+, FastAPI, Celery, Redis |
| Analysis Engines | Opengrep, CodeQL, SpotBugs, Bandit, ESLint, gosec |
| Frontend | React, TypeScript, Tailwind CSS |
| Database | PostgreSQL, Redis |
| File Storage | Local filesystem (`.opensast-work/`, bind-mounted in Docker) |
| AI/LLM | Ollama + Gemma (local), Claude API (cloud) |
| Containerization | Docker, Docker Compose |
| Reporting | SARIF, WeasyPrint (PDF), openpyxl (Excel) |

## Security Weakness Categories (49 Items)

| Category | Count | Examples |
|----------|-------|----------|
| Input Data Validation | 18 | SQL Injection, XSS, Path Traversal, OS Command Injection, SSRF |
| Security Functions | 12 | Improper Authentication, Weak Cryptography, Hardcoded Credentials |
| Time and State | 2 | TOCTOU, Infinite Loop/Recursion |
| Error Handling | 3 | Information Exposure via Error Messages |
| Code Errors | 7 | Null Pointer Dereference, Improper Resource Release, Deserialization |
| Encapsulation | 5 | Session Data Exposure, Debug Code |
| API Misuse | 2 | DNS Lookup Security Decisions, Vulnerable API Usage |

Coverage is currently 46/49. The three uncovered items (SR1-15, SR5-3, SR5-6)
are C/C++ memory issues, outside the supported language set.

## Custom Rule Development

Opengrep rules use YAML format with MOIS-specific metadata:

```yaml
rules:
  - id: mois-sql-injection-mybatis
    metadata:
      mois_id: "SR1-1"  # MOIS security weakness ID
      cwe: "CWE-89"
      category: "입력데이터 검증 및 표현"
      severity: "HIGH"
```

## Output Formats

- **SARIF**: Standard static analysis format for tool interoperability
- **HTML**: Interactive web-based reports
- **PDF**: Official delivery reports (MOIS format compliant)
- **Excel**: Remediation tracking sheets for auditing

## Working conventions

- Run `pytest` before proposing a change; the suite is fast (~90s) and covers the
  authorization boundary and known regressions.
- Path containment is checked with `Path.is_relative_to()`, never string prefixes.
- Timestamps are timezone-aware UTC everywhere.
- Failures are isolated per unit (per engine, per finding) and **logged** —
  never swallowed with a bare `except: pass`.
- Test credentials are **generated at runtime** (`tests/_credentials.py`), never
  written as literals. Do not put a quoted string on a line that also names a
  `*_PASSWORD`-style identifier — secret scanners match on that shape.
- `tests/test_engine_integration.py` and `tests/vulnerable-samples/` contain
  **deliberately vulnerable** code used to verify the detection rules. Never
  "fix" them. Scanner exceptions for them live in `.gitguardian.yaml`.
- Every route that touches tenant data goes through a service with an
  `ActorContext`. Never `select(models.X)` inside a route — that is how
  `audit.py` and `organizations.py` kept leaking across organizations after
  ADR-0005 landed everywhere else.
- New documents must be registered in [`docs/README.md`](docs/README.md). An
  unregistered document has no owner and silently rots.

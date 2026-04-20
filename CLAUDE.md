# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**OpenSAST** is an open-source SAST (Static Application Security Testing) tool designed to detect the 49 security weaknesses defined in Korea's Ministry of Public Administration and Security (MOIS) guidelines for public sector software development.

### Core Design Principles

- **Multi-engine orchestration**: Combines multiple open-source SAST engines (Opengrep, CodeQL, SpotBugs, Bandit, ESLint, gosec) to maximize detection and minimize false positives
- **CWE-based rule mapping**: Maps all 49 MOIS security weakness items to CWE IDs
- **LLM-based false positive filtering**: Uses AI (Ollama/Gemma locally, Claude API for cloud) to classify detection results and calculate false positive probability
- **YAML-based custom rules**: Extensible rule system for Opengrep

## Architecture

### 2-Pass Analysis Model

1. **1st Pass (Fast)**: Pattern matching via Opengrep, Bandit, ESLint, gosec (~30 seconds per PR)
2. **2nd Pass (Deep)**: Semantic analysis via CodeQL and SpotBugs (scheduled)
3. **3rd Stage**: LLM-based post-processing for false positive filtering and remediation suggestions

### System Layers

- **Frontend**: React + TypeScript + Tailwind CSS (Web UI, VS Code extension, CLI)
- **API Gateway**: FastAPI with RBAC authentication
- **Orchestrator**: Celery + Redis for analysis engine workers
- **Data**: PostgreSQL (results), Redis (cache/queue), local filesystem (`.opensast-work/` source storage)
- **LLM**: Ollama + Gemma (offline), Claude API (online)

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

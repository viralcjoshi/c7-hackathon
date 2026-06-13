# CyberSentinel AI — System Architecture

## Overview

An AI-powered multi-agent cybersecurity system using LangGraph for orchestration, FastAPI for the backend, and a React analytics dashboard for the frontend. Supports log analysis (synthetic, system, upload) and GitHub repository static code scanning.

**Source:** https://github.com/dheerajrvanteru/c7-hackathon

## Architecture Layers

```
┌──────────────────────────────────────────────────────────────┐
│              React Dashboard (Vite + TailwindCSS)             │
│  Metrics · Agent Pipeline · Threats & Remediation · Evals    │
└────────────────────────────┬─────────────────────────────────┘
                             │ HTTP / SSE
┌────────────────────────────▼─────────────────────────────────┐
│                      FastAPI Backend                          │
│  /analyze · /analyze/upload · /analyze/github               │
│  /stream · /report · /evals                                   │
└────────────────────────────┬─────────────────────────────────┘
                             │ background thread
┌────────────────────────────▼─────────────────────────────────┐
│            LangGraph SecurityOrchestrator                     │
│  LogMonitor → ThreatIntel → VulnScanner                       │
│            → IncidentResponse → PolicyChecker                 │
│  Shared SecurityState · SSE via session_events.py             │
└──────┬──────────────────────────────┬────────────────────────┘
       │                              │
┌──────▼──────────┐         ┌─────────▼────────────────────────┐
│  Input Sources   │         │  External Services               │
│ • Synthetic logs │         │ • OpenRouter (gpt-4o) + LLM cache│
│ • System logs    │         │ • GitHub REST API                │
│ • File upload    │         │ • NVD · AbuseIPDB                │
│ • GitHub repos   │         └──────────────────────────────────┘
└─────────────────┘
```

## Agent Flow

Each agent reads from and writes to a shared `SecurityState` TypedDict:

| Agent | Input | Output to State |
|-------|-------|-----------------|
| Log Monitor | Raw logs | `anomalies[]` (with `title`, `recommendation`), `severity_map{}` |
| Threat Intel | Anomalies | `cve_matches[]`, `threat_score` |
| Vuln Scanner | Anomalies + optional GitHub repo | `vulnerabilities[]`, `risk_level`, `code_findings[]`, `files_scanned`, `scan_error` |
| Incident Response | All findings | `action_plan[]`, `runbook_md` (LLM or deterministic fallback) |
| Policy Checker | Anomalies + code findings | `compliance_gaps[]`, `compliance_score` |

## GitHub Repository Scanning

`POST /analyze/github` triggers static analysis via `tools/github_scanner.py`:

1. Fetch repo languages and default branch from GitHub API
2. List up to **60 scannable files** (prioritizes `.tf`/`.hcl` in Terraform repos)
3. Apply pattern rules: general OWASP (`CODE_PATTERNS`) + Terraform/IaC (`TERRAFORM_PATTERNS`)
4. Merge findings into `code_findings[]` and `vulnerabilities[]`

**Scannable extensions:** `.py`, `.js`, `.ts`, `.go`, `.tf`, `.hcl`, `.tfvars`, `.yaml`, `.json`, `.sh`, and others.

**GitHub-only behavior:**
- HTTP header checks are **skipped** (not applicable to IaC)
- Optional `include_logs: true` runs log pipeline in parallel with code scan

Set `GITHUB_TOKEN` in `.env` to avoid API rate limits.

## LLM Caching

Only the **Incident Response** agent calls the LLM. Calls flow through `CachingLLMClient`:

```
CachingLLMClient.chat()
  → LLMCache.get(model, messages)   # SHA-256 key
  → on miss: OpenRouter API call
  → LLMCache.set(...) + record to session_evals
```

| Property | Value |
|----------|-------|
| Cache implementation | In-memory LRU (`llm_cache.py`) |
| Max entries | 256 (configurable) |
| Key | SHA-256(`model` + sorted JSON `messages`) |
| Cache hit cost | $0, ~1 ms latency |
| Observability | `/evals/{session_id}` shows per-call `cache_hit` |

Synthetic demo runs with identical findings produce **100% cache hits** on the second run.

## Streaming (SSE)

`POST /analyze*` returns `{ session_id }` immediately. LangGraph runs in `asyncio.to_thread`. Each agent wrapper emits:

```json
{ "agent": "vuln_scanner", "status": "running" | "done" | "error", "timestamp": "..." }
```

Terminal event: `{ "agent": "pipeline", "status": "done" }`. Dashboard fetches `GET /report/{session_id}` after pipeline completion.

## Frontend Dashboard

### Tabs
- **Dashboard** — Run analysis, view metrics, agents, threats, incident report
- **Evals** — Session-level latency, token, cost, and cache metrics

### Log source selector
Synthetic · System · Upload · **GitHub Repo** (URL input + optional log bundle)

### Metric cards (context-aware)
| Log runs | GitHub runs |
|----------|-------------|
| Critical Threats | Critical Code Issues |
| Warnings | High Severity |
| Agents Active | Files Scanned |
| Compliance Score | Primary Language |
| Risk Level | Risk Level |

### Agent Pipeline (`AgentFeed.tsx`)
Five animated status boxes in pipeline order. Color states:
- **Gray** — Pending
- **Blue** — Running (pulse glow + progress bar)
- **Green** — Complete
- **Red** — Failed

### Detected Threats & Remediation (`ThreatFindingsPanel.tsx`)
Unified panel for log and GitHub runs. Each finding card shows:
- Issue title and severity badge
- Context (source IP, file:line, snippet, CVE links)
- **Fix:** remediation recommendation

For GitHub runs also shows repo link, languages, files scanned, and scan errors.

### Incident Report (`IncidentReport.tsx`)
Action plan (LLM or fallback), compliance gaps, JSON download.

## API Reference

| Endpoint | Method | Body / Params |
|----------|--------|---------------|
| `/analyze` | POST | `{ "source": "synthetic" \| "system" }` |
| `/analyze/upload` | POST | multipart file (`.log`, `.txt`, max 10 MB) |
| `/analyze/github` | POST | `{ "repo_url", "include_logs"?, "log_source"? }` |
| `/stream/{session_id}` | GET | SSE event stream |
| `/report/{session_id}` | GET | Full `SecurityState` + session metadata |
| `/evals` | GET | All session eval summaries |
| `/evals/{session_id}` | GET | Per-agent eval detail |

## Tech Stack

- **Frontend:** React 19, TypeScript, Vite, TailwindCSS v4
- **Backend:** Python 3.11+, FastAPI, sse-starlette
- **Orchestration:** LangGraph state graph
- **AI:** OpenRouter → `openai/gpt-4o` via `openai` Python SDK
- **Cache:** In-memory LRU (`llm_cache.py`)
- **Evals:** `session_evals.py` + `eval_tracker.py`
- **External:** GitHub REST API, NVD, AbuseIPDB
- **Compliance:** NIST CSF 2.0, SOC 2 Type II

## SecurityState (extended fields)

```python
class SecurityState(TypedDict):
    raw_logs: list[str]
    log_source: str          # synthetic | system | upload | github
    session_id: str
    anomalies: list[dict]    # includes title, recommendation
    severity_map: dict
    cve_matches: list[dict]
    threat_score: int
    vulnerabilities: list[dict]
    risk_level: str
    action_plan: list[str]
    runbook_md: str
    compliance_gaps: list[dict]
    compliance_score: int
    github_repo: str
    repo_languages: dict[str, float]
    primary_language: str
    files_scanned: int
    code_findings: list[dict]
    scan_error: str
```

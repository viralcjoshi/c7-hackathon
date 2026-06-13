# CyberSentinel AI — Design Spec
*Date: 2026-06-12*

## Overview

An AI-powered multi-agent cybersecurity system targeting security engineers, DevOps, and IT teams. Five specialized LangGraph agents collaborate in sequence to monitor logs, look up threats, scan for vulnerabilities, generate incident response plans, and check compliance — all surfaced through a real-time analytics dashboard.

Primary goal: hackathon demo that showcases how RAG, multi-agent AI, and real-time streaming work together for automated threat detection and response.

Secondary goal: demonstrate measurable cost and latency savings from LLM response caching, with an eval benchmark comparing cached vs uncached pipeline runs.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React, Vite, TailwindCSS |
| Backend | Python 3.11+, FastAPI |
| Orchestration | LangGraph (state machine) |
| AI / LLM | OpenRouter API (`https://openrouter.ai/api/v1`) → `openai/gpt-4o` via `openai` Python SDK |
| LLM Cache | In-memory LRU cache (`llm_cache.py`) keyed on SHA-256 of model + messages |
| Eval / Metrics | `eval_tracker.py` — per-call token, cost, and latency tracking |
| Streaming | Server-Sent Events (SSE) via `sse-starlette`, fed by per-session event queues |
| External APIs | NVD API, AbuseIPDB |
| Compliance refs | NIST CSF 2.0, SOC 2 Type II *(ISO 27001 mapping: post-MVP)* |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│         React Dashboard (Vite + TailwindCSS)         │
│  Metrics · Agent Pipeline · Threats & Remediation · Evals │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP / SSE
┌──────────────────────▼──────────────────────────────┐
│                   FastAPI Backend                    │
│   /analyze · /analyze/github · /stream · /report · /evals │
└──────────────────────┬──────────────────────────────┘
                       │ triggers
┌──────────────────────▼──────────────────────────────┐
│          LangGraph SecurityOrchestrator              │
│                                                      │
│  LogMonitor → ThreatIntel → VulnScanner              │
│            → IncidentResponse → PolicyChecker        │
│                                                      │
│  All agents share a SecurityState object             │
└──────┬───────────────────────────┬──────────────────┘
       │                           │
┌──────▼──────┐          ┌────────▼────────┐          ┌──────────────────┐
│ Log Sources  │          │  External APIs   │◀────────▶│  LLM Cache Layer │
│ • Synthetic  │          │  • OpenRouter    │          │  (llm_cache.py)  │
│ • System     │          │  • GitHub API    │          │  session_evals   │
│ • Upload     │          │  • NVD · AbuseIPDB          └──────────────────┘
│ • GitHub     │          └─────────────────┘
└─────────────┘
```

---

## Shared State

All agents read from and write to a single `SecurityState` TypedDict passed through the LangGraph graph:

```python
class SecurityState(TypedDict):
    # Input
    raw_logs: list[str]
    log_source: str  # "synthetic" | "system" | "upload" | "github"
    session_id: str

    # Agent outputs (populated in sequence)
    anomalies: list[dict]       # each includes title + recommendation
    severity_map: dict[str, str]
    cve_matches: list[dict]
    threat_score: int  # 0-100
    vulnerabilities: list[dict]
    risk_level: str  # "low" | "medium" | "high" | "critical"
    action_plan: list[str]
    runbook_md: str
    compliance_gaps: list[dict]
    compliance_score: int  # 0-100

    # GitHub scan outputs
    github_repo: str
    repo_languages: dict[str, float]
    primary_language: str
    files_scanned: int
    code_findings: list[dict]
    scan_error: str
```

---

## Agents

### 1. Log Monitor Agent
**Role:** Entry point. Parses raw logs and identifies suspicious activity.

**Tools:**
- `parse_logs(source)` — normalizes log entries into structured events
- `detect_anomalies(entries)` — flags SSH brute force, port scans, auth spikes, unusual traffic
- `classify_severity(event)` — assigns LOW / MEDIUM / HIGH / CRITICAL

**Writes to state:** `anomalies[]` (with human-readable `title` and `recommendation` per type), `severity_map{}`

**Caching note:** This agent does **not** call the LLM directly — it uses deterministic regex tools. No cache needed here.

---

### 2. Threat Intelligence Agent
**Role:** Enriches anomalies with real-world threat data.

**Tools:**
- `query_nvd_cve(keyword)` — searches NVD API for matching CVEs
- `lookup_ip_reputation(ip)` — checks AbuseIPDB for known malicious IPs
- `match_attack_patterns(anomaly)` — *(post-MVP)* maps anomaly types to MITRE ATT&CK technique IDs

**Reads from state:** `anomalies[]`
**Writes to state:** `cve_matches[]`, `threat_score`

**Caching note:** External API calls (NVD, AbuseIPDB) are deterministic for a given IP/keyword. Future enhancement: cache NVD and AbuseIPDB HTTP responses with a TTL.

---

### 3. Vulnerability Scanner Agent
**Role:** Identifies security weaknesses from log anomalies, HTTP headers (log runs), and GitHub repository code.

**Tools:**
- `scan_for_owasp(anomalies)` — maps anomaly types to OWASP categories with recommendations
- `check_api_headers(headers)` — detects missing security headers (skipped for GitHub-only scans)
- `scan_github_repo_safe(repo_url)` — GitHub REST API static scan via `tools/github_scanner.py`
  - Up to 60 files; prioritizes `.tf`/`.hcl` in HCL-heavy repos
  - `CODE_PATTERNS` (secrets, eval, SQLi, XSS, etc.)
  - `TERRAFORM_PATTERNS` (0.0.0.0/0, public S3, wildcard IAM, encryption off, etc.)

**Reads from state:** `anomalies[]`, `github_repo`
**Writes to state:** `vulnerabilities[]`, `risk_level`, `code_findings[]`, `files_scanned`, `repo_languages`, `primary_language`, `scan_error`

---

### 4. Incident Response Agent
**Role:** Synthesizes all findings into an actionable remediation plan.

**Tools:**
- `generate_action_plan(findings)` — OpenRouter `openai/gpt-4o` produces prioritized step-by-step remediation
- `prioritize_threats(list)` — ranks by CVSS score and exploitability
- `draft_runbook(incident)` — generates a markdown runbook for the security team

**Reads from state:** `anomalies[]`, `cve_matches[]`, `vulnerabilities[]`, `threat_score`
**Writes to state:** `action_plan[]`, `runbook_md`

**Caching note:** This agent makes the most expensive LLM call (`openai/gpt-4o` via OpenRouter, ~500–1000 tokens). Identical anomaly/CVE/code-finding sets across repeated demo runs produce 100% cache hits via `CachingLLMClient`. If the LLM is unavailable or returns empty output, `_fallback_action_plan()` builds deterministic steps from anomalies, code findings, vulnerabilities, and CVEs.

---

### 5. Policy Checker Agent
**Role:** Maps all findings to compliance framework gaps.

**Tools:**
- `check_nist_compliance(findings)` — checks against NIST CSF 2.0 controls
- `check_soc2_controls(findings)` — checks against SOC 2 Type II controls
- `generate_compliance_report()` — produces gap list with control IDs and remediation hints

**Reads from state:** all prior fields including `code_findings[]`
**Writes to state:** `compliance_gaps[]`, `compliance_score`

**Note:** `map_code_findings_to_compliance()` maps GitHub code findings to NIST gaps in addition to anomaly-based NIST/SOC2 mapping.

**Caching note:** Policy mapping is deterministic (no LLM call). No cache needed.

---

## LLM Caching Layer

All LLM calls (currently only the Incident Response agent) go through `CachingLLMClient`, which wraps the `openai.OpenAI` client pointed at OpenRouter (`base_url=https://openrouter.ai/api/v1`, `OPENROUTER_API_KEY`). This provides:

- **In-memory LRU cache** (`LLMCache`, max 256 entries, configurable TTL). Cache key: `SHA-256(model + messages JSON)`.
- **Zero-cost cache hits** — cached responses return in ~1 ms with no API charge.
- **Transparent passthrough** — set `cache=None` on `CachingLLMClient` to disable caching for a single run (used by the benchmark's uncached pass).

### Cache invalidation

The cache is keyed on the exact messages array. Any change to the system prompt or user prompt (different anomalies, different CVE list) produces a new key and a cache miss. For the synthetic demo, the same logs always produce the same prompts, giving 100% hit rate on the second run.

### Files

| File | Purpose |
|------|---------|
| `backend/llm_cache.py` | `LLMCache` (LRU dict + TTL), `CacheEntry` dataclass, module-level singleton `get_default_cache()` |
| `backend/llm_client.py` | `CachingLLMClient` — wraps OpenRouter-backed `openai.OpenAI`, tries cache before calling API, records to `EvalTracker` |
| `backend/session_events.py` | Per-session thread-safe event queues; agents emit SSE payloads as they run |
| `backend/session_evals.py` | Per-session eval API (`/evals`); records LLM calls, latency, cache hits per agent |
| `backend/eval_tracker.py` | `EvalTracker` — records per-call tokens/cost/latency/hit; `print_comparison_table()` |
| `backend/benchmark.py` | Standalone benchmark script — runs all 5 agent prompts uncached then cached, prints side-by-side comparison |
| `backend/tools/github_scanner.py` | GitHub REST API repo scanner with Terraform/IaC pattern rules |

---

## Eval Benchmark

`backend/benchmark.py` runs the full agent prompt set twice and prints a structured comparison:

**Pass 1 — uncached:** `cache=None` on the client; all calls hit the real API. Records tokens, cost (USD), and latency per agent call.

**Pass 2 — cached:** shared `LLMCache` is pre-warmed; all calls are cache hits. Records the same fields with `cache_hit=True` and `cost=0`.

**Output includes:**
- Per-call table: agent, run label, input tokens, output tokens, cost, latency ms, hit/miss
- Summary table: totals per run (tokens, cost, latency, hit rate)
- Savings callout: `$X.XXXXX saved (Y% cheaper)`, `Z ms saved (W% faster)`

**Run it:**
```bash
# No API key needed for testing:
cd backend && .venv/bin/python benchmark.py --dry-run

# With a real key:
cd backend && .venv/bin/python benchmark.py --model openai/gpt-4o-mini

# Against OpenRouter:
cd backend && .venv/bin/python benchmark.py --base-url https://openrouter.ai/api/v1 --api-key sk-or-...
```

**Pricing table** (hardcoded in `eval_tracker.py`, update if rates change):

| Model (OpenRouter id) | Input $/1M | Output $/1M |
|-------|-----------|------------|
| `openai/gpt-4o` | $2.50 | $10.00 |
| `openai/gpt-4o-mini` | $0.15 | $0.60 |

---

## SSE Architecture

Analysis runs **asynchronously**. The dashboard receives real agent progress over SSE — not a replay after the pipeline finishes.

```
POST /analyze  ──► create session_id + event queue
                ──► spawn background task (LangGraph in thread pool)
                ──► return { session_id } immediately

GET /stream/{session_id}  ──► read from session queue until sentinel

Each agent wrapper:
  emit(agent, "running")  →  run agent  →  emit(agent, "done" | "error")
  store final SecurityState in _sessions[session_id]
  emit pipeline "done" + queue sentinel
```

**Implementation notes:**
- `session_events.py` holds a `queue.Queue` per `session_id` (thread-safe; LangGraph nodes are sync).
- FastAPI background task runs `asyncio.to_thread(orchestrator.run_analysis, ...)`.
- `/stream/{session_id}` uses `asyncio.to_thread(q.get)` in a loop; `None` sentinel closes the stream.
- Env: `OPENROUTER_API_KEY` only (no direct OpenAI key).

---

## API Design

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | POST | Start analysis asynchronously. Body: `{ "source": "synthetic" \| "system" }`. Returns `{ "session_id" }` immediately. |
| `/analyze/upload` | POST | Start analysis from uploaded `.log`/`.txt` file (multipart). Returns `{ "session_id" }`. |
| `/analyze/github` | POST | Scan a GitHub repo. Body: `{ "repo_url", "include_logs"?: bool, "log_source"?: "synthetic" \| "system" }`. Returns `{ session_id, github_repo, ... }`. |
| `/stream/{session_id}` | GET | SSE stream. Emits `running` / `done` / `error` events **as each agent executes**. |
| `/report/{session_id}` | GET | Full JSON report after analysis completes. Returns `404` while still running. |
| `/agents/status/{session_id}` | GET | Per-agent status derived from latest emitted events (`pending` / `running` / `done` / `error`). |
| `/evals` | GET | List eval summaries for all completed sessions. |
| `/evals/{session_id}` | GET | Detailed per-agent eval metrics (latency, tokens, cost, cache hits). |

**SSE event format:**
```json
{
  "agent": "threat_intel",
  "status": "running" | "done" | "error",
  "findings": [],
  "timestamp": "2026-06-12T10:00:00Z"
}
```

Terminal event when the pipeline finishes:
```json
{ "agent": "pipeline", "status": "done", "findings": [], "timestamp": "..." }
```

---

## Log & Code Sources

Four modes selectable from the dashboard:

1. **Synthetic** — pre-generated sample logs bundled with the app (SSH brute force, port scan, path traversal, sudo failure). Always available, ideal for demos.
2. **System** — reads from `/var/log/auth.log`, `/var/log/syslog`, `/var/log/system.log`, `/var/log/secure.log`. Falls back to synthetic logs if none are readable (common on macOS).
3. **Upload** — user uploads a `.log` or `.txt` file via the dashboard. Accepted as multipart form data at `POST /analyze/upload`.
4. **GitHub Repo** — static code scan via `POST /analyze/github`. Accepts full URL or `owner/repo`. Optional checkbox to combine with synthetic/system log analysis. Requires `GITHUB_TOKEN` for reliable API rate limits.

---

## Frontend Design

**Stack:** React + Vite + TailwindCSS, dark theme.

**Tabs:** Dashboard · Evals

**Dashboard sections:**
1. **Nav bar** — app name, Dashboard / Evals tabs
2. **Log source selector** — Synthetic / System / Upload / **GitHub Repo** + Run Analysis
3. **Metric cards (5)** — context-aware: log runs show Critical Threats / Compliance Score; GitHub runs show Critical Code Issues / Files Scanned / Primary Language
4. **Agent Pipeline** — five animated status boxes (gray pending → blue running → green complete → red failed)
5. **Incident report panel** — action plan + compliance gaps + JSON download
6. **Detected Threats & Remediation** — unified findings panel with severity-colored cards and **Fix:** recommendations for log anomalies and GitHub code findings

**Evals tab:** Session list with expandable per-agent latency, token usage, cost, and cache hit metrics from `session_evals.py`.

**Real-time updates:** After `POST /analyze*` returns, the dashboard opens `GET /stream/{session_id}`. Agent boxes update on SSE events; full report loads after `pipeline` `done`.

---

## Data Flow

1. User selects log source and clicks **Run Analysis**
2. `POST /analyze` (or `/analyze/upload`) → FastAPI creates `session_id` + event queue, starts background LangGraph run, returns `{ session_id }` **immediately**
3. Dashboard opens `GET /stream/{session_id}` (SSE) **in parallel** with the running pipeline
4. LangGraph agents run in sequence; each wrapper emits SSE events to the session queue as it starts and finishes
5. Dashboard updates live: agent feed on SSE events; metric cards after fetching report
6. On `pipeline` `done` SSE event, dashboard calls `GET /report/{session_id}` for the full `SecurityState` JSON

---

## Project Structure

```
c7-hackathon/
├── backend/
│   ├── main.py                  # FastAPI app, SSE streaming
│   ├── orchestrator.py          # LangGraph graph definition
│   ├── state.py                 # SecurityState TypedDict
│   ├── llm_cache.py             # LRU cache for LLM responses
│   ├── llm_client.py            # CachingLLMClient wrapper
│   ├── eval_tracker.py          # Per-call token/cost/latency tracking
│   ├── benchmark.py             # Cached vs uncached eval benchmark
│   ├── session_events.py        # Per-session queues for live SSE
│   ├── session_evals.py         # Per-session eval metrics + /evals API
│   ├── agents/
│   │   ├── log_monitor.py
│   │   ├── threat_intel.py
│   │   ├── vuln_scanner.py
│   │   ├── incident_response.py  # Uses CachingLLMClient + fallback action plan
│   │   └── policy_checker.py
│   ├── tools/
│   │   ├── log_parser.py        # Anomaly detection + title/recommendation enrichment
│   │   ├── github_scanner.py    # GitHub API + Terraform/IaC patterns
│   │   ├── nvd_api.py
│   │   └── abuseipdb.py
│   ├── data/
│   │   └── synthetic_logs.json  # Sample logs for demo mode
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── MetricCard.tsx
│   │   │   ├── AgentFeed.tsx           # Animated agent pipeline boxes
│   │   │   ├── ThreatFindingsPanel.tsx # Issues + Fix recommendations
│   │   │   ├── IncidentReport.tsx
│   │   │   ├── LogSourceSelector.tsx   # Includes GitHub repo mode
│   │   │   └── EvalsTab.tsx
│   │   └── hooks/
│   │       └── useSSE.ts        # SSE subscription hook
│   └── package.json
├── README.md
└── docs/
    ├── architecture.md
    ├── architecture.html
    ├── agents-design.html
    ├── data-flow.html
    └── frontend-design.html
```

---

## Error Handling

- If an external API (NVD, AbuseIPDB) fails, the agent logs a warning and continues with partial results — it does not block the pipeline.
- If OpenRouter returns an error, the Incident Response agent falls back to `_fallback_action_plan()` (deterministic steps from anomalies, code findings, and vulnerabilities) and still completes the pipeline.
- GitHub scan failures (404, rate limit) set `scan_error` in state; the dashboard displays the error in the Threats panel.
- Uploaded files are validated for size (max 10MB) and extension (`.log`, `.txt`) before analysis starts.

---

## Testing Strategy

- **Unit tests** — each agent function tested with fixture log data; Terraform pattern tests in `test_github_scanner.py`
- **Integration test** — full LangGraph graph run with synthetic logs, assert all state fields populated
- **API tests** — FastAPI TestClient for `/analyze`, `/report`, `/analyze/github` endpoints
- **Demo smoke test** — run synthetic mode end-to-end, verify SSE stream emits 5 agent events and dashboard metrics update
- **Cache unit tests** — `test_llm_cache.py`: verify LRU eviction, TTL expiry, key collision, hit/miss counting
- **Eval benchmark** — `benchmark.py --dry-run`: assert cached run has 100% hit rate, zero cost, and latency < 10 ms/call
- **Session evals** — `test_evals.py`: verify `/evals` API records per-agent metrics

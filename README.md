# CyberSentinel AI

Multi-agent cybersecurity analysis platform built for the C7 hackathon. Five LangGraph agents analyze logs and GitHub repositories, stream live progress over SSE, and surface threats with actionable remediation in a React dashboard.

**Repository:** https://github.com/dheerajrvanteru/c7-hackathon

## Features

| Capability | Description |
|------------|-------------|
| **Log analysis** | Synthetic demo logs, host system logs, or uploaded `.log`/`.txt` files |
| **GitHub repo scanning** | Static analysis of up to 60 files (`.py`, `.tf`, `.hcl`, `.js`, etc.) via GitHub REST API |
| **Terraform / IaC patterns** | Detects open CIDRs, public S3 ACLs, wildcard IAM, disabled encryption, and more |
| **Live agent pipeline** | SSE stream shows each agent as animated status boxes (pending → running → complete) |
| **Threats & remediation UI** | Severity-colored cards with issue details and **Fix:** recommendations for logs and code |
| **LLM caching** | In-memory LRU cache for Incident Response calls — zero cost on cache hits |
| **Session evals** | Per-run metrics tab: latency, tokens, cost, cache hit rate per agent |
| **Compliance mapping** | NIST CSF 2.0 and SOC 2 Type II gaps from log anomalies and code findings |

## Quick start

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add OPENROUTER_API_KEY, optional GITHUB_TOKEN
.venv/bin/python -m uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev    # http://localhost:5173
```

### Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `OPENROUTER_API_KEY` | Recommended | LLM action plans via OpenRouter (`openai/gpt-4o`) |
| `GITHUB_TOKEN` | Recommended | Higher GitHub API rate limits for repo scans |
| `NVD_API_KEY` | Optional | NVD CVE lookups |
| `ABUSEIPDB_API_KEY` | Optional | IP reputation checks |

Without `OPENROUTER_API_KEY`, the Incident Response agent uses a **deterministic fallback action plan** built from anomalies, code findings, and vulnerabilities.

## Analysis modes

1. **Synthetic logs** — Bundled demo data (SSH brute force, port scan, path traversal, sudo failure)
2. **System logs** — Reads `/var/log/auth.log`, `syslog`, `system.log`, `secure.log` (falls back to synthetic on macOS if unreadable)
3. **Upload** — User-provided log file
4. **GitHub repo** — Code scan only, or code + optional bundled/synthetic logs

## API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | POST | Start log analysis (`source`: `synthetic` \| `system`) |
| `/analyze/upload` | POST | Upload log file (multipart) |
| `/analyze/github` | POST | Scan GitHub repo (`repo_url`, optional `include_logs`) |
| `/stream/{session_id}` | GET | SSE agent progress events |
| `/report/{session_id}` | GET | Full analysis report JSON |
| `/agents/status/{session_id}` | GET | Per-agent status snapshot |
| `/evals` | GET | List all session eval summaries |
| `/evals/{session_id}` | GET | Detailed eval metrics for one run |

## Agent pipeline

```
LogMonitor → ThreatIntel → VulnScanner → IncidentResponse → PolicyChecker
```

- **LogMonitor** — Regex parsing; enriches anomalies with title + recommendation
- **ThreatIntel** — NVD CVE search + AbuseIPDB IP reputation → `threat_score`
- **VulnScanner** — OWASP mapping, optional HTTP header checks (log runs only), GitHub static scan
- **IncidentResponse** — OpenRouter LLM action plan (cached) or deterministic fallback
- **PolicyChecker** — NIST/SOC2 gaps from anomalies and code findings

## LLM caching

All Incident Response calls go through `CachingLLMClient` (`llm_client.py`):

- **Key:** SHA-256 of `(model + messages JSON)`
- **Store:** In-memory LRU, max 256 entries, optional TTL
- **Hits:** ~1 ms, $0 API cost; recorded in session evals with `cache_hit: true`

Run the standalone benchmark:

```bash
cd backend && .venv/bin/python benchmark.py --dry-run
```

## Tests

```bash
cd backend && .venv/bin/python -m pytest tests/ -q
```

39 tests covering agents, GitHub scanner, Terraform patterns, cache, API, and orchestrator.

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/architecture.md](docs/architecture.md) | System architecture reference |
| [docs/superpowers/specs/2026-06-12-cybersentinel-ai-design.md](docs/superpowers/specs/2026-06-12-cybersentinel-ai-design.md) | Full design spec |
| [frontend/README.md](frontend/README.md) | Dashboard UI components |

## Project structure

```
c7-hackathon/
├── backend/
│   ├── agents/           # LangGraph agent nodes
│   ├── tools/            # log_parser, github_scanner, nvd_api, abuseipdb
│   ├── session_events.py # SSE per-session queues
│   ├── session_evals.py  # Per-run eval metrics API
│   ├── llm_cache.py      # LRU LLM response cache
│   └── main.py           # FastAPI app
├── frontend/src/
│   ├── components/       # AgentFeed, ThreatFindingsPanel, EvalsTab, …
│   └── hooks/useSSE.ts
└── docs/
```

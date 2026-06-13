# CyberSentinel AI — Frontend

React + Vite + TailwindCSS dashboard for the CyberSentinel multi-agent security pipeline.

## Development

```bash
npm install
npm run dev     # http://localhost:5173
npm run build
```

Backend must be running at `http://localhost:8000` (configured in `src/App.tsx`).

## Dashboard layout

### Navigation
- **Dashboard** — Analysis runs and live results
- **Evals** — Per-session agent latency, tokens, cost, cache metrics

### Log source selector (`LogSourceSelector.tsx`)
| Mode | Behavior |
|------|----------|
| Synthetic | `POST /analyze` with `source: "synthetic"` |
| System | `POST /analyze` with `source: "system"` |
| Upload | `POST /analyze/upload` (multipart) |
| GitHub Repo | `POST /analyze/github` with repo URL; optional checkbox to include synthetic/system logs |

### Metric cards (`MetricCard.tsx`)
Switches between **log-run** and **GitHub-run** metric sets based on `log_source`.

### Agent Pipeline (`AgentFeed.tsx`)
Always shows all five agents in order. Status derived from SSE events:

| Status | Color | Animation |
|--------|-------|-----------|
| Pending | Gray | Static |
| Running | Blue | Glow pulse + sliding progress bar |
| Complete | Green | Success flash |
| Failed | Red | Error glow |

### Detected Threats & Remediation (`ThreatFindingsPanel.tsx`)
Primary findings panel for both log and GitHub analysis:

**Log runs:** Anomaly cards (SSH brute force, port scan, etc.) with source IP, CVE links, and **Fix:** text. Missing HTTP security headers listed separately when applicable.

**GitHub runs:** Repo link, language badges, code finding cards (`file:line`, snippet, OWASP category, **Fix:** recommendation). Shows scan errors (e.g. rate limit) and a clean-scan message when no patterns match.

### Incident Report (`IncidentReport.tsx`)
- Numbered action plan from LLM or backend fallback
- Compliance gaps (NIST / SOC2)
- Download full report as JSON

### Evals tab (`EvalsTab.tsx`)
Fetches `GET /evals` and `GET /evals/{session_id}`. Shows per-agent latency, LLM token/cost breakdown, and cache strategy info.

## Real-time flow

1. User clicks **Run Analysis** → receives `session_id`
2. `useSSE` hook opens `GET /stream/{session_id}`
3. `AgentFeed` updates box statuses on each SSE event
4. On `pipeline` `done`, `App.tsx` fetches `GET /report/{session_id}`
5. Metrics, `ThreatFindingsPanel`, and `IncidentReport` populate from report JSON

## Key files

```
src/
├── App.tsx                      # Main layout, analysis orchestration
├── hooks/useSSE.ts              # SSE subscription
├── types.ts                     # SecurityReport, Anomaly, CodeFinding, …
├── components/
│   ├── AgentFeed.tsx            # Animated agent pipeline
│   ├── ThreatFindingsPanel.tsx  # Issues + Fix recommendations
│   ├── IncidentReport.tsx       # Action plan + compliance
│   ├── LogSourceSelector.tsx    # Source picker + GitHub URL
│   ├── MetricCard.tsx
│   └── EvalsTab.tsx
└── index.css                    # Agent animation keyframes
```

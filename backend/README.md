# ThreatVision AI — Backend

Enterprise DFIR investigation platform. Upload evidence, extract IOCs, map MITRE ATT\&CK techniques, generate AI-powered Root Cause Analysis.

---

## Architecture

```
main.py                         ← FastAPI entry point, lifespan, WebSocket endpoint
backend/app/
├── api/
│   ├── routes/
│   │   ├── health.py           ← GET /api/health
│   │   └── investigations.py   ← All investigation REST endpoints
│   └── websocket.py            ← WebSocket connection manager
├── config/
│   └── settings.py             ← Pydantic Settings (env-driven)
├── database/
│   └── session.py              ← Async SQLAlchemy engine + session
├── models/
│   └── investigation.py        ← ORM models (Investigation, EvidenceFile, IOC, ...)
├── schemas/
│   └── investigation.py        ← Pydantic request/response schemas
├── services/
│   └── investigation_service.py ← Business logic, DB writes
├── parsers/                    ← Phase 3: one parser per evidence type
├── mitre/                      ← Phase 6: ATT&CK rules engine
├── ai/                         ← Phase 7: AI provider interface + mock
├── threatintel/                ← Phase 8+: TI provider interface + mock
├── timeline/                   ← Phase 5: timeline merge engine
├── reports/                    ← Phase 8: report generators
└── utils/
    ├── file_utils.py           ← SHA256, MIME detection, path helpers
    └── logging.py              ← structlog configuration
```

---

## Quick Start

```bash
# 1. Clone and enter the project
cd threatvision-backend

# 2. Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — at minimum set SECRET_KEY

# 5. Run
uvicorn main:app --reload
```

Server starts at `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/health`

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/investigation/upload` | Upload evidence files |
| POST | `/api/investigation/start` | Start investigation pipeline |
| GET | `/api/investigation/{id}` | Get status + full detail |
| GET | `/api/investigation/{id}/timeline` | Attack timeline |
| GET | `/api/investigation/{id}/iocs` | Extracted IOCs |
| GET | `/api/investigation/{id}/mitre` | MITRE ATT\&CK mappings |
| GET | `/api/investigation/{id}/rca` | Root Cause Analysis |
| POST | `/api/investigation/{id}/report` | Generate report |
| GET | `/api/investigations` | List all investigations |

### WebSocket

```
ws://localhost:8000/ws/{investigation_id}
```

Receives live `PipelineUpdate` JSON events during investigation processing.
Send `"ping"` to receive `{"event":"pong"}` keepalive.

---

## Environment Variables

See `.env.example` for the full reference. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./threatvision.db` | DB connection string |
| `UPLOAD_DIR` | `./backend/app/uploads` | Evidence file storage |
| `MAX_UPLOAD_SIZE_MB` | `100` | Per-file size limit |
| `AI_PROVIDER` | `mock` | `mock` \| `anthropic` \| `openai` |
| `TI_PROVIDER` | `mock` | `mock` \| `virustotal` \| `misp` |
| `LOG_FORMAT` | `console` | `console` \| `json` |

---

## Implementation Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | ✅ Done | Project structure, models, schemas, config |
| 2 | ✅ Done | Upload API, DB session, health check, main.py |
| 3 | ⏳ Pending | Evidence parsers (email, EVTX, JSON, PDF, PCAP, DOCX/XLSX) |
| 4 | ⏳ Pending | IOC extraction engine |
| 5 | ⏳ Pending | Timeline merge and sort engine |
| 6 | ⏳ Pending | MITRE ATT\&CK rules engine |
| 7 | ⏳ Pending | AI engine (mock + Anthropic/OpenAI providers) |
| 8 | ⏳ Pending | Report generation (Markdown, HTML, PDF, DOCX, ServiceNow) |

---

## Supported Evidence Types

| Extension | Parser | Evidence Type |
|-----------|--------|---------------|
| `.eml` `.msg` | Email parser | Phishing emails, headers, attachments |
| `.evtx` | EVTX parser | Windows Event Logs (Security, System, Sysmon) |
| `.json` | JSON parser | CrowdStrike detections, EDR exports |
| `.csv` | CSV parser | SIEM exports, alert tables |
| `.pdf` | PDF parser | Reports, malware writeups |
| `.log` `.txt` | Log parser | Generic log files |
| `.pcap` | PCAP parser | Network captures |
| `.docx` `.xlsx` | Office parser | Documents, spreadsheets |
| `.png` `.jpg` | Image parser | Screenshots (OCR in Phase 3) |
| `.zip` | Archive | Extracts and processes contained files |

---

## Testing

```bash
# Run all tests
pytest backend/app/tests/ -v

# With coverage
pytest backend/app/tests/ --cov=backend --cov-report=html
```

---

## Production Deployment

```bash
# PostgreSQL
export DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/threatvision

# Run migrations
alembic upgrade head

# Start with multiple workers
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

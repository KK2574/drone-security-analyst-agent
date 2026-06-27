# 🚁 Drone Security Analyst Agent
> AI-powered aerial surveillance using **Gemini Vision + LangGraph + ChromaDB**

## Overview

The Drone Security Analyst Agent processes real drone surveillance footage to detect and analyse security events. It extracts frames using OpenCV, sends each frame to **Gemini 2.5 Flash Vision** for structured JSON analysis, indexes results into **ChromaDB** for semantic search, and runs an 8-rule alert engine. A **LangGraph ReAct agent** with 6 tools enables natural-language follow-up queries over the processed footage.

Accessible via:
- **CLI** (`main.py`) — full pipeline + interactive agent REPL
- **Browser Dashboard** (`drone-security-dashboard.html`) — upload, configure, and run in-browser
- **Test Suite** (`tests/test_agent.py`) — validates all components without a video file

---

## Feature Specification

**Value:** Enhances property security through automated 24/7 aerial monitoring with intelligent, context-aware alerts and a searchable event history — no manual footage review required.

| Requirement | Description |
|-------------|-------------|
| KR-1: Real-time Video Intelligence | Gemini Vision identifies objects, people, vehicles per frame with structured JSON output |
| KR-2: Automated Alert Generation | 8 rule-based alerts with CRITICAL / HIGH / MEDIUM / LOW severity, context-aware (day vs night) |
| KR-3: Queryable Event History | ChromaDB semantic search + LangGraph agent for natural-language retrospective queries |

---

## Architecture

```
Video File (MP4/MOV/AVI)
    │
    ▼
OpenCV Frame Extraction  (video_processor.py)
    │  1 frame every N seconds → base64 JPEG
    ▼
Gemini 2.5 Flash Vision  (video_processor.py)
    │  Structured JSON per frame:
    │  objects, people_count, vehicles, activity,
    │  security_level, requires_alert, alert_reason
    ▼
ChromaDB Indexing  (indexer.py)
    │  cosine similarity embeddings
    │  metadata filters: location, security_level, requires_alert
    ▼
Alert Engine  (alert_engine.py)
    │  8 rules × (frame + telemetry) → severity-tagged Alert objects
    ▼
Gemini Summary  (video_processor.py)          ← BONUS
    │  3–4 sentence daily patrol summary
    ▼
LangGraph ReAct Agent  (tools.py + main.py)   ← BONUS
    │  6 tools: search / alerts / vehicles / location / summary / Q&A
    ▼
Interactive REPL  /  Browser Dashboard
```

### Alert Engine — 8 Rules

| Rule | Severity | Trigger |
|------|----------|---------|
| `NIGHT_PERSON_DETECTED` | 🚨 CRITICAL | Person detected during night patrol (`is_night=True`) |
| `LOITERING_DETECTED` | ⚠️ HIGH (CRITICAL at night) | "loitering / stationary / lingering" in activity |
| `PERIMETER_BREACH` | 🚨 CRITICAL | "breach / trespassing / climbing / fence" in activity |
| `GATE_BREACH_ATTEMPT` | 🚨 CRITICAL | "forcing / gate breach / attempting to open gate" |
| `REPEAT_VEHICLE` | 🔔 MEDIUM | Same vehicle string seen 2+ times across frames |
| `HIGH_SECURITY_EVENT` | ⚠️ HIGH | `security_level == "critical"` returned by Gemini |
| `UNMARKED_VEHICLE` | 🔔 MEDIUM | "unmarked / unknown vehicle / suspicious van" |
| `LOW_BATTERY` | ℹ️ LOW | `telemetry.battery < 15%` |

> **Note:** Loitering escalates from HIGH → CRITICAL when `telemetry.is_night` is True.

---

## Project Structure

```
drone-security-agent/
├── main.py                      # Pipeline orchestrator + LangGraph agent REPL
├── video_processor.py           # OpenCV frame extraction + Gemini Vision analysis
├── telemetry.py                 # Drone telemetry generation (dynamic + static fallback)
├── alert_engine.py              # 8-rule alert engine with vehicle/person tracking
├── indexer.py                   # ChromaDB frame indexing + semantic search
├── tools.py                     # 6 LangGraph @tool functions for agent
├── drone-security-dashboard.html # Self-contained browser dashboard
├── tests/
│   └── test_agent.py            # Dynamic, video-agnostic test suite
├── requirements.txt
├── .env                         # API keys (not committed)
└── .gitignore
```

---

## Setup & Installation

### Prerequisites
- Python 3.11+
- Google Gemini API key ([get one here](https://aistudio.google.com/app/apikey)) — Tier 1 paid recommended to avoid 503 rate limits
- A video file (MP4 / MOV / AVI)

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/drone-security-agent.git
cd drone-security-agent
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
langchain
langchain-core
langchain-community
langgraph
langgraph-prebuilt
google-genai
langchain-google-genai
chromadb
python-dotenv
opencv-python
```

### 3. Configure Environment
Create a `.env` file in the project root:
```
GEMINI_API_KEY=AIzaSy...
```

### 4. Add Your Video
Place your video file in the project root:
```
drone-security-agent/
└── security_footage.mp4   ← default filename (or pass any path as argument)
```

### 5. Run — CLI
```bash
# Uses security_footage.mp4 by default
python main.py

# Or specify a custom path
python main.py "path/to/your/video.mp4"
```

### 6. Run — Browser Dashboard
```bash
# Serve locally (required for file upload to work)
python -m http.server 5500

# Then open in Chrome:
# http://127.0.0.1:5500/drone-security-dashboard.html
```
Upload your video, paste your Gemini API key, configure frame interval / max frames / night threshold, and click **Run Security Analysis**.

### 7. Run — Test Suite
```bash
# From the project root (no video or API key needed)
python tests/test_agent.py
```

---

## Configuration

| Parameter | Default | Location | Description |
|-----------|---------|----------|-------------|
| `FRAME_INTERVAL` | `2.5s` | `main.py` | Seconds between extracted frames |
| `MAX_FRAMES` | `20` | Dashboard | Max frames to cap API calls |
| `NIGHT_THRESHOLD` | `80%` | `video_processor.py` | % of video duration after which = night patrol |
| `MODEL` | `gemini-2.5-flash` | `video_processor.py` | Gemini model for vision + chat |
| `DEFAULT_VIDEO` | `security_footage.mp4` | `main.py` | Fallback filename if no argument passed |
| `CHROMA_PATH` | `./chroma_db` | `indexer.py` | Local ChromaDB persistence path |

---

## Expected Output

### CLI Pipeline
```
🚁  DRONE SECURITY ANALYST AGENT
   Mode: Real Video: security_footage.mp4
   Powered by Gemini Vision + LangGraph + ChromaDB

📡 Step 1: Loading drone telemetry and video frames...
   📹 Video loaded: 13.8s duration, 24.0 FPS
   ✅ Extracted frame F001 @ 0.0s → Zone A
   ...
   📸 Total frames extracted: 6

🔍 Step 2: Analysing frames with Gemini Vision...
   🔍 Analysing F001 @ Zone A (2026-06-14 08:00:00)...
   ⚠️  Gemini error for F002: 503 UNAVAILABLE — using fallback

📦 Step 3: Indexing frames into ChromaDB...
   ✅ Indexed F001 @ Zone A
   ...

🚨 Step 4: Running security alert engine...
   ℹ️  [LOW] 🔋 Drone battery critical: 10.0% at Zone D.

📊 Step 5: Generating AI daily security summary...
   Drone surveillance from 08:00 to 10:40 detected significant pedestrian
   movement across Zones A–C with Delhi Police barricades...
```

### Alerts
```
🚨 [CRITICAL] Person detected at night at Zone D. Immediate verification required.
   Action: Dispatch security personnel. Review live feed immediately.

⚠️  [HIGH] Loitering detected at Zone C. Person stationary for extended period.
   Action: Monitor closely. Alert security if behaviour continues.

🔔 [MEDIUM] Repeat vehicle: 'bicycle' seen 3x.
   Action: Log vehicle details. Verify with property owner if expected.
```

### Agent Q&A (Bonus)
```
❓ "What vehicles were detected?"
✅ 6 unique vehicles: green/yellow auto-rickshaw (Zone A), black motorcycle
   (Zone A), blue vendor cart (Zone B), white bus (Zone C)...

❓ "Show all critical alerts"
✅ 2 critical alerts — NIGHT_PERSON_DETECTED and LOITERING_DETECTED at Zone D.

❓ "What colour is the bus?"
✅ The bus is white.
```

---

## Telemetry

`telemetry.py` generates realistic drone telemetry for each extracted frame:
- **Battery**: drains linearly from 100% → 10% over the patrol
- **Altitude**: varies by zone (Zone A: 30m, Zone B: 25m, Zone C: 35m, Zone D: 40m)
- **Status**: `patrolling` / `hovering` / `returning` (when battery < 15%)
- **is_night**: `True` when `video_second >= total_seconds × 0.8`
- **Coordinates**: Base GPS (Pune, Maharashtra) offset per zone

A static `FRAME_DESCRIPTIONS` + `TELEMETRY_DATA` fixture is included for offline testing without a video file or API key.

---

## Testing

```bash
python tests/test_agent.py
```

The test suite is **video-agnostic** — it uses the static fixture data and runs without a Gemini API key. It covers:

| Suite | What it tests |
|-------|--------------|
| Telemetry | Frame/telemetry counts, required fields (`video_second`, `is_night`), battery range, unique IDs |
| Alert Engine | `NIGHT_PERSON_DETECTED` → CRITICAL; `LOITERING_DETECTED` → HIGH/CRITICAL; `LOW_BATTERY` when battery < 15%; `REPEAT_VEHICLE` on 2nd appearance; `HIGH_SECURITY_EVENT` when `security_level == "critical"` |
| ChromaDB | Empty-collection query returns `[]` not an error; semantic search returns correct frame with relevance score; location filter works; clear resets to 0 |
| Pipeline Integration | All frames index successfully; alert totals self-consistent (`total = critical + high + medium + low`) |

Expected output: `🎉 All tests passed! Score: 100.0%`

---

## AI Tools Used

| Tool | Purpose | Impact |
|------|---------|--------|
| **Gemini 2.5 Flash Vision** | Frame analysis, daily summary, agent LLM | Core intelligence — real vision analysis with structured JSON output |
| **LangGraph** | ReAct agent with 6 tools | Conversational Q&A over processed footage |
| **ChromaDB** | Vector database for frame indexing | Semantic search by object, location, security level |
| **Claude (Anthropic)** | Development assistance throughout | Code generation, debugging (4 runtime bugs fixed), architecture validation, test suite, dashboard scaffolding, documentation |

### How Claude Was Used
- **Generated**: Gemini Vision prompt/JSON schema, alert engine structure, LangGraph tools module, HTML dashboard, test suite
- **Debugged**: `KeyError: 'frame_num'` (missing field in static fixture); inverted `HIGH_SECURITY_EVENT` rule condition; missing `video_second`/`is_night` fields; test suite guard masking `LOW_BATTERY` regression
- **Explained**: ChromaDB `PersistentClient`, metadata filtering, empty-collection edge case
- **Customised by author**: All 8 alert domain rules, night-escalation logic, `answer_security_question` tool, zone-based telemetry model

---

## Bonus Features

- ✅ **Video Summarization** — Gemini generates a professional 3–4 sentence daily patrol summary (`generate_video_summary` in `video_processor.py`)
- ✅ **Follow-up Q&A Agent** — LangGraph ReAct agent answers natural-language questions about footage with 6 specialised tools
- ✅ **Browser Dashboard** — Self-contained dark-themed UI in `drone-security-dashboard.html` with frame gallery, Inspector panel, AI Chat, and Logs tabs

---

## Known Limitations

- Repeat-vehicle matching uses exact string equality on VLM output — same vehicle phrased differently across frames won't be linked
- ChromaDB runs locally; a multi-drone deployment would need a hosted shared vector store
- Gemini 503 errors occur under high API demand — handled by retry/backoff with a safe fallback record
- `create_react_agent` import is deprecated in LangGraph V1.0 (warning shown at runtime); will need migration to `langchain.agents.create_agent` before V2.0

---

*Built for FlytBase AI Engineer Assignment · June 2026*

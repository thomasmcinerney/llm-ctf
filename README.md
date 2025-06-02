# LLM Security Research Platform

A full‑stack laboratory for evaluating **prompt‑injection**, context manipulation, jailbreaks, and sandbox‑escape attacks against Large‑Language‑Models (LLMs).

> **Why this exists**
> Modern LLMs are powerful—but fragile.  This project provides a reproducible test‑bed to measure, visualize, and harden model‑level defences against malicious or accidental prompt attacks.

---

## Key Features

| Area                          | Highlights                                                                                                                                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Challenges**                | Five built‑in security scenarios (`basic_bypass`, `role_confusion`, `context_manipulation`, `instruction_injection`, `system_escape`) with per‑challenge prompts, forbidden files, and tool whitelists. |
| **Pluggable Agents**          | Works with OpenAI (`gpt‑4o`) out of the box and AnthropicClaude 3.5 if the `ANTHROPIC_API_KEY` is provided.                                                                                            |
| **In‑depth Telemetry**        | Tracks every tool call, injection technique, token usage, and security event; persists to SQLite with automatic retry handling.                                                                        |
| **Prompt‑Injection Detector** | Hybrid rule‑based+ ML ensemble (HF *InjecGuard* & optional OpenAI Moderations) returning labelled techniques.                                                                                          |
| **One‑click Analysis**        | Generates a comprehensive JSON report: risk score, breach detection, technique escalation, tool success rates, timeline events, and remediation recommendations.                                        |
| **Modern UI**                 | Vanilla JS + custom CSS with live chat, session manager, interactive timeline, and matrix visualisations.                                                                                               |
| **Containerised**             | Single‑command spin‑up via DockerCompose; mounts source for hot‑reload during development.                                                                                                             |

---

## Quick Start

### 1·Clone & configure

```bash
#Clone repo
$ git clone https://github.com/thomasmcinerney/llm‑ctf.git
$ cd llm‑ctf

#Create .env and add keys
#  OPENAI_API_KEY=sk‑...
#  ANTHROPIC_API_KEY=...   # optional
```

### 2·Run with Docker (recommended)

```bash
$ docker compose up --build
```

This builds the backend container, installs Python dependencies, and exposes:

* **Backend API**:[http://localhost:9000/api](http://localhost:9000/api)
* **Frontend (static)**: open `index.html` in your browser (served by any static server or VSCode LiveServer).

### 3·Run natively (development mode)

```bash
# Backend
$ cd backend
$ python -m venv .venv && source .venv/bin/activate
$ pip install -r requirements.txt
$ python main.py  --verbose

# Frontend
$ npx serve -l 8000 .   # or open index.html directly
```

---

## Project Structure

```
.
├── backend
│   ├── agents.py              #Tool‑aware agent factory
│   ├── analysis.py            #Response & breach analysis helpers
│   ├── database.py            #SQLite schema + thread‑safe wrapper
│   ├── injection_detector.py  #Rule/ML hybrid detector
│   ├── main.py                #FastAPI app (REST API + startup/shutdown)
│   ├── session_management.py  #In‑memory & DB session manager
│   └── ...
├── assets
│   ├── js/main.js             #Frontend logic (chat, analysis views)
│   └── css/styles.css         #Design system
├── index.html                 #Single‑page UI
├── docker-compose.yml
└── Dockerfile
```

---

## Environment Variables

| Variable            | Description                            |
| ------------------- | -------------------------------------- |
| `OPENAI_API_KEY`    | **Required** for OpenAI agent.         |
| `ANTHROPIC_API_KEY` | Optional—enables Claude agent support. |
| `VERBOSE`           | `true` to enable console debug logs.   |
| `PORT`              | Backend port (default`9000`).         |

---

## API Overview

When the server is running, browse interactive docs at **`/docs`** (Swagger) or **`/redoc`**.

| Method | Endpoint               | Purpose                                                 |
| ------ | ---------------------- | ------------------------------------------------------- |
| `GET`  | `/api/challenges`      | List all available security challenges.                 |
| `POST` | `/api/start_research`  | Create a new session (returns `session_id`).            |
| `POST` | `/api/interact`        | Send user input and receive AI response plus telemetry. |
| `POST` | `/api/analyze_session` | Generate full session analysis JSON.                    |
| `GET`  | `/api/session/{id}`    | Fetch session, interactions, and events.                |
| `GET`  | `/api/research_stats`  | Aggregate statistics across all sessions.               |

---

## Adding New Challenges

1. Open **`backend/config.py`**.
2. Duplicate an existing entry in `SECURITY_CHALLENGES` and change:

   * `id`, `name`, `description`.
   * `security_prompt`, `forbidden_files`, `allowed_files`.
   * `tools` list (subset of `file_read`, `file_write`, `file_list`, `terminal_command`).
3. Restart the backend—your new challenge auto‑loads and appears in the UI.

---

## Contributing

Pull requests are welcome.

---

## License

Released under the **MIT License**—see `LICENSE` for details.

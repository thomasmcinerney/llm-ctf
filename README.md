# LLM-CTF Security Research Platform

## Overview

LLM-CTF is an advanced security research platform for studying the security boundaries of Large Language Models (LLMs). It provides interactive security challenges focused on prompt injection, context manipulation, and AI boundary testing. The platform includes:
- A FastAPI backend for managing research sessions, AI agents, challenges, and session analysis.
- A modern JavaScript/HTML/CSS web frontend for interactive research workflows and results visualization.
- Support for integration with OpenAI and Anthropic models via the backend.

## Features

- **Challenge-Based Prompt Security Testing**: Select from predefined security challenges (e.g., prompt injection, context escape) to analyze LLM behavior.
- **Session Management**: Start and track research sessions, interact with AI agents, and view session history.
- **Detailed Analysis**: Real-time analysis of prompt injection techniques, AI model responses, and breach detection.
- **Session Analytics**: Visualization of session statistics, historical research outcomes, and detected vulnerabilities.
- **Extensible / Dockerized**: Easy to run locally in Docker, and to add new LLM challenges.

## Directory Structure

```
├── backend/                   # FastAPI backend app
│   ├── agents.py              # LLM agent wrappers
│   ├── analysis.py            # Analysis logic (injection, breach detection)
│   ├── config.py              # Challenge and config settings
│   ├── database.py            # SQLite DB manager
│   ├── main.py                # FastAPI APIs
│   ├── requirements.txt       # Python requirements
│   └── ...                    # More modules/utilities
├── assets/                    # Frontend assets
│   ├── css/styles.css         # Main styles
│   └── js/main.js             # Frontend JS logic
├── index.html                 # Main frontend web app
├── Dockerfile                 # Backend Docker build
├── docker-compose.yml         # Docker orchestration
├── serve.py                   # Simple HTTP server for dev
└── ...
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/thomasmcinerney/llm-ctf
cd LLM-CTF
```

### 2. Running with Docker

The easiest way to start both backend and frontend is using Docker Compose:

```bash
docker-compose up --build
```

- Backend API: [http://localhost:9000](http://localhost:9000)
- Frontend: open `index.html` directly in your browser, or use `python serve.py` (see below).

### 3. Running Locally (Dev Mode)

**Backend:**
```bash
cd backend
pip install -r requirements.txt
python main.py
```

**Frontend:**
```bash
python serve.py
```
This serves `index.html` and static assets on [http://localhost:8000](http://localhost:8000).

## Usage

1. Access the frontend UI.
2. Browse and select a security challenge.
3. Start a research session and interact with the AI agent to probe security boundaries.
4. Review session results, analysis, and historical performance.

## Configuration

- **Challenge Descriptions**: See `backend/config.py` for how challenges are defined.
- **AI Keys**: Set API keys for OpenAI or Anthropic in your environment as needed.
- **Persistence**: Session data and logs are stored in SQLite under `backend/research_data.db`.

## API

- `GET /api/challenges`: List available security challenges.
- `POST /api/start_research`: Start a new research session.
- `POST /api/interact`: Interact in an active session.
- ... (see `backend/main.py` for complete API).

## Requirements

- Python 3.11+
- [See `backend/requirements.txt`](backend/requirements.txt) for backend dependencies (FastAPI, OpenAI, Anthropic, etc).
- Docker/Docker Compose for containerized use.

## License

MIT License

## Credits

Developed as part of an LLM security research project.

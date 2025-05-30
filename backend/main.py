"""
Main FastAPI application for the LLM Security Research Platform
"""

import os
import json
import uuid
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config import SECURITY_CHALLENGES, get_log_config
from database import init_database, DatabaseManager
from agents import create_research_agent, setup_challenge_files
from analysis import analyze_injection_techniques, analyze_ai_response, detect_successful_breach, generate_session_analysis
from session_management import session_manager, get_current_user

# ───────────────────── LOGGING SETUP
parser = argparse.ArgumentParser()
parser.add_argument("--verbose", action="store_true")
args, _ = parser.parse_known_args()

log_config = get_log_config()
VERBOSE = args.verbose or os.getenv("VERBOSE", "false").lower() in ("true", "1", "yes")

logging.basicConfig(
    filename=log_config["file"],
    level=getattr(logging, log_config["level"]),
    format=log_config["format"]
)

def vlog(*args, **kwargs):
    if VERBOSE:
        print("[VERBOSE]", *args, **kwargs)
        logging.debug(" ".join(str(arg) for arg in args))

# ───────────────────── INITIALIZE SERVICES
init_database()
db = DatabaseManager()

# Store agents separately from sessions
AGENTS: Dict[str, Any] = {}

# ───────────────────── PYDANTIC MODELS
class StartResearchRequest(BaseModel):
    challenge_id: str
    agent_type: str = "openai"
    researcher_notes: Optional[str] = None

class InteractionRequest(BaseModel):
    session_id: str
    user_input: str

class AnalysisRequest(BaseModel):
    session_id: str

# ───────────────────── FASTAPI APP
app = FastAPI(title="LLM Security Research Platform")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

@app.get("/api/challenges")
def list_challenges():
    """Get list of available security challenges"""
    return {
        "challenges": [
            {
                "id": challenge_id,
                "name": challenge["name"],
                "category": challenge["category"],
                "description": challenge["description"],
                "vulnerability_type": challenge["vulnerability_type"],
                "forbidden_files": challenge.get("forbidden_files", []),
                "allowed_files": challenge["allowed_files"],
                "tools": challenge["tools"]
            }
            for challenge_id, challenge in SECURITY_CHALLENGES.items()
        ]
    }

@app.post("/api/start_research")
def start_research(req: StartResearchRequest):
    """Start a new research session"""
    if req.challenge_id not in SECURITY_CHALLENGES:
        raise HTTPException(400, f"Unknown challenge: {req.challenge_id}")

    # Create session
    session = session_manager.create_session(req.challenge_id, req.agent_type, req.researcher_notes)

    # Setup challenge files
    setup_challenge_files(session.game_dir, req.challenge_id)

    # Create AI agent
    try:
        agent = create_research_agent(session.session_id, req.challenge_id, req.agent_type)
        AGENTS[session.session_id] = agent
    except Exception as e:
        session_manager.end_session(session.session_id)
        raise HTTPException(500, f"Failed to create AI agent: {str(e)}")

    challenge = SECURITY_CHALLENGES[req.challenge_id]

    vlog(f"[RESEARCH_START] Session {session.session_id} started for challenge {req.challenge_id}")

    return {
        "session_id": session.session_id,
        "challenge": challenge,
        "agent_type": req.agent_type,
        "start_time": session.start_time.isoformat(),
        "research_notes": req.researcher_notes
    }

@app.post("/api/interact")
def research_interaction(req: InteractionRequest):
    """Conduct a research interaction"""
    session = session_manager.get_session(req.session_id)
    if not session:
        raise HTTPException(404, "Research session not found")

    agent = AGENTS.get(req.session_id)
    if not agent:
        raise HTTPException(500, "AI agent not found")

    session.interaction_count += 1
    interaction_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc)

    try:
        vlog(f"[INTERACTION] Session {req.session_id}, #{session.interaction_count}: {req.user_input[:100]}")

        # Analyze user input for injection techniques
        injection_techniques = analyze_injection_techniques(req.user_input)

        # Run the AI agent
        result = agent.run_sync(req.user_input, message_history=session.conversation_history)
        response = result.output

        # Update conversation history
        session.conversation_history.extend(result.new_messages())

        # Analyze AI response
        challenge = SECURITY_CHALLENGES[session.challenge_id]
        response_analysis = analyze_ai_response(
            response,
            challenge.get("forbidden_files", []),
            session.challenge_id
        )

        # Check for successful breach
        breach_details = detect_successful_breach(response, session.challenge_id)
        if breach_details and not session.successful_breach:
            session.record_breach(breach_details)

        # Get token usage if available
        token_usage = {}
        try:
            usage_obj = result.usage()
            token_usage = (
                usage_obj.model_dump()
                if hasattr(usage_obj, "model_dump")
                else usage_obj.__dict__
            )
        except:
            pass

        # Log interaction to database
        interaction_data = {
            "interaction_id": interaction_id,
            "session_id": req.session_id,
            "sequence_number": session.interaction_count,
            "timestamp": timestamp.isoformat(),
            "user_input": req.user_input,
            "ai_response": response,
            "token_usage": token_usage,
            "injection_techniques": injection_techniques,
            "response_analysis": response_analysis,
            "breach_details": breach_details
        }
        db.log_interaction(interaction_data)

        return {
            "ai_response": response,
            "analysis": response_analysis,
            "detected_techniques": injection_techniques,
            "breach": breach_details,
            "token_usage": token_usage
        }
    except Exception as e:
        vlog(f"[ERROR] Interaction failed: {str(e)}")
        raise HTTPException(500, f"Interaction failed: {str(e)}")

@app.get("/api/session/{session_id}")
def get_session(session_id: str):
    """Get session info"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return session.to_dict()

# ---------------- NEW ENDPOINTS (Statistics & User Sessions) ---------------------
@app.get('/api/sessions')
def list_user_sessions(user=Depends(get_current_user)):
    """
    Returns session summary objects for the logged-in user.
    """
    with db._conn() as conn:
        rows = conn.execute(
            "SELECT session_id, challenge_id, start_time, end_time, total_interactions, successful_breach "
            "FROM research_sessions WHERE user_id = ? ORDER BY start_time DESC",
            (user.user_id,)
        ).fetchall()
    sessions = [
        {
            "session_id": row[0],
            "challenge_id": row[1],
            "challenge_name": row[1],
            "status": "complete" if row[3] else "active",
            "started_at": row[2],
            "total_interactions": row[4] or 0,
            "successful_breach": bool(row[5])
        }
        for row in rows
    ]
    return {"sessions": sessions}

@app.get('/api/statistics')
def get_statistics(user=Depends(get_current_user)):
    """
    Site/user stats for statistics tab.
    """
    with db._conn() as conn:
        user_count = conn.execute("SELECT COUNT(1) FROM users").fetchone()[0]
        session_count = conn.execute("SELECT COUNT(1) FROM research_sessions").fetchone()[0]
        user_sessions = conn.execute("SELECT COUNT(1) FROM research_sessions WHERE user_id = ?", (user.user_id,)).fetchone()[0]
        breaches = conn.execute("SELECT COUNT(1) FROM research_sessions WHERE successful_breach = 1").fetchone()[0]
    return {
        "site_users": user_count,
        "site_sessions": session_count,
        "your_sessions": user_sessions,
        "total_breaches": breaches
    }

@app.get("/api/sessions/{session_id}/analysis")
def session_analysis(session_id: str, user=Depends(get_current_user)):
    """
    Returns placeholder analysis for this session (expand as you wish!)
    """
    s = db.get_session_by_id(session_id)
    if not s or s['user_id'] != user.user_id:
        raise HTTPException(404, "No such session for this user")
    return {
        "session_id": session_id,
        "challenge_id": s['challenge_id'],
        "total_interactions": s["total_interactions"],
        "successful_breach": s.get("successful_breach", False),
    }
# ---------------- END OF FILE ---------------------

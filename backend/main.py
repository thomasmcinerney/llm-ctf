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

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config import SECURITY_CHALLENGES, get_log_config
from database import init_database, DatabaseManager
from agents import create_research_agent, setup_challenge_files
from analysis import analyze_injection_techniques, analyze_ai_response, detect_successful_breach, generate_session_analysis
from session_management import session_manager

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
            "injection_techniques": injection_techniques,
            "response_analysis": response_analysis,
            "token_usage": token_usage
        }
        db.log_interaction(interaction_data)

        # Update session in database
        session.log_to_database()

        return {
            "interaction_id": interaction_id,
            "sequence_number": session.interaction_count,
            "response": response,
            "injection_techniques_detected": injection_techniques,
            "response_analysis": response_analysis,
            "breach_detected": breach_details is not None,
            "breach_details": breach_details,
            "token_usage": token_usage,
            "security_events": len(session.security_events),
            "session_status": {
                "total_interactions": session.interaction_count,
                "successful_breach": session.successful_breach,
                "breach_details": session.breach_details
            }
        }

    except Exception as e:
        vlog(f"[INTERACTION_ERROR] Error in session {req.session_id}: {str(e)}")
        raise HTTPException(500, f"Interaction error: {str(e)}")

@app.get("/api/session/{session_id}")
def get_session_details(session_id: str):
    """Get detailed session information"""
    session_data = db.get_session(session_id)
    if not session_data:
        raise HTTPException(404, "Session not found")

    interactions = db.get_interactions(session_id)
    events = db.get_security_events(session_id)

    return {
        "session": session_data,
        "interactions": interactions,
        "security_events": events
    }

@app.get("/api/sessions")
def list_sessions(skip: int = 0, limit: int = 100):
    """List all research sessions"""
    result = db.get_sessions(skip, limit)
    return {
        **result,
        "skip": skip,
        "limit": limit
    }

@app.post("/api/analyze_session")
def analyze_session(req: AnalysisRequest):
    """Generate comprehensive analysis of a research session"""
    # Get session data
    session_data = db.get_session(req.session_id)
    if not session_data:
        raise HTTPException(404, "Session not found")

    interactions = db.get_interactions(req.session_id)
    events = db.get_security_events(req.session_id)

    # Generate analysis
    analysis = generate_session_analysis(session_data, interactions, events)

    # Store analysis results
    analysis_id = str(uuid.uuid4())
    analysis["analysis_id"] = analysis_id
    analysis["created_timestamp"] = datetime.now(timezone.utc).isoformat()

    return analysis

@app.get("/api/research_stats")
def get_research_stats():
    """Get overall research statistics"""
    stats = db.get_research_stats()

    # Add active session stats
    active_stats = session_manager.get_session_stats()
    stats["active_sessions"] = active_stats

    return stats

@app.get("/api/export_session/{session_id}")
def export_session_data(session_id: str):
    """Export complete session data for external analysis"""
    session_data = db.get_session(session_id)
    if not session_data:
        raise HTTPException(404, "Session not found")

    interactions = db.get_interactions(session_id)
    events = db.get_security_events(session_id)

    export_data = {
        "session_metadata": session_data,
        "interactions": interactions,
        "security_events": events,
        "export_timestamp": datetime.now(timezone.utc).isoformat(),
        "challenge_config": SECURITY_CHALLENGES.get(session_data.get("challenge_id", ""), {})
    }

    return export_data

@app.delete("/api/session/{session_id}")
def end_session(session_id: str):
    """End a research session"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    # Clean up
    session_manager.end_session(session_id)
    if session_id in AGENTS:
        del AGENTS[session_id]

    return {"message": f"Session {session_id} ended successfully"}

@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_sessions": len(session_manager.sessions),
        "available_challenges": len(SECURITY_CHALLENGES),
        "database_ready": True
    }

@app.get("/api/challenge/{challenge_id}/details")
def get_challenge_details(challenge_id: str):
    """Get detailed information about a specific challenge"""
    if challenge_id not in SECURITY_CHALLENGES:
        raise HTTPException(404, f"Challenge {challenge_id} not found")

    challenge = SECURITY_CHALLENGES[challenge_id]

    # Don't expose actual file contents in API
    safe_challenge = {**challenge}
    safe_challenge["setup_files"] = {
        filename: f"<Content hidden - {len(content)} characters>"
        for filename, content in challenge["setup_files"].items()
    }

    return {
        "challenge": safe_challenge,
        "stats": {
            # Could add challenge-specific stats here
            "total_attempts": 0,  # TODO: Implement from database
            "success_rate": 0.0   # TODO: Implement from database
        }
    }

@app.post("/api/session/{session_id}/add_note")
def add_session_note(session_id: str, note: dict):
    """Add a researcher note to a session"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    # Add note as a security event
    session.add_security_event({
        "event_type": "researcher_note",
        "event_description": note.get("content", ""),
        "severity": "info",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "technical_details": {
            "note_type": note.get("type", "general"),
            "researcher": note.get("researcher", "unknown")
        }
    })

    return {"message": "Note added successfully"}

@app.get("/api/session/{session_id}/conversation")
def get_conversation_history(session_id: str):
    """Get the conversation history for a session"""
    session = session_manager.get_session(session_id)
    if not session:
        # Try to get from database
        interactions = db.get_interactions(session_id)
        if not interactions:
            raise HTTPException(404, "Session not found")

        conversation = []
        for interaction in interactions:
            conversation.append({
                "role": "user",
                "content": interaction["user_input"],
                "timestamp": interaction["timestamp"]
            })
            conversation.append({
                "role": "assistant",
                "content": interaction["ai_response"],
                "timestamp": interaction["timestamp"],
                "analysis": json.loads(interaction.get("response_analysis", "{}"))
            })

        return {"conversation": conversation}

    # Convert message history to readable format
    conversation = []
    for msg in session.conversation_history:
        conversation.append({
            "role": msg.role,
            "content": str(msg.content),
            "timestamp": getattr(msg, "timestamp", None)
        })

    return {"conversation": conversation}

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    # Create base research directory
    Path("research_sessions").mkdir(exist_ok=True)

    # Clean up any old sessions from memory (in case of restart)
    session_manager.cleanup_old_sessions(max_age_hours=24)

    vlog(f"[BOOT] Security Research Backend started with {len(SECURITY_CHALLENGES)} challenges")
    print(f"[STARTUP] Server ready - {len(SECURITY_CHALLENGES)} challenges available")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    # End all active sessions
    for session_id in list(session_manager.sessions.keys()):
        session_manager.end_session(session_id)

    # Clear agents
    AGENTS.clear()

    vlog("[SHUTDOWN] All sessions ended, cleanup complete")
    print("[SHUTDOWN] Server stopped - all sessions cleaned up")

# ───────────────────── STARTUP
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "9000"))
    print(f"🔬 LLM Security Research Platform")
    print(f"🌐 Running on http://localhost:{port}")
    print(f"📊 Available challenges: {len(SECURITY_CHALLENGES)}")

    # Check for available AI models
    available_models = ["OpenAI GPT-4"]
    try:
        from pydantic_ai.models.anthropic import AnthropicModel
        available_models.append("Claude")
    except ImportError:
        pass

    print(f"🤖 Supported AI models: {', '.join(available_models)}")
    print(f"💾 Database: research_data.db")
    print(f"📁 Sessions directory: ./research_sessions/")
    print(f"📝 Logs: ./logs/security_research.log")

    try:
        uvicorn.run(app, host="0.0.0.0", port=port)
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user")
    except Exception as e:
        print(f"[ERROR] Server failed to start: {e}")
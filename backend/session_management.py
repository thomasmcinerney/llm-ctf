"""
Research session management for the LLM Security Research Platform
"""

import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from database import DatabaseManager


class ResearchSession:
    """Manages a single research session"""

    def __init__(self, session_id: str, challenge_id: str, agent_type: str):
        self.session_id = session_id
        self.challenge_id = challenge_id
        self.agent_type = agent_type
        self.start_time = datetime.now(timezone.utc)
        self.interaction_count = 0
        self.game_dir = Path(f"research_sessions/{session_id}")
        self.conversation_history = []
        self.security_events = []
        self.successful_breach = False
        self.breach_details = None
        self.db = DatabaseManager()

    def log_to_database(self):
        """Log session to database"""
        session_data = {
            "session_id": self.session_id,
            "challenge_id": self.challenge_id,
            "agent_type": self.agent_type,
            "start_time": self.start_time.isoformat(),
            "total_interactions": self.interaction_count,
            "successful_breach": self.successful_breach,
            "breach_method": self.breach_details.get("breach_type") if self.breach_details else None,
            "breach_timestamp": self.breach_details.get("timestamp") if self.breach_details else None
        }
        self.db.log_session(session_data)

    def add_security_event(self, event: Dict[str, Any]):
        """Add a security event to the session"""
        self.security_events.append(event)
        event["session_id"] = self.session_id
        self.db.log_security_event(event)

    def record_breach(self, breach_details: Dict[str, Any]):
        """Record a successful security breach"""
        if not self.successful_breach:
            self.successful_breach = True
            self.breach_details = {
                **breach_details,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "interaction_number": self.interaction_count
            }

            # Log breach as security event
            self.add_security_event({
                "event_type": "security_breach",
                "event_description": f"Successful breach detected: {breach_details['breach_type']}",
                "severity": "critical",
                "timestamp": self.breach_details["timestamp"],
                "technical_details": breach_details
            })


class SessionManager:
    """Manages all research sessions"""

    def __init__(self):
        self.sessions: Dict[str, ResearchSession] = {}
        self.db = DatabaseManager()

    def generate_session_id(self) -> str:
        """Generate a unique session ID"""
        return str(uuid.uuid4())

    def create_session(self, challenge_id: str, agent_type: str,
                       researcher_notes: Optional[str] = None) -> ResearchSession:
        """Create a new research session"""
        session_id = self.generate_session_id()
        session = ResearchSession(session_id, challenge_id, agent_type)

        # Log initial session
        session.log_to_database()

        # Store in memory
        self.sessions[session_id] = session

        return session

    def get_session(self, session_id: str) -> Optional[ResearchSession]:
        """Get a session by ID"""
        return self.sessions.get(session_id)

    def resume_session(self, session_id, challenge_id, agent_type, start_time, breach=False, breach_details=None,
                       interaction_count=0):
        """Resume an existing session with provided details"""
        session = ResearchSession(session_id, challenge_id, agent_type)
        session.start_time = datetime.fromisoformat(start_time)
        session.successful_breach = breach
        session.breach_details = breach_details
        session.interaction_count = interaction_count

        self.sessions[session_id] = session
        return session

    def end_session(self, session_id: str):
        """End a research session"""
        session = self.sessions.get(session_id)
        if session:
            # Final database update
            session.log_to_database()
            # Remove from memory
            del self.sessions[session_id]

    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Clean up old sessions from memory"""
        current_time = datetime.now(timezone.utc)
        to_remove = []

        for session_id, session in self.sessions.items():
            age_hours = (current_time - session.start_time).total_seconds() / 3600
            if age_hours > max_age_hours:
                to_remove.append(session_id)

        for session_id in to_remove:
            self.end_session(session_id)

    def get_session_stats(self) -> Dict[str, Any]:
        """Get statistics about active sessions"""
        return {
            "active_sessions": len(self.sessions),
            "sessions_by_challenge": {
                challenge_id: len([s for s in self.sessions.values() if s.challenge_id == challenge_id])
                for challenge_id in set(s.challenge_id for s in self.sessions.values())
            },
            "sessions_by_agent": {
                agent_type: len([s for s in self.sessions.values() if s.agent_type == agent_type])
                for agent_type in set(s.agent_type for s in self.sessions.values())
            }
        }


# Global session manager instance
session_manager = SessionManager()
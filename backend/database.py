"""
Database operations for the LLM Security Research Platform
"""

import sqlite3
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from config import DATABASE_CONFIG


def init_database():
    """Initialize SQLite database for research logging"""
    db_path = Path(DATABASE_CONFIG["path"])
    conn = sqlite3.connect(db_path)

    # --- Users table ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP NOT NULL
        )
    """)

    # --- Research sessions table (with user_id column for ownership) ---
    # Migration: add user_id to old table if not present
    cursor = conn.execute("PRAGMA table_info(research_sessions)")
    columns = [row[1] for row in cursor.fetchall()]
    if "user_id" not in columns:
        conn.execute("ALTER TABLE research_sessions ADD COLUMN user_id TEXT REFERENCES users(user_id)")

    conn.execute("""
                 CREATE TABLE IF NOT EXISTS research_sessions
                 (
                     session_id TEXT PRIMARY KEY,
                     challenge_id TEXT NOT NULL,
                     agent_type TEXT NOT NULL,
                     start_time TIMESTAMP NOT NULL,
                     end_time TIMESTAMP,
                     total_interactions INTEGER DEFAULT 0,
                     successful_breach BOOLEAN DEFAULT FALSE,
                     breach_method TEXT,
                     breach_timestamp TIMESTAMP,
                     session_notes TEXT,
                     user_id TEXT REFERENCES users(user_id)  -- Link to users
                 )
                 """)
    
    # --- Interactions table ---
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS interactions
                 (
                     interaction_id TEXT PRIMARY KEY,
                     session_id TEXT NOT NULL,
                     sequence_number INTEGER NOT NULL,
                     timestamp TIMESTAMP NOT NULL,
                     user_input TEXT NOT NULL,
                     ai_response TEXT NOT NULL,
                     tool_calls_made TEXT, 
                     security_violations TEXT,
                     response_analysis TEXT,
                     injection_techniques_detected TEXT,
                     token_usage TEXT,
                     FOREIGN KEY(session_id) REFERENCES research_sessions(session_id)
                 )
                 """)

    # --- Security events table ---
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS security_events
                 (
                     event_id TEXT PRIMARY KEY,
                     session_id TEXT NOT NULL,
                     interaction_id TEXT,
                     event_type TEXT NOT NULL,
                     event_description TEXT NOT NULL,
                     severity TEXT NOT NULL,
                     timestamp TIMESTAMP NOT NULL,
                     technical_details TEXT,
                     FOREIGN KEY(session_id) REFERENCES research_sessions(session_id),
                     FOREIGN KEY(interaction_id) REFERENCES interactions(interaction_id)
                 )
                 """)

    # --- Analysis results table ---
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS analysis_results
                 (
                     analysis_id TEXT PRIMARY KEY,
                     session_id TEXT NOT NULL,
                     challenge_id TEXT NOT NULL,
                     breach_successful BOOLEAN NOT NULL,
                     breach_method TEXT,
                     steps_to_breach INTEGER,
                     total_attempts INTEGER,
                     time_to_breach_seconds INTEGER,
                     injection_patterns_used TEXT,
                     ai_responses_analysis TEXT,
                     vulnerability_assessment TEXT,
                     created_timestamp TIMESTAMP NOT NULL,
                     FOREIGN KEY(session_id) REFERENCES research_sessions(session_id)
                 )
                 """)
    conn.commit()

class DatabaseManager:
    """Database utility methods including users/authentication"""
    def __init__(self):
        self.db_path = Path(DATABASE_CONFIG["path"])
    def _conn(self):
        return sqlite3.connect(self.db_path)

    # --- User Management ---
    def create_user(self, username: str, password_hash: str, is_admin: bool = False) -> str:
        user_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO users(user_id, username, password_hash, is_admin, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, username, password_hash, is_admin, created_at))
        return user_id

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if row:
                return {
                    "user_id": row[0], "username": row[1], "password_hash": row[2],
                    "is_admin": bool(row[3]), "created_at": row[4]
                }
            return None
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
            if row:
                return {
                    "user_id": row[0], "username": row[1], "password_hash": row[2],
                    "is_admin": bool(row[3]), "created_at": row[4]
                }
            return None

    # --- Research session logging ---
    def log_session(self, session_data: Dict[str, Any]):
        """Insert or update a research session record"""
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO research_sessions (
                    session_id, challenge_id, agent_type, start_time, total_interactions,
                    successful_breach, breach_method, breach_timestamp, session_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    challenge_id=excluded.challenge_id,
                    agent_type=excluded.agent_type,
                    start_time=excluded.start_time,
                    total_interactions=excluded.total_interactions,
                    successful_breach=excluded.successful_breach,
                    breach_method=excluded.breach_method,
                    breach_timestamp=excluded.breach_timestamp,
                    session_notes=excluded.session_notes
            """,
            (
                session_data["session_id"],
                session_data["challenge_id"],
                session_data["agent_type"],
                session_data["start_time"],
                session_data.get("total_interactions", 0),
                int(bool(session_data.get("successful_breach", False))),
                session_data.get("breach_method"),
                session_data.get("breach_timestamp"),
                session_data.get("session_notes")
            )
        )

    # TODO: implement any missing methods as needed for security_events, analysis, etc.

    # Existing session/logging methods ...


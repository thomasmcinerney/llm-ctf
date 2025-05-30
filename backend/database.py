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

    # Research sessions table
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS research_sessions
                 (
                     session_id
                     TEXT
                     PRIMARY
                     KEY,
                     challenge_id
                     TEXT
                     NOT
                     NULL,
                     agent_type
                     TEXT
                     NOT
                     NULL,
                     start_time
                     TIMESTAMP
                     NOT
                     NULL,
                     end_time
                     TIMESTAMP,
                     total_interactions
                     INTEGER
                     DEFAULT
                     0,
                     successful_breach
                     BOOLEAN
                     DEFAULT
                     FALSE,
                     breach_method
                     TEXT,
                     breach_timestamp
                     TIMESTAMP,
                     session_notes
                     TEXT
                 )
                 """)

    # Interactions table
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS interactions
                 (
                     interaction_id
                     TEXT
                     PRIMARY
                     KEY,
                     session_id
                     TEXT
                     NOT
                     NULL,
                     sequence_number
                     INTEGER
                     NOT
                     NULL,
                     timestamp
                     TIMESTAMP
                     NOT
                     NULL,
                     user_input
                     TEXT
                     NOT
                     NULL,
                     ai_response
                     TEXT
                     NOT
                     NULL,
                     tool_calls_made
                     TEXT, -- JSON array
                     security_violations
                     TEXT, -- JSON array
                     response_analysis
                     TEXT, -- JSON object
                     injection_techniques_detected
                     TEXT, -- JSON array
                     token_usage
                     TEXT, -- JSON object
                     FOREIGN
                     KEY
                 (
                     session_id
                 ) REFERENCES research_sessions
                 (
                     session_id
                 )
                     )
                 """)

    # Security events table
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS security_events
                 (
                     event_id
                     TEXT
                     PRIMARY
                     KEY,
                     session_id
                     TEXT
                     NOT
                     NULL,
                     interaction_id
                     TEXT,
                     event_type
                     TEXT
                     NOT
                     NULL, -- 'violation', 'breach', 'technique_detected', etc.
                     event_description
                     TEXT
                     NOT
                     NULL,
                     severity
                     TEXT
                     NOT
                     NULL, -- 'low', 'medium', 'high', 'critical'
                     timestamp
                     TIMESTAMP
                     NOT
                     NULL,
                     technical_details
                     TEXT, -- JSON object
                     FOREIGN
                     KEY
                 (
                     session_id
                 ) REFERENCES research_sessions
                 (
                     session_id
                 ),
                     FOREIGN KEY
                 (
                     interaction_id
                 ) REFERENCES interactions
                 (
                     interaction_id
                 )
                     )
                 """)

    # Analysis results table
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS analysis_results
                 (
                     analysis_id
                     TEXT
                     PRIMARY
                     KEY,
                     session_id
                     TEXT
                     NOT
                     NULL,
                     challenge_id
                     TEXT
                     NOT
                     NULL,
                     breach_successful
                     BOOLEAN
                     NOT
                     NULL,
                     breach_method
                     TEXT,
                     steps_to_breach
                     INTEGER,
                     total_attempts
                     INTEGER,
                     time_to_breach_seconds
                     INTEGER,
                     injection_patterns_used
                     TEXT, -- JSON array
                     ai_responses_analysis
                     TEXT, -- JSON object
                     vulnerability_assessment
                     TEXT, -- JSON object
                     created_timestamp
                     TIMESTAMP
                     NOT
                     NULL,
                     FOREIGN
                     KEY
                 (
                     session_id
                 ) REFERENCES research_sessions
                 (
                     session_id
                 )
                     )
                 """)

    conn.commit()
    conn.close()


class DatabaseManager:
    def __init__(self):
        self.db_path = DATABASE_CONFIG["path"]

    def log_session(self, session_data: Dict[str, Any]):
        """Log a research session to the database"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT OR REPLACE INTO research_sessions 
            (session_id, challenge_id, agent_type, start_time, total_interactions, 
             successful_breach, breach_method, breach_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_data["session_id"],
            session_data["challenge_id"],
            session_data["agent_type"],
            session_data["start_time"],
            session_data.get("total_interactions", 0),
            session_data.get("successful_breach", False),
            session_data.get("breach_method"),
            session_data.get("breach_timestamp")
        ))
        conn.commit()
        conn.close()

    def log_interaction(self, interaction_data: Dict[str, Any]):
        """Log an interaction to the database"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
                     INSERT INTO interactions
                     (interaction_id, session_id, sequence_number, timestamp, user_input, ai_response,
                      injection_techniques_detected, response_analysis, token_usage)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                     """, (
                         interaction_data["interaction_id"],
                         interaction_data["session_id"],
                         interaction_data["sequence_number"],
                         interaction_data["timestamp"],
                         interaction_data["user_input"],
                         interaction_data["ai_response"],
                         json.dumps(interaction_data.get("injection_techniques", [])),
                         json.dumps(interaction_data.get("response_analysis", {})),
                         json.dumps(interaction_data.get("token_usage", {}))
                     ))
        conn.commit()
        conn.close()

    def log_security_event(self, event_data: Dict[str, Any]):
        """Log a security event to the database"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
                     INSERT INTO security_events
                     (event_id, session_id, interaction_id, event_type, event_description,
                      severity, timestamp, technical_details)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                     """, (
                         str(uuid.uuid4()),
                         event_data["session_id"],
                         event_data.get("interaction_id"),
                         event_data["event_type"],
                         event_data["event_description"],
                         event_data["severity"],
                         event_data["timestamp"],
                         json.dumps(event_data.get("technical_details", {}))
                     ))
        conn.commit()
        conn.close()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID"""
        conn = sqlite3.connect(self.db_path)
        result = conn.execute("""
                              SELECT *
                              FROM research_sessions
                              WHERE session_id = ?
                              """, (session_id,)).fetchone()
        conn.close()

        if result:
            columns = [col[0] for col in conn.execute("PRAGMA table_info(research_sessions)").fetchall()]
            return dict(zip(columns, result))
        return None

    def get_sessions(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of sessions with pagination"""
        conn = sqlite3.connect(self.db_path)
        results = conn.execute("""
                               SELECT session_id,
                                      challenge_id,
                                      agent_type,
                                      start_time,
                                      end_time,
                                      total_interactions,
                                      successful_breach,
                                      breach_method,
                                      breach_timestamp
                               FROM research_sessions
                               ORDER BY start_time DESC LIMIT ?
                               OFFSET ?
                               """, (limit, skip)).fetchall()

        total_count = conn.execute("SELECT COUNT(*) FROM research_sessions").fetchone()[0]
        conn.close()

        sessions = [dict(zip([
            "session_id", "challenge_id", "agent_type", "start_time", "end_time",
            "total_interactions", "successful_breach", "breach_method", "breach_timestamp"
        ], row)) for row in results]

        return {"sessions": sessions, "total_count": total_count}

    def get_interactions(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all interactions for a session"""
        conn = sqlite3.connect(self.db_path)
        results = conn.execute("""
                               SELECT *
                               FROM interactions
                               WHERE session_id = ?
                               ORDER BY sequence_number
                               """, (session_id,)).fetchall()
        conn.close()

        columns = ["interaction_id", "session_id", "sequence_number", "timestamp",
                   "user_input", "ai_response", "tool_calls_made", "security_violations",
                   "response_analysis", "injection_techniques_detected", "token_usage"]

        return [dict(zip(columns, row)) for row in results]

    def get_security_events(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all security events for a session"""
        conn = sqlite3.connect(self.db_path)
        results = conn.execute("""
                               SELECT *
                               FROM security_events
                               WHERE session_id = ?
                               ORDER BY timestamp
                               """, (session_id,)).fetchall()
        conn.close()

        columns = ["event_id", "session_id", "interaction_id", "event_type",
                   "event_description", "severity", "timestamp", "technical_details"]

        return [dict(zip(columns, row)) for row in results]

    def get_research_stats(self) -> Dict[str, Any]:
        """Get overall research statistics"""
        conn = sqlite3.connect(self.db_path)

        # Overall stats
        total_sessions = conn.execute("SELECT COUNT(*) FROM research_sessions").fetchone()[0]
        successful_breaches = conn.execute(
            "SELECT COUNT(*) FROM research_sessions WHERE successful_breach = 1"
        ).fetchone()[0]

        # Stats by challenge
        challenge_stats = conn.execute("""
                                       SELECT challenge_id,
                                              COUNT(*)                as total_attempts,
                                              SUM(successful_breach)  as successful_breaches,
                                              AVG(total_interactions) as avg_interactions
                                       FROM research_sessions
                                       GROUP BY challenge_id
                                       """).fetchall()

        # Stats by agent type
        agent_stats = conn.execute("""
                                   SELECT agent_type,
                                          COUNT(*)               as total_sessions,
                                          SUM(successful_breach) as successful_breaches
                                   FROM research_sessions
                                   GROUP BY agent_type
                                   """).fetchall()

        conn.close()

        return {
            "overall": {
                "total_sessions": total_sessions,
                "successful_breaches": successful_breaches,
                "breach_rate": successful_breaches / total_sessions if total_sessions > 0 else 0
            },
            "by_challenge": [
                {
                    "challenge_id": row[0],
                    "total_attempts": row[1],
                    "successful_breaches": row[2],
                    "success_rate": row[2] / row[1] if row[1] > 0 else 0,
                    "avg_interactions": round(row[3], 2) if row[3] else 0
                }
                for row in challenge_stats
            ],
            "by_agent": [
                {
                    "agent_type": row[0],
                    "total_sessions": row[1],
                    "successful_breaches": row[2],
                    "success_rate": row[2] / row[1] if row[1] > 0 else 0
                }
                for row in agent_stats
            ]
        }
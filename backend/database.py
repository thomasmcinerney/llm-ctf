"""
Database operations for the LLM Security Research Platform
"""

import sqlite3
import json
import uuid
import threading
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
        self._local = threading.local()

    def _get_connection(self):
        """Get a thread-local database connection"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            try:
                self._local.connection = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=30.0
                )
                # Enable row factory for easier column access
                self._local.connection.row_factory = sqlite3.Row
            except Exception as e:
                print(f"[DATABASE_ERROR] Failed to create connection: {e}")
                raise
        return self._local.connection

    def _execute_with_retry(self, query, params=None, fetch=None):
        """Execute a query with automatic retry on connection issues"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()

                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)

                if fetch == 'one':
                    result = cursor.fetchone()
                elif fetch == 'all':
                    result = cursor.fetchall()
                else:
                    result = cursor

                conn.commit()
                return result

            except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
                print(f"[DATABASE_RETRY] Attempt {attempt + 1}/{max_retries} failed: {e}")
                # Close the connection to force reconnection
                if hasattr(self._local, 'connection'):
                    try:
                        self._local.connection.close()
                    except:
                        pass
                    self._local.connection = None

                if attempt == max_retries - 1:
                    raise
            except Exception as e:
                print(f"[DATABASE_ERROR] Unexpected error: {e}")
                raise

    def log_session(self, session_data: Dict[str, Any]):
        """Log a research session to the database"""
        self._execute_with_retry("""
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

    def log_interaction(self, interaction_data: Dict[str, Any]):
        """Log an interaction to the database"""
        # Handle tool_calls field mapping
        tool_calls = interaction_data.get("tool_calls", [])
        if not tool_calls:
            tool_calls = interaction_data.get("tool_calls_made", [])

        self._execute_with_retry("""
                     INSERT INTO interactions
                     (interaction_id, session_id, sequence_number, timestamp, user_input, ai_response,
                      tool_calls_made, injection_techniques_detected, response_analysis, token_usage)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     """, (
                         interaction_data["interaction_id"],
                         interaction_data["session_id"],
                         interaction_data["sequence_number"],
                         interaction_data["timestamp"],
                         interaction_data["user_input"],
                         interaction_data["ai_response"],
                         json.dumps(tool_calls),
                         json.dumps(interaction_data.get("injection_techniques", [])),
                         json.dumps(interaction_data.get("response_analysis", {})),
                         json.dumps(interaction_data.get("token_usage", {}))
                     ))

    def log_security_event(self, event_data: Dict[str, Any]):
        """Log a security event to the database"""
        self._execute_with_retry("""
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

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID"""
        try:
            result = self._execute_with_retry("""
                                  SELECT *
                                  FROM research_sessions
                                  WHERE session_id = ?
                                  """, (session_id,), fetch='one')

            if result:
                # Convert sqlite3.Row to dict
                return dict(result)
            return None

        except Exception as e:
            print(f"[DATABASE_ERROR] Error getting session {session_id}: {e}")
            return None

    def get_sessions(self, skip: int = 0, limit: int = 100) -> Dict[str, Any]:
        """Get list of sessions with pagination"""
        try:
            results = self._execute_with_retry("""
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
                                   """, (limit, skip), fetch='all')

            total_count_result = self._execute_with_retry(
                "SELECT COUNT(*) FROM research_sessions", fetch='one'
            )
            total_count = total_count_result[0] if total_count_result else 0

            sessions = [dict(row) for row in results]

            return {"sessions": sessions, "total_count": total_count}

        except Exception as e:
            print(f"[DATABASE_ERROR] Error getting sessions: {e}")
            return {"sessions": [], "total_count": 0}

    def get_interactions(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all interactions for a session"""
        try:
            results = self._execute_with_retry("""
                                   SELECT *
                                   FROM interactions
                                   WHERE session_id = ?
                                   ORDER BY sequence_number
                                   """, (session_id,), fetch='all')

            interactions = []
            for row in results:
                interaction = dict(row)
                # Parse JSON fields safely
                for json_field in ['tool_calls_made', 'injection_techniques_detected', 'response_analysis', 'token_usage']:
                    if interaction.get(json_field):
                        try:
                            interaction[json_field] = json.loads(interaction[json_field])
                        except (json.JSONDecodeError, TypeError):
                            interaction[json_field] = [] if json_field.endswith('_detected') or json_field.endswith('_made') else {}
                    else:
                        interaction[json_field] = [] if json_field.endswith('_detected') or json_field.endswith('_made') else {}

                # Map tool_calls_made to tool_calls for consistency
                if 'tool_calls_made' in interaction:
                    interaction['tool_calls'] = interaction['tool_calls_made']

                # Map injection_techniques_detected to injection_techniques for consistency
                if 'injection_techniques_detected' in interaction:
                    interaction['injection_techniques'] = interaction['injection_techniques_detected']

                interactions.append(interaction)

            return interactions

        except Exception as e:
            print(f"[DATABASE_ERROR] Error getting interactions for session {session_id}: {e}")
            return []

    def get_security_events(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all security events for a session"""
        try:
            results = self._execute_with_retry("""
                                   SELECT *
                                   FROM security_events
                                   WHERE session_id = ?
                                   ORDER BY timestamp
                                   """, (session_id,), fetch='all')

            events = []
            for row in results:
                event = dict(row)
                # Parse JSON technical_details safely
                if event.get('technical_details'):
                    try:
                        event['technical_details'] = json.loads(event['technical_details'])
                    except (json.JSONDecodeError, TypeError):
                        event['technical_details'] = {}
                else:
                    event['technical_details'] = {}
                events.append(event)

            return events

        except Exception as e:
            print(f"[DATABASE_ERROR] Error getting security events for session {session_id}: {e}")
            return []

    def get_research_stats(self) -> Dict[str, Any]:
        """Get overall research statistics"""
        try:
            # Overall stats
            total_sessions_result = self._execute_with_retry(
                "SELECT COUNT(*) FROM research_sessions", fetch='one'
            )
            total_sessions = total_sessions_result[0] if total_sessions_result else 0

            successful_breaches_result = self._execute_with_retry(
                "SELECT COUNT(*) FROM research_sessions WHERE successful_breach = 1", fetch='one'
            )
            successful_breaches = successful_breaches_result[0] if successful_breaches_result else 0

            # Stats by challenge
            challenge_stats = self._execute_with_retry("""
                                           SELECT challenge_id,
                                                  COUNT(*)                as total_attempts,
                                                  SUM(successful_breach)  as successful_breaches,
                                                  AVG(total_interactions) as avg_interactions
                                           FROM research_sessions
                                           GROUP BY challenge_id
                                           """, fetch='all')

            # Stats by agent type
            agent_stats = self._execute_with_retry("""
                                       SELECT agent_type,
                                              COUNT(*)               as total_sessions,
                                              SUM(successful_breach) as successful_breaches
                                       FROM research_sessions
                                       GROUP BY agent_type
                                       """, fetch='all')

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
                        "successful_breaches": row[2] if row[2] else 0,
                        "success_rate": (row[2] or 0) / row[1] if row[1] > 0 else 0,
                        "avg_interactions": round(row[3], 2) if row[3] else 0
                    }
                    for row in challenge_stats
                ],
                "by_agent": [
                    {
                        "agent_type": row[0],
                        "total_sessions": row[1],
                        "successful_breaches": row[2] if row[2] else 0,
                        "success_rate": (row[2] or 0) / row[1] if row[1] > 0 else 0
                    }
                    for row in agent_stats
                ]
            }

        except Exception as e:
            print(f"[DATABASE_ERROR] Error getting research stats: {e}")
            return {
                "overall": {"total_sessions": 0, "successful_breaches": 0, "breach_rate": 0},
                "by_challenge": [],
                "by_agent": []
            }

    def store_analysis(self, analysis_data: Dict[str, Any]):
        """Store analysis results in the database"""
        try:
            self._execute_with_retry("""
                INSERT INTO analysis_results
                (analysis_id, session_id, challenge_id, breach_successful, breach_method,
                 steps_to_breach, total_attempts, time_to_breach_seconds, 
                 injection_patterns_used, ai_responses_analysis, vulnerability_assessment, 
                 created_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_data["analysis_id"],
                analysis_data["session_id"],
                analysis_data["session_metadata"]["challenge_id"],
                analysis_data["security_analysis"]["breach_detected"],
                analysis_data["security_analysis"].get("breach_details", {}).get("method"),
                analysis_data["interaction_analysis"]["total_interactions"],
                analysis_data["injection_analysis"]["total_injection_attempts"],
                int(analysis_data["session_metadata"]["duration_seconds"]),
                json.dumps(list(analysis_data["injection_analysis"]["techniques_attempted"].keys())),
                json.dumps(analysis_data["behavioral_analysis"]),
                json.dumps(analysis_data["risk_assessment"]),
                analysis_data["created_timestamp"]
            ))

        except Exception as e:
            print(f"[DATABASE_ERROR] Error storing analysis: {e}")
            raise

    def close_connections(self):
        """Close all database connections"""
        if hasattr(self._local, 'connection') and self._local.connection:
            try:
                self._local.connection.close()
            except:
                pass
            self._local.connection = None

    def __del__(self):
        """Cleanup connections when object is destroyed"""
        self.close_connections()
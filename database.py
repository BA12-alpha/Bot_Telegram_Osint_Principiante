#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database module for CyberMentor Bot
Handles user profiles, progress tracking, and curriculum data
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

logger = logging.getLogger("ciberhackercito")


class Database:
    """Database manager for CyberMentor Bot"""

    def __init__(self, db_path: str = "cybermentor.db"):
        self.db_path = db_path
        self.init_database()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()

    def init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    device_type TEXT DEFAULT 'computer',
                    level TEXT DEFAULT 'beginner',
                    current_module TEXT DEFAULT 'A',
                    current_lesson TEXT DEFAULT '1.1',
                    xp INTEGER DEFAULT 0,
                    created_at TEXT,
                    last_active TEXT
                )
            """)

            # Progress table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS progress (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    lesson_id TEXT,
                    completed INTEGER DEFAULT 0,
                    score INTEGER DEFAULT 0,
                    completed_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)

            # Exercises table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exercises (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    exercise_id TEXT,
                    submission TEXT,
                    feedback TEXT,
                    score INTEGER,
                    submitted_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)

            # Achievements table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS achievements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    achievement_type TEXT,
                    achievement_name TEXT,
                    earned_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)

            # Specializations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS specializations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    specialization TEXT,
                    selected_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)

            conn.commit()
            logger.info("Database initialized successfully")

    def create_user(self, user_id: int, username: str = None, device_type: str = "computer") -> bool:
        """Create a new user profile"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO users (user_id, username, device_type, created_at, last_active)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_id, username, device_type, now, now))
            return True
        except sqlite3.IntegrityError:
            logger.info(f"User {user_id} already exists")
            return False

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user profile"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def update_user(self, user_id: int, **kwargs) -> bool:
        """Update user profile"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                kwargs['last_active'] = datetime.now().isoformat()
                
                fields = ", ".join([f"{key} = ?" for key in kwargs.keys()])
                values = list(kwargs.values()) + [user_id]
                
                cursor.execute(f"UPDATE users SET {fields} WHERE user_id = ?", values)
            return True
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            return False

    def add_xp(self, user_id: int, xp_amount: int) -> int:
        """Add XP to user and return new total"""
        user = self.get_user(user_id)
        if not user:
            return 0
        
        new_xp = user['xp'] + xp_amount
        self.update_user(user_id, xp=new_xp)
        return new_xp

    def mark_lesson_complete(self, user_id: int, lesson_id: str, score: int = 100) -> bool:
        """Mark a lesson as completed"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO progress (user_id, lesson_id, completed, score, completed_at)
                    VALUES (?, ?, 1, ?, ?)
                """, (user_id, lesson_id, score, now))
            return True
        except Exception as e:
            logger.error(f"Error marking lesson complete: {e}")
            return False

    def get_completed_lessons(self, user_id: int) -> List[str]:
        """Get list of completed lesson IDs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT lesson_id FROM progress 
                WHERE user_id = ? AND completed = 1
                ORDER BY completed_at
            """, (user_id,))
            return [row['lesson_id'] for row in cursor.fetchall()]

    def save_exercise_submission(self, user_id: int, exercise_id: str, 
                                 submission: str, feedback: str = "", score: int = 0) -> bool:
        """Save exercise submission"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO exercises (user_id, exercise_id, submission, feedback, score, submitted_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, exercise_id, submission, feedback, score, now))
            return True
        except Exception as e:
            logger.error(f"Error saving exercise: {e}")
            return False

    def get_user_stats(self, user_id: int) -> Dict[str, Any]:
        """Get user statistics"""
        user = self.get_user(user_id)
        if not user:
            return {}

        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Count completed lessons
            cursor.execute("""
                SELECT COUNT(*) as count FROM progress 
                WHERE user_id = ? AND completed = 1
            """, (user_id,))
            completed_count = cursor.fetchone()['count']
            
            # Count exercises
            cursor.execute("""
                SELECT COUNT(*) as count FROM exercises WHERE user_id = ?
            """, (user_id,))
            exercise_count = cursor.fetchone()['count']
            
            # Count achievements
            cursor.execute("""
                SELECT COUNT(*) as count FROM achievements WHERE user_id = ?
            """, (user_id,))
            achievement_count = cursor.fetchone()['count']
            
            # Average score
            cursor.execute("""
                SELECT AVG(score) as avg_score FROM progress 
                WHERE user_id = ? AND completed = 1
            """, (user_id,))
            avg_score = cursor.fetchone()['avg_score'] or 0

        return {
            'user_id': user_id,
            'level': user['level'],
            'xp': user['xp'],
            'current_module': user['current_module'],
            'current_lesson': user['current_lesson'],
            'completed_lessons': completed_count,
            'exercises_submitted': exercise_count,
            'achievements': achievement_count,
            'average_score': round(avg_score, 1),
            'created_at': user['created_at'],
            'last_active': user['last_active']
        }

    def add_achievement(self, user_id: int, achievement_type: str, achievement_name: str) -> bool:
        """Add an achievement for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO achievements (user_id, achievement_type, achievement_name, earned_at)
                    VALUES (?, ?, ?, ?)
                """, (user_id, achievement_type, achievement_name, now))
            return True
        except Exception as e:
            logger.error(f"Error adding achievement: {e}")
            return False

    def get_achievements(self, user_id: int) -> List[Dict[str, Any]]:
        """Get user achievements"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT achievement_type, achievement_name, earned_at 
                FROM achievements 
                WHERE user_id = ?
                ORDER BY earned_at DESC
            """, (user_id,))
            return [dict(row) for row in cursor.fetchall()]

    def add_specialization(self, user_id: int, specialization: str) -> bool:
        """Add a specialization for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO specializations (user_id, specialization, selected_at)
                    VALUES (?, ?, ?)
                """, (user_id, specialization, now))
            return True
        except Exception as e:
            logger.error(f"Error adding specialization: {e}")
            return False

    def get_specializations(self, user_id: int) -> List[str]:
        """Get user specializations"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT specialization FROM specializations 
                WHERE user_id = ?
                ORDER BY selected_at
            """, (user_id,))
            return [row['specialization'] for row in cursor.fetchall()]

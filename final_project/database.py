"""
The Continental Access Control System - Phase 2
Database Management Module

This module handles all database operations for The Continental.
It manages user data storage in SQLite with support for secure authentication.
"""

import sqlite3
from typing import Optional, Dict


# Database file name - stores all user information in a single SQLite file
DB_FILE = "continental.db"


def get_connection():
    """
    Creates and returns a connection to the SQLite database.

    This function sets up a connection with row_factory enabled, which allows
    us to access database rows like dictionaries (by column name) instead of
    just tuples. This makes the code much easier to read and work with.

    Returns:
        sqlite3.Connection: Database connection object
    """
    # Connect to the SQLite database file (creates it if it doesn't exist)
    conn = sqlite3.connect(DB_FILE)

    # This makes rows act like dictionaries - we can access by column name
    # Example: row['username'] instead of row[1]
    conn.row_factory = sqlite3.Row

    return conn


def init_database():
    """
    Initializes the database by creating the users table if it doesn't exist.

    The table structure:
    - id: Unique identifier for each user (automatically increments)
    - username: User's login name (must be unique across all users)
    - password_hash: Encrypted password using bcrypt (never store plain passwords!)
    - role: User's permission level (guest, member, manager)
    - created_at: Timestamp of when the account was created
    """
    # Get a connection to the database
    conn = get_connection()
    cursor = conn.cursor()

    # Create the users table if it doesn't already exist
    # CREATE TABLE IF NOT EXISTS prevents errors if we run this multiple times
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL,
                   role TEXT DEFAULT 'guest',
                   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                   )
    ''')

    # Save the changes to the database file
    conn.commit()

    # Close the connection to free up resources
    conn.close()


def add_user(username: str, password_hash: str, role: str = "guest") -> bool:
    """
    Adds a new user to the database.

    This function uses parameterized queries (the ? placeholders) to prevent
    SQL injection attacks. Never build SQL queries with string concatenation!

    Args:
        username (str): The user's username
        password_hash (str): The bcrypt hash of the user's password
        role (str): The user's role (default: "guest")

    Returns:
        bool: True if user was added successfully, False if username already exists
    """
    # Get a connection to the database
    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Insert the new user into the database
        # The ? placeholders are replaced with the values in the tuple
        # This is safe from SQL injection attacks
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (username, password_hash, role)
        )

        # Save the changes to the database
        conn.commit()
        conn.close()
        return True

    except sqlite3.IntegrityError:
        # This exception occurs when the UNIQUE constraint is violated
        # In our case, this means the username already exists in the database
        conn.close()
        return False

    except Exception as e:
        # Catch any other unexpected database errors
        print(f"Database error: {e}")
        conn.close()
        return False


def username_exists(username: str) -> bool:
    """
    Checks if a username already exists in the database.

    This is useful for validation before attempting to create a new account,
    allowing us to give the user a helpful error message.

    Args:
        username (str): The username to check

    Returns:
        bool: True if username exists, False otherwise
    """
    # Get a connection to the database
    conn = get_connection()
    cursor = conn.cursor()

    # Search for a user with this username
    # Using parameterized query (?) for security against SQL injection
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))

    # Try to get one matching row (there should only be one due to UNIQUE constraint)
    result = cursor.fetchone()

    # Close the connection
    conn.close()

    # If we found a result, the username exists (return True)
    # If result is None, the username doesn't exist (return False)
    return result is not None


def get_user(username: str) -> Optional[Dict]:
    """
    Retrieves a user's information from the database.

    This function is used during login to verify credentials and load user data.
    The returned dictionary includes the password hash, which can be checked
    against the user's login attempt using bcrypt.

    Args:
        username (str): The username to look up

    Returns:
        Optional[Dict]: Dictionary with user info if found, None if not found
                       Dictionary contains: id, username, password_hash, role, created_at
    """
    # Get a connection to the database
    conn = get_connection()
    cursor = conn.cursor()

    # Search for the user by username
    # Using parameterized query (?) for security
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))

    # Get the first matching row (should only be one due to UNIQUE constraint)
    result = cursor.fetchone()

    # Close the connection
    conn.close()

    # If we found a user, convert the row to a dictionary and return it
    if result:
        return dict(result)

    # If no user was found, return None
    return None


def get_all_users() -> list:
    """
    Retrieves all users from the database.

    Returns:
        list: List of dictionaries, each containing user information
    """
    # Get a connection to the database
    conn = get_connection()
    cursor = conn.cursor()

    # Get all users from the users table
    cursor.execute('SELECT * FROM users')

    # Fetch all rows at once
    results = cursor.fetchall()

    # Close the connection
    conn.close()

    # Convert each row to a dictionary and return as a list
    # This is a list comprehension - it loops through each row and converts it
    return [dict(row) for row in results]


def delete_all_users():
    """
    Deletes all users from the database.

    WARNING: This removes all user data. Only use for testing!
    """
    # Get a connection to the database
    conn = get_connection()
    cursor = conn.cursor()

    # Delete all rows from the users table (but keep the table structure)
    cursor.execute('DELETE FROM users')

    # Save the changes to the database
    conn.commit()

    # Close the connection
    conn.close()


def delete_database():
    """
    Deletes the entire database file from the filesystem.

    WARNING: This permanently removes the database. Only use for testing!
    """
    import os

    # Check if the database file exists before trying to delete it
    if os.path.exists(DB_FILE):
        # Remove the file from the filesystem
        os.remove(DB_FILE)

"""
The Continental Access Control System - Encrypted Audit Logging Module

This module provides secure audit logging functionality using Fernet encryption.
It tracks all access attempts, user actions, and security events in an encrypted
database to maintain a tamper-resistant audit trail.

Key Features:
- Encrypted storage of sensitive log details
- Automatic timestamp tracking for all events
- Brute force attack detection through failed login counting
- Flexible log querying and filtering
- Convenient logging functions for common security events
"""

from cryptography.fernet import Fernet
import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict
try:
    import database as db
except ImportError:
    from . import database as db

# Database file for storing audit logs
LOG_DB_FILE = "continental_logs.db"

# Encryption key file - stores the key persistently so logs remain decryptable
# across program restarts. In production, use a secure key management system.
ENCRYPTION_KEY_FILE = "continental_encryption.key"


def _get_or_create_encryption_key():
    """
    Loads the encryption key from file, or creates a new one if it doesn't exist.

    CRITICAL SECURITY FEATURE:
    This ensures the same encryption key is used across all program runs.
    Without this, logs encrypted in one session would be permanently unreadable
    in future sessions because Fernet encryption requires the EXACT same key
    to decrypt data that was encrypted with it.

    The key file should be:
    - Kept secure and backed up (losing it means losing access to all encrypted logs)
    - Never committed to version control (add to .gitignore)
    - Protected with proper file permissions in production

    Returns:
        bytes: The Fernet encryption key (44 bytes, base64-encoded)
    """
    # Check if the key file already exists
    if os.path.exists(ENCRYPTION_KEY_FILE):
        # Load the existing key from the file
        # This preserves the ability to decrypt old logs
        with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
            key = key_file.read()
            return key
    else:
        # No key file exists yet - generate a new key
        # This only happens on the first run of the program
        key = Fernet.generate_key()

        # Save the key to a file so we can use it again later
        # This is what makes logs readable across sessions
        with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
            key_file.write(key)

        return key


# Initialize the encryption key (load from file or create new)
# This must happen at module import time so the cipher is ready for use
ENCRYPTION_KEY = _get_or_create_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)


def get_log_connection():
    """
    Establishes a connection to the audit log database.

    Returns:
        sqlite3.Connection: Active database connection for log operations
    """
    return sqlite3.connect(LOG_DB_FILE)


def init_log_database():
    """
    Creates the audit log database and logs table if they don't exist.

    Database Schema:
    - id: Unique identifier for each log entry (auto-incrementing)
    - timestamp: When the event occurred (automatically set by database)
    - username: The user who performed the action
    - action: Type of event (e.g., "login_attempt", "registration", "permission_denied")
    - details: Encrypted JSON containing sensitive information about the event
    - ip_address: Optional IP address where the action originated
    - success: Whether the action succeeded (1) or failed (0)

    Security Note:
    The 'details' field is encrypted to protect sensitive information like
    IP addresses, failure reasons, and other metadata that could be exploited
    if the database is compromised. The 'username' and 'action' fields remain
    unencrypted to allow for efficient querying and filtering.
    """
    conn = get_log_connection()
    cursor = conn.cursor()

    # Create the logs table with all required columns
    # Using IF NOT EXISTS ensures we don't accidentally delete existing logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            success BOOLEAN
        )
    ''')

    # Save changes and close the connection
    conn.commit()
    conn.close()


def encrypt_log_details(details: Dict) -> str:
    """
    Encrypts log details using Fernet symmetric encryption.

    Fernet is a secure encryption method that guarantees:
    - Data cannot be read without the encryption key
    - Data cannot be modified without detection
    - Encrypted data includes a timestamp to prevent replay attacks

    This is important for audit logs because it prevents attackers from:
    1. Reading sensitive details even if they access the database
    2. Tampering with logs to hide their actions
    3. Inserting fake log entries

    Args:
        details (Dict): Dictionary containing log details to encrypt
                       (e.g., {'ip': '192.168.1.100', 'reason': 'Invalid password'})

    Returns:
        str: Base64-encoded encrypted string safe for database storage

    Example:
        >>> details = {'ip': '192.168.1.100', 'reason': 'Invalid password'}
        >>> encrypted = encrypt_log_details(details)
        >>> print(encrypted)
        gAAAAABl7x8Q9yH3KpL_mN5oP6qR7sT8uV9wX0yZ1...
    """
    # Step 1: Convert the dictionary to a JSON string
    # This allows us to store complex data structures in a single encrypted field
    json_data = json.dumps(details)

    # Step 2: Encrypt the JSON string
    # encode() converts the string to bytes (required for encryption)
    encrypted_bytes = cipher.encrypt(json_data.encode())

    # Step 3: Convert encrypted bytes to a string for database storage
    # decode() converts bytes back to a string that SQLite can store
    encrypted_string = encrypted_bytes.decode()

    return encrypted_string


def decrypt_log_details(encrypted_details: str) -> Dict:
    """
    Decrypts log details that were encrypted with encrypt_log_details().

    This function reverses the encryption process to retrieve the original
    log details. It requires the same encryption key that was used to encrypt
    the data, providing secure access control to sensitive log information.

    Args:
        encrypted_details (str): Base64-encoded encrypted string from database

    Returns:
        Dict: Decrypted dictionary containing the original log details

    Example:
        >>> encrypted = "gAAAAABl7x8Q9yH3KpL..."
        >>> details = decrypt_log_details(encrypted)
        >>> print(details)
        {'ip': '192.168.1.100', 'reason': 'Invalid password'}
    """
    # Step 1: Decrypt the encrypted string
    # encode() converts the string to bytes for decryption
    decrypted_bytes = cipher.decrypt(encrypted_details.encode())

    # Step 2: Convert decrypted bytes back to a string
    json_string = decrypted_bytes.decode()

    # Step 3: Parse the JSON string back into a dictionary
    # This restores the original structure of the log details
    details = json.loads(json_string)

    return details


def log_event(username: str, action: str, success: bool, details: Dict, ip_address: str = None):
    """
    Logs a security event to the encrypted audit log.

    Audit logging is critical for security because it:
    1. Creates a permanent record of all system access and actions
    2. Helps detect unauthorized access attempts and suspicious patterns
    3. Provides evidence for security investigations and compliance
    4. Enables accountability by tracking who did what and when

    This function encrypts sensitive details before storage, ensuring that
    even if someone gains access to the database, they can't read the details
    without the encryption key.

    Args:
        username (str): Username of the person performing the action
        action (str): Type of event being logged (e.g., "login_attempt", "registration")
        success (bool): Whether the action succeeded (True) or failed (False)
        details (Dict): Additional information about the event (will be encrypted)
        ip_address (str, optional): IP address where the action originated

    Example:
        >>> details = {'ip': '192.168.1.100', 'location': 'New York'}
        >>> log_event('JohnWick', 'login_attempt', True, details)
        >>> print("Event logged!")
    """
    # Encrypt the details before storing them in the database
    # This protects sensitive information like IP addresses and failure reasons
    encrypted_details = encrypt_log_details(details)

    # Connect to the log database
    conn = get_log_connection()
    cursor = conn.cursor()

    # Create a high-precision timestamp (includes microseconds)
    # This is important for accurate ordering of events that happen rapidly
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

    # Insert the log entry into the database
    # We convert success (boolean) to an integer because SQLite stores booleans as 0/1
    cursor.execute('''
        INSERT INTO logs (timestamp, username, action, details, ip_address, success)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, username, action, encrypted_details, ip_address, int(success)))

    # Save the changes and close the connection
    conn.commit()
    conn.close()


def get_logs(username: Optional[str] = None, action: Optional[str] = None, limit: int = 100) -> List[Dict]:
    """
    Retrieves and decrypts audit logs with optional filtering.

    This function queries the log database and automatically decrypts the
    details field of each log entry. It supports filtering by username and
    action type to help security administrators analyze specific events.

    The logs are returned in reverse chronological order (newest first),
    making it easy to see the most recent security events.

    Args:
        username (Optional[str]): Filter logs for a specific user (None = all users)
        action (Optional[str]): Filter logs by action type (None = all actions)
        limit (int): Maximum number of logs to return (default: 100)

    Returns:
        List[Dict]: List of log dictionaries with the following keys:
                   - id: Unique log entry ID
                   - timestamp: When the event occurred
                   - username: User who performed the action
                   - action: Type of event
                   - details: Decrypted dictionary of event details
                   - ip_address: IP address (if recorded)
                   - success: Whether the action succeeded

    Example:
        >>> logs = get_logs(username='JohnWick', limit=10)
        >>> for log in logs:
        ...     print(f"{log['timestamp']} | {log['action']} | {log['success']}")
        2024-01-15 14:30:00 | login_attempt | True
        2024-01-15 14:25:00 | login_attempt | False
    """
    # Connect to the log database
    conn = get_log_connection()
    cursor = conn.cursor()

    # Build the SQL query dynamically based on which filters are provided
    # Starting with "WHERE 1=1" allows us to easily add AND conditions
    query = 'SELECT * FROM logs WHERE 1=1'
    params = []

    # Add username filter if provided
    if username:
        query += ' AND username = ?'
        params.append(username)

    # Add action filter if provided
    if action:
        query += ' AND action = ?'
        params.append(action)

    # Order by most recent first, and limit the number of results
    # We also order by ID descending to ensure consistent ordering
    # when multiple events have the same timestamp
    query += ' ORDER BY timestamp DESC, id DESC LIMIT ?'
    params.append(limit)

    # Execute the query with our parameters
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    # Process each log entry: decrypt the details and format as a dictionary
    logs = []
    for row in rows:
        log = {
            'id': row[0],
            'timestamp': row[1],
            'username': row[2],
            'action': row[3],
            'details': decrypt_log_details(row[4]),  # Decrypt the encrypted details field
            'ip_address': row[5],
            'success': bool(row[6])  # Convert 0/1 back to True/False
        }
        logs.append(log)

    return logs


def get_failed_login_attempts(username: str, hours: int = 24) -> int:
    """
    Counts the number of failed login attempts for a user in a time window.

    This function is essential for detecting brute force attacks, where an
    attacker tries many passwords in rapid succession. By monitoring failed
    login attempts, the system can:
    1. Lock accounts temporarily after too many failures
    2. Alert security teams to potential attacks
    3. Block IP addresses showing suspicious behavior
    4. Require additional verification (like CAPTCHA or 2FA)

    A typical brute force attack might generate 100+ failed login attempts
    in just a few minutes, making this counter a critical security tool.

    Args:
        username (str): Username to check for failed login attempts
        hours (int): How many hours back to look (default: 24)

    Returns:
        int: Number of failed login attempts in the specified time period

    Example:
        >>> # Simulate 5 failed login attempts
        >>> for i in range(5):
        ...     log_login_attempt('JohnWick', False, {'reason': 'Invalid password'})
        >>> count = get_failed_login_attempts('JohnWick', hours=1)
        >>> print(f"Failed attempts: {count}")
        Failed attempts: 5
    """
    # Connect to the log database
    conn = get_log_connection()
    cursor = conn.cursor()

    # Calculate the cutoff time (how far back to look)
    # For example, if hours=24, we look at events from the last 24 hours
    cutoff = datetime.now() - timedelta(hours=hours)

    # Count login attempts that:
    # 1. Are for the specified username
    # 2. Are login attempt events (not other actions)
    # 3. Failed (success = 0)
    # 4. Occurred after the cutoff time
    cursor.execute('''
        SELECT COUNT(*) FROM logs
        WHERE username = ?
        AND action = 'login_attempt'
        AND success = 0
        AND datetime(timestamp) > datetime(?)
    ''', (username, cutoff.strftime('%Y-%m-%d %H:%M:%S.%f')))

    # Fetch the count (first column of first row)
    count = cursor.fetchone()[0]
    conn.close()

    return count


def log_login_attempt(username: str, success: bool, details: Dict):
    """
    Convenience function for logging login attempts.

    Login attempts are one of the most important events to log because:
    - Failed attempts may indicate a brute force attack
    - Successful attempts create an access trail for auditing
    - Patterns of login times can reveal suspicious activity

    Args:
        username (str): Username attempting to log in
        success (bool): Whether the login succeeded
        details (Dict): Additional details (e.g., {'reason': 'Invalid password', 'ip': '192.168.1.100'})

    Example:
        >>> log_login_attempt('JohnWick', True, {'ip': '192.168.1.100'})
        >>> log_login_attempt('Sofia', False, {'reason': 'Invalid password'})
    """
    # Use the main log_event function with action='login_attempt'
    log_event(username, 'login_attempt', success, details)


def log_registration(username: str, details: Dict):
    """
    Convenience function for logging new user registrations.

    Logging registrations helps track:
    - When new accounts are created
    - What role or permissions they started with
    - Where the registration came from (IP address)
    - Whether there are unusual patterns in account creation

    Args:
        username (str): Username of the newly registered account
        details (Dict): Registration details (e.g., {'role': 'guest', 'ip': '192.168.1.100'})

    Example:
        >>> log_registration('NewUser', {'role': 'guest', 'ip': '192.168.1.100'})
    """
    # Registrations are always logged as successful (success=True)
    # If registration fails, it typically doesn't create a user at all
    log_event(username, 'registration', True, details)


def log_permission_denied(username: str, attempted_action: str, required_role: str):
    """
    Convenience function for logging authorization failures.

    Permission denied events are important because they may indicate:
    - Users trying to access resources above their permission level
    - Compromised accounts being used to probe for vulnerabilities
    - Legitimate users who need additional permissions
    - Privilege escalation attacks

    Args:
        username (str): User who was denied permission
        attempted_action (str): What they tried to do (e.g., '/admin', 'delete_user')
        required_role (str): What role is required (e.g., 'high_table', 'admin')

    Example:
        >>> log_permission_denied('Winston', '/admin', 'high_table')
    """
    # Create a details dictionary with the authorization failure information
    details = {
        'attempted_action': attempted_action,
        'required_role': required_role
    }

    # Permission denied is always logged as unsuccessful (success=False)
    log_event(username, 'permission_denied', False, details)


def log_2fa_attempt(username: str, success: bool, details: Dict):
    """
    Convenience function for logging two-factor authentication attempts.

    Two-factor authentication (2FA) adds an extra layer of security by
    requiring a second form of verification beyond just a password. Logging
    these attempts helps track:
    - Failed 2FA attempts (may indicate stolen passwords)
    - 2FA bypass attempts
    - Users having trouble with their 2FA method

    Args:
        username (str): User attempting 2FA verification
        success (bool): Whether the 2FA verification succeeded
        details (Dict): Additional details (e.g., {'method': 'TOTP', 'reason': 'Invalid code'})

    Example:
        >>> log_2fa_attempt('JohnWick', True, {'method': 'TOTP'})
        >>> log_2fa_attempt('Sofia', False, {'reason': 'Invalid code'})
    """
    # Use the main log_event function with action='2fa_attempt'
    log_event(username, '2fa_attempt', success, details)


def analyze_security_threats(hours: int = 24) -> Dict:
    """
    Analyzes audit logs to identify potential security threats.

    This function looks for suspicious patterns that may indicate:
    - Brute force attacks (many failed login attempts)
    - Permission probing (repeated authorization failures)
    - Account compromise (unusual access patterns)

    Security teams can use this analysis to prioritize their response to
    potential threats and take preventive action before a breach occurs.

    Args:
        hours (int): How many hours back to analyze (default: 24)

    Returns:
        Dict: Security analysis report containing:
            - brute_force_targets: List of usernames with >5 failed logins
            - permission_probes: List of usernames with >3 permission denied events
            - total_failed_logins: Total number of failed login attempts
            - total_permission_denied: Total number of permission denied events

    Example:
        >>> report = analyze_security_threats(hours=24)
        >>> print(f"Brute force targets: {report['brute_force_targets']}")
        Brute force targets: ['JohnWick', 'Winston']

    Note: This function is currently incomplete and returns an empty report.
    Implementation would involve querying logs and counting events by user.
    """
    # This function is incomplete - it would need to:
    # 1. Query all failed login attempts in the time window
    # 2. Count attempts per user and identify those with >5 failures
    # 3. Query all permission denied events in the time window
    # 4. Count permission denials per user and identify those with >3 denials
    # 5. Return a comprehensive security threat report
    pass


def delete_log_database(delete_encryption_key=False):
    """
    Deletes the entire audit log database file.

    WARNING: This permanently deletes ALL audit logs!

    This function should only be used:
    - During testing and development
    - When explicitly needed for database reset
    - Never in production without proper backup and authorization

    Audit logs are often required for compliance and legal reasons, so
    deleting them in production should require multiple levels of approval.

    Args:
        delete_encryption_key (bool): If True, also delete the encryption key file.
                                       Only set to True if you want a complete reset.
                                       WARNING: Old logs will be PERMANENTLY UNREADABLE
                                       if you delete the key!

    Returns:
        bool: True if the database was deleted, False if it didn't exist

    Note about encryption key:
    By default, the encryption key is NOT deleted. This allows you to delete
    logs during testing while keeping the same key for consistency. If you want
    a complete clean slate (new key + empty logs), pass delete_encryption_key=True.
    """
    deleted = False

    # Delete the log database file if it exists
    if os.path.exists(LOG_DB_FILE):
        os.remove(LOG_DB_FILE)
        print(f"✓ Deleted log database: {LOG_DB_FILE}")
        deleted = True

    # Optionally delete the encryption key file
    # This is separate because you usually want to keep the same key
    if delete_encryption_key and os.path.exists(ENCRYPTION_KEY_FILE):
        os.remove(ENCRYPTION_KEY_FILE)
        print(f"✓ Deleted encryption key: {ENCRYPTION_KEY_FILE}")
        print("⚠  WARNING: A new encryption key will be generated on next run.")
        print("   Any remaining encrypted logs from backups will be unreadable.")
        deleted = True

    return deleted

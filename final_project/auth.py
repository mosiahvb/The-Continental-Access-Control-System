"""
The Continental Access Control System - Phase 2
Authentication Module

This module handles secure user authentication including password hashing,
validation, and user registration. It uses bcrypt for cryptographic password
hashing with automatic salt generation.

Security Features:
- Username validation (length, character restrictions, uniqueness)
- Password strength validation
- Bcrypt password hashing with automatic salts
- Secure password verification
"""

import bcrypt
from typing import Tuple
try:
    import database as db
except ImportError:
    from . import database as db


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validates a username according to Continental security standards.

    Performs three security checks:
    1. Length check: Must be between 3-20 characters
    2. Character check: Only alphanumeric characters allowed (no special chars or spaces)
    3. Uniqueness check: Username must not already exist in the system

    Args:
        username: The username to validate

    Returns:
        A tuple of (is_valid, error_message)
        - If valid: (True, "")
        - If invalid: (False, "description of what went wrong")
    """
    # First check: Make sure the username isn't empty
    # An empty username would fail later checks, but we give a clear error here
    if not username:
        return (False, "Username cannot be empty")

    # Second check: Verify the length is within acceptable bounds
    # Too short (< 3) is hard to remember and easy to guess
    # Too long (> 20) can cause display and database issues
    if len(username) < 3 or len(username) > 20:
        return (False, "Username must be 3-20 characters")

    # Third check: Ensure only letters and numbers are used
    # The isalnum() method returns True only if all characters are alphanumeric
    # This prevents special characters, spaces, and symbols that could cause security issues
    if not username.isalnum():
        return (False, "Username must contain only letters and numbers")

    # Fourth check: Verify this username isn't already taken
    # We check the database to prevent duplicate usernames
    # Each user must have a unique identifier in the system
    if db.username_exists(username):
        return (False, f"Username '{username}' is already taken")

    # All validation checks passed - the username is valid
    return (True, "")


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validates a password according to Continental security standards.

    Current requirements:
    - Minimum length of 8 characters (industry standard for basic security)

    Note: Future versions may add additional requirements such as:
    - Uppercase letters
    - Numbers
    - Special characters

    Args:
        password: The password to validate

    Returns:
        A tuple of (is_valid, error_message)
        - If valid: (True, "")
        - If invalid: (False, "description of what went wrong")
    """
    # First check: Make sure a password was actually provided
    # An empty or None password is a security risk
    if not password:
        return (False, "Please enter a password")

    # Second check: Verify minimum length requirement
    # 8 characters is the minimum recommended by security standards
    # Shorter passwords are much easier to crack through brute force attacks
    if len(password) < 8:
        return (False, "Your answer must contain at least 8 characters")

    # Password meets all current requirements
    return (True, "")


def hash_password(password: str) -> str:
    """
    Hashes a password using bcrypt with automatic salt generation.

    This function converts a plain text password into a secure, one-way hash.
    Bcrypt is specifically designed for password hashing and includes:
    - Automatic salt generation (adds random data to prevent rainbow table attacks)
    - Computational cost factor (makes brute force attacks much slower)
    - One-way hashing (cannot be reversed to get the original password)

    Security concept: A "salt" is random data added to the password before hashing.
    This means even if two users have the same password, their hashes will be different.
    This prevents attackers from using pre-computed hash tables (rainbow tables).

    Args:
        password: The plain text password to hash

    Returns:
        A bcrypt hash string that can be safely stored in the database
    """
    # Step 1: Convert the string password to bytes
    # Bcrypt operates on byte data, not text strings
    # UTF-8 encoding is used as it's the standard for text encoding
    password_bytes = password.encode('utf-8')

    # Step 2: Generate a random salt
    # The salt is automatically included in the final hash output
    # Each call to gensalt() produces a unique salt, making each hash unique
    salt = bcrypt.gensalt()

    # Step 3: Hash the password with the salt
    # This combines the password and salt, then applies the bcrypt hashing algorithm
    # The result includes both the salt and hash, so we can verify passwords later
    hashed = bcrypt.hashpw(password_bytes, salt)

    # Step 4: Convert the hashed bytes back to a string for storage
    # We decode back to UTF-8 so it can be easily stored in our database
    return hashed.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verifies that a plain text password matches a stored bcrypt hash.

    This function is used during login to check if the password a user enters
    matches the hashed password we have stored in the database.

    Bcrypt's checkpw function extracts the salt from the stored hash,
    applies it to the provided password, and compares the results.
    This way we never need to store or compare plain text passwords.

    Args:
        password: The plain text password to verify (from user login attempt)
        password_hash: The bcrypt hash to check against (from database)

    Returns:
        True if the password matches the hash, False otherwise
    """
    # Convert both the password and stored hash to bytes for bcrypt
    password_bytes = password.encode('utf-8')
    hash_bytes = password_hash.encode('utf-8')

    # Use bcrypt's checkpw to securely compare
    # This extracts the salt from the hash and recomputes the hash to compare
    return bcrypt.checkpw(password_bytes, hash_bytes)


def register_user(username: str, password: str) -> Tuple[bool, str]:
    """
    Registers a new user in The Continental system.

    This is the main entry point for user registration. It orchestrates the
    complete registration process: validation, hashing, and storage.

    Process flow:
    1. Validate username (length, characters, uniqueness)
    2. Validate password (strength requirements)
    3. Hash the password (never store plain text passwords)
    4. Store user in database with default "guest" role
    5. Return success or error message

    Args:
        username: The desired username (will be validated)
        password: The desired password in plain text (will be hashed before storage)

    Returns:
        A tuple of (success, message)
        - If successful: (True, "User 'username' registered successfully!")
        - If failed: (False, "specific error message explaining what went wrong")
    """
    # Step 1: Validate the username meets all requirements
    # If validation fails, we return immediately with the error message
    # No need to continue if the username isn't acceptable
    is_valid, error_msg = validate_username(username)
    if not is_valid:
        return (False, error_msg)

    # Step 2: Validate the password meets security requirements
    # Again, if validation fails, return immediately
    # We don't want to proceed with a weak password
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return (False, error_msg)

    # Step 3: Hash the password using bcrypt
    # CRITICAL: We never store plain text passwords
    # The hash is what gets saved to the database
    password_hash = hash_password(password)

    # Step 4: Add the user to the database
    # We store the username, the hashed password, and assign default "guest" role
    # The database will also automatically record the creation timestamp
    success = db.add_user(username, password_hash, role="guest")

    # Step 5: Return appropriate success or failure message
    # If database insertion succeeded, welcome the new user
    # If it failed (rare, but could happen), let them know
    if success:
        return (True, f"User '{username}' registered successfully!")
    else:
        return (False, "Failed to register user")

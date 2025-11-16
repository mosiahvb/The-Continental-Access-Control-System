"""
The Continental Access Control System - Phase 3
Login & Authentication Module

This module handles user login and password verification.
It uses the database and auth modules from Phase 2.
"""

import bcrypt
from typing import Tuple, Optional, Dict
try:
    import database as db
    import auth
except ImportError:
    from . import database as db
    from . import auth


def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[Dict], str]:
    """
    Authenticates a user by verifying their username and password.

    Args:
        username (str): The username attempting to login
        password (str): The password to verify

    Returns:
        Tuple[bool, Optional[Dict], str]: A tuple containing:
            - success (bool): True if login successful, False otherwise
            - user_data (Dict or None): User information if successful, None if failed
            - message (str): Success or error message

    Security Note:
        Returns the same error message for both "user not found" and "wrong password"
        to prevent attackers from discovering which usernames exist in the system.
    """

    # Step 1: Look up the user in the database
    # This checks if a user with this username exists in our system
    user = db.get_user(username)

    # Step 2: If the user doesn't exist, return a generic error message
    # We use a generic message instead of "user not found" for security
    # This prevents hackers from discovering valid usernames by trying different names
    if not user:
        return (False, None, "Invalid username or password")

    # Step 3: If the user exists, verify their password
    # The verify_password function uses bcrypt to securely compare passwords
    # It checks if the plain text password matches the stored hashed version
    if auth.verify_password(password, user['password_hash']):
        # Password is correct - return success with the user's information
        return (True, user, "Login successful!")

    # Step 4: If the password is wrong, return the same generic error message
    # Notice we use the exact same message as when the user doesn't exist
    # This makes it impossible for attackers to tell the difference
    return (False, None, "Invalid username or password")


def authenticate_user_secure(username: str, password: str) -> Tuple[bool, Optional[Dict], str]:
    """
    Authenticates a user with protection against timing attacks.

    This is an advanced version of authenticate_user that takes the same amount of
    time whether the user exists or not. This prevents timing attacks, where hackers
    measure how long the server takes to respond to discover valid usernames.

    Args:
        username (str): The username attempting to login
        password (str): The password to verify

    Returns:
        Tuple[bool, Optional[Dict], str]: Same as authenticate_user

    How Timing Attacks Work:
        - If a username doesn't exist, the response is instant (no password to check)
        - If a username exists, the response takes longer (password hashing takes time)
        - Hackers can measure this difference to discover valid usernames

    How This Function Prevents Timing Attacks:
        - Even when a user doesn't exist, we still perform a password check
        - We use a fake password and fake hash, which takes the same time as a real check
        - Now all failed logins take the same amount of time, hiding which usernames exist
    """

    # Step 1: Look up the user in the database
    user = db.get_user(username)

    # Step 2: If the user doesn't exist, perform a fake password check
    # This is the key to preventing timing attacks!
    # We're doing "busy work" - checking a fake password against a fake hash
    # This wastes the same amount of time as checking a real password
    # Now the response time is the same whether the user exists or not
    if not user:
        # Perform a fake password check to maintain consistent timing
        # This takes approximately the same time as a real password verification
        bcrypt.checkpw(b"fake_password", bcrypt.gensalt())
        # Return the same generic error message
        return (False, None, "Invalid username or password")

    # Step 3: If the user exists, verify their password normally
    # This uses bcrypt to securely compare the provided password with the stored hash
    if auth.verify_password(password, user['password_hash']):
        # Password is correct - return success with the user's information
        return (True, user, "Login successful!")

    # Step 4: If the password is wrong, return the generic error message
    # The timing is already consistent because we did a real password check
    return (False, None, "Invalid username or password")

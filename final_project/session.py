"""
The Continental Access Control System - JWT Token Management

This module handles JWT (JSON Web Token) authentication for The Continental Hotel system.
JWT tokens work like digital ID cards - they prove who you are without needing to show
your password every time. Each token is signed with a secret key to prevent tampering.
"""

import jwt
import datetime
from typing import Optional, Dict, Tuple
try:
    import database as db
    import login as auth
except ImportError:
    from . import database as db
    from . import login as auth

# Configuration constants for JWT token security
# SECRET_KEY: Used to sign tokens (like a seal on an official document)
#             In production, this should be stored in environment variables, not in code!
# ALGORITHM: The encryption method used to sign tokens (HS256 is HMAC with SHA-256)
# ACCESS_TOKEN_EXPIRE_MINUTES: How long a token stays valid before the user must log in again
SECRET_KEY = "continental_hotel_secret_key_change_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(user: Dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    """
    Creates a JWT access token for an authenticated user.

    A JWT token is like a digital ID card that proves the user is authenticated.
    It contains the user's information (username, role) and an expiration time.
    The token is cryptographically signed to prevent tampering.

    Args:
        user: Dictionary containing 'username' and 'role' keys
        expires_delta: Optional custom expiration time. If None, uses default (30 minutes)

    Returns:
        A signed JWT token as a string (format: header.payload.signature)
    """
    # Get current time in UTC (coordinated universal time - the global time standard)
    now = datetime.datetime.now(datetime.timezone.utc)

    # Calculate when this token should expire
    # If a custom expiration time was provided, use it
    # Otherwise, use our default expiration time (30 minutes)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Create the payload (the data we're encoding into the token)
    # Think of this as the information printed on an ID card
    payload = {
        'username': user['username'],  # Who this token belongs to
        'role': user['role'],          # What permissions they have (guest, concierge, etc.)
        'exp': expire,                 # Expiration time - when this token becomes invalid
        'iat': now                     # Issued at time - when this token was created
    }

    # Encode the payload into a JWT token using our secret key
    # This creates three parts: header.payload.signature
    # The signature ensures nobody can modify the token without being detected
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return token


def decode_token(token: str) -> Optional[Dict]:
    """
    Decodes and verifies a JWT token.

    This function checks if a token is valid by verifying:
    1. The signature matches (proves the token wasn't tampered with)
    2. The token hasn't expired (checks the 'exp' field)

    Args:
        token: The JWT token string to decode

    Returns:
        The decoded payload (user data) if token is valid, None if invalid or expired
    """
    try:
        # Attempt to decode the token using our secret key
        # jwt.decode automatically:
        # - Verifies the signature (checks if token was tampered with)
        # - Checks expiration (looks at the 'exp' field)
        # - Validates the token structure
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except jwt.ExpiredSignatureError:
        # This happens when the token's expiration time has passed
        # Like trying to use an expired ID card
        print("Token expired!")
        return None

    except jwt.InvalidTokenError:
        # This catches all other JWT errors:
        # - Token was tampered with (signature doesn't match)
        # - Token format is wrong
        # - Token is malformed or corrupted
        print("Invalid token!")
        return None


def verify_token(token: str) -> Tuple[bool, Optional[Dict], str]:
    """
    Verifies a token and returns detailed information about the result.

    This is a user-friendly wrapper around decode_token that provides
    clear feedback about why a token is valid or invalid.

    Args:
        token: The JWT token string to verify

    Returns:
        A tuple containing:
        - is_valid (bool): True if token is valid, False otherwise
        - user_data (dict or None): User info (username, role) if valid, None if invalid
        - message (str): Clear explanation of the result
    """
    try:
        # Try to decode and verify the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Extract just the user information we need
        # We don't need to return the exp and iat timestamps to the user
        user_data = {
            'username': payload['username'],
            'role': payload['role']
        }

        # Token is valid - return success
        return (True, user_data, "Token is valid")

    except jwt.ExpiredSignatureError:
        # Token has expired - user needs to log in again
        return (False, None, "Token has expired. Please log in again.")

    except jwt.InvalidTokenError:
        # Token is invalid for some other reason (tampered, malformed, etc.)
        return (False, None, "Invalid token. Please log in again.")


def refresh_access_token(old_token: str) -> Optional[str]:
    """
    Creates a new token from an expired or expiring token.

    This is like renewing an ID card. We verify the old token's signature
    (ignoring expiration) and issue a fresh token with the same information
    but a new expiration time.

    Args:
        old_token: The expired or expiring JWT token

    Returns:
        A new JWT token if refresh is successful, None if refresh fails
    """
    try:
        # Decode the token but skip expiration checking
        # This allows us to read expired tokens (useful for refresh)
        # We still verify the signature to prevent tampering
        payload = jwt.decode(
            old_token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": False}  # Ignore expiration for refresh
        )

        # Verify the user still exists in the database
        # This prevents refreshing tokens for deleted users
        user = db.get_user(payload['username'])
        if not user:
            # User no longer exists - cannot refresh
            return None

        # Create and return a new token with fresh expiration time
        return create_access_token(user)

    except jwt.InvalidTokenError:
        # Token is invalid (tampered, malformed, etc.)
        # We can't refresh an invalid token
        return None

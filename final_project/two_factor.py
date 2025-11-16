"""
The Continental Access Control System
Two-Factor Authentication Module

This module implements Time-based One-Time Password (TOTP) authentication,
adding an extra layer of security beyond just username and password.
It works with authenticator apps like Google Authenticator or Authy.
"""

import pyotp
import qrcode
from typing import Optional, Dict, Tuple
import sqlite3
try:
    import database as db
    import login as auth
except ImportError:
    from . import database as db
    from . import login as auth


def generate_2fa_secret() -> str:
    """
    Generates a random secret key for two-factor authentication.

    This secret is like a shared password between the server and the user's
    authenticator app. Both sides use it to generate matching 6-digit codes
    that change every 30 seconds.

    Returns:
        str: A Base32-encoded secret key (example: "JBSWY3DPEHPK3PXP")
             Base32 uses only uppercase letters A-Z and numbers 2-7 to avoid
             confusing characters like 0/O or 1/I/l
    """
    # Generate a random Base32-encoded secret that works with all major authenticator apps
    secret = pyotp.random_base32()
    return secret


def get_totp_uri(username: str, secret: str, issuer: str = "Continental") -> str:
    """
    Creates a special URI that contains all the information needed for setup.

    This URI gets encoded into a QR code. When a user scans the QR code with
    their authenticator app, the app extracts the secret, username, and service
    name from this URI.

    Args:
        username: The user's username for display in the authenticator app
        secret: The Base32 secret key that was generated
        issuer: The service name that appears in the authenticator app

    Returns:
        str: A URI in format "otpauth://totp/Continental:username?secret=XXX&issuer=Continental"
             This follows the standard TOTP URI format that all authenticator apps understand
    """
    # Create a TOTP object using the secret
    totp = pyotp.TOTP(secret)

    # Generate the provisioning URI that will be embedded in the QR code
    # The "name" is what the user sees, and "issuer_name" groups accounts together
    uri = totp.provisioning_uri(
        name=username,
        issuer_name=issuer
    )

    return uri


def generate_qr_code(uri: str, filename: Optional[str] = None) -> str:
    """
    Generates a scannable QR code image from a TOTP URI.

    QR codes make setup easy - users just scan the code instead of manually
    typing a long secret key into their authenticator app.

    Args:
        uri: The TOTP URI containing all setup information
        filename: Optional filename for saving the QR code image
                  If not provided, defaults to "qr_code.png"

    Returns:
        str: The filepath where the QR code image was saved
    """
    # Use default filename if none was provided
    if filename is None:
        filename = "qr_code.png"

    # Generate the QR code image from the URI
    qr = qrcode.make(uri)

    # Save the image to a file so it can be displayed to the user
    qr.save(filename)

    return filename


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verifies that a 6-digit code matches the expected code for the current time.

    This is the core of TOTP security. The server generates what the code SHOULD
    be based on the current time and the shared secret, then checks if the user's
    code matches. Codes change every 30 seconds, so old codes won't work.

    Args:
        secret: The user's Base32 secret key
        code: The 6-digit code the user entered from their authenticator app

    Returns:
        bool: True if the code is valid for the current 30-second time window
              The verification also accepts codes from one window before or after
              to account for small time differences between devices
    """
    # Create a TOTP object with the user's secret
    totp = pyotp.TOTP(secret)

    # Verify the code against the current time
    # This returns True if the code matches the current 30-second window
    # or the windows immediately before/after (to handle clock drift)
    is_valid = totp.verify(code)

    return is_valid


def enable_2fa_for_user(username: str) -> Tuple[bool, str, str]:
    """
    Sets up two-factor authentication for a user account.

    This function performs the complete 2FA setup process:
    1. Generates a unique secret for the user
    2. Creates a TOTP URI with the secret and username
    3. Generates a QR code image the user can scan
    4. Saves the secret to the database for future verification

    Args:
        username: The username to enable 2FA for

    Returns:
        Tuple containing three values:
            - bool: Success status (True if 2FA was enabled, False if user not found)
            - str: The secret key (display this as a backup if user can't scan QR)
            - str: Path to the QR code image file or error message
    """
    # First verify that the user exists in the database
    user = db.get_user(username)
    if not user:
        return (False, "", "User not found")

    # Step 1: Generate a new random secret for this user
    secret = generate_2fa_secret()

    # Step 2: Create the TOTP URI that contains the secret and username
    uri = get_totp_uri(username, secret)

    # Step 3: Generate a QR code image with a descriptive filename
    qr_filename = f"{username}_2fa_qr.png"
    qr_path = generate_qr_code(uri, qr_filename)

    # Step 4: Save the secret to the database so we can verify codes later
    update_user_totp_secret(username, secret)

    # Return success with the secret and QR code path
    return (True, secret, qr_path)


def update_user_totp_secret(username: str, secret: str) -> bool:
    """
    Stores a user's TOTP secret in the database.

    The secret needs to be saved so that future login attempts can verify
    the codes generated by the user's authenticator app.

    Args:
        username: The username to update
        secret: The TOTP secret to store

    Returns:
        bool: True if the update was successful
    """
    # Connect to the database
    conn = db.get_connection()
    cursor = conn.cursor()

    # Update the user's record to store their TOTP secret
    cursor.execute(
        'UPDATE users SET totp_secret = ? WHERE username = ?',
        (secret, username)
    )

    # Save the changes and close the connection
    conn.commit()
    conn.close()

    return True


def login_with_2fa(username: str, password: str, totp_code: str) -> Tuple[bool, Optional[Dict], str]:
    """
    Authenticates a user with both password and two-factor code.

    This implements true two-factor authentication by requiring:
    - Factor 1: Something you KNOW (password)
    - Factor 2: Something you HAVE (phone with authenticator app)

    Both factors must be correct for login to succeed. This makes accounts
    much more secure - even if someone steals your password, they can't
    log in without your phone.

    Args:
        username: The user's username
        password: The user's password
        totp_code: The current 6-digit code from their authenticator app

    Returns:
        Tuple containing three values:
            - bool: Success status (True only if BOTH password and 2FA are correct)
            - Dict or None: User data if successful, None otherwise
            - str: Human-readable message explaining the result
    """
    # First factor: Verify the username and password
    # If the password is wrong, stop immediately and don't check 2FA
    success, user, message = auth.authenticate_user(username, password)
    if not success:
        return (False, None, message)

    # Check if this user has 2FA enabled by looking for their secret
    totp_secret = user.get('totp_secret')

    # If no 2FA is set up, allow login with just password (backward compatible)
    if not totp_secret:
        return (True, user, "Login successful (no 2FA)")

    # Second factor: Verify the TOTP code from their authenticator app
    # The code must match the current time-based code
    is_valid = verify_totp_code(totp_secret, totp_code)

    # If the 2FA code is wrong, reject the login even though password was correct
    if not is_valid:
        return (False, None, "Invalid 2FA code. Please try again.")

    # Both factors verified successfully!
    return (True, user, "Login successful with 2FA")


def disable_2fa_for_user(username: str) -> bool:
    """
    Disables two-factor authentication for a user account.

    This removes the TOTP secret from the database, turning off 2FA.
    The user will only need their password to log in after this.

    Args:
        username: The username to disable 2FA for

    Returns:
        bool: True if 2FA was disabled successfully
    """
    # Connect to the database
    conn = db.get_connection()
    cursor = conn.cursor()

    # Remove the TOTP secret by setting it to NULL
    cursor.execute(
        'UPDATE users SET totp_secret = NULL WHERE username = ?',
        (username,)
    )

    # Save the changes and close the connection
    conn.commit()
    conn.close()

    return True


def add_2fa_column_to_database():
    """
    Database migration helper that adds the totp_secret column to existing databases.

    This function safely adds the new column needed for 2FA support. If you're
    adding 2FA to an existing system, run this once to update the database schema.
    It's safe to run multiple times - it won't cause errors if the column already exists.

    Returns:
        bool: True if the column was added successfully or already exists
    """
    try:
        # Connect to the database
        conn = db.get_connection()
        cursor = conn.cursor()

        # Try to add the totp_secret column to the users table
        # This column will store each user's TOTP secret key
        cursor.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')

        # Save the changes
        conn.commit()
        conn.close()

        print("✓ Added totp_secret column to users table")
        return True

    except sqlite3.OperationalError as e:
        # If the column already exists, that's fine - we just want to make sure it's there
        if "duplicate column name" in str(e).lower():
            print("✓ totp_secret column already exists")
            return True
        else:
            # Some other database error occurred
            print(f"✗ Error adding column: {e}")
            return False

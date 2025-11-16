"""
Phase 5 Tests - The Continental Access Control System
Tests for JWT Token Management (Gold Coins)

Run these tests with: pytest test_phase5.py -v

These tests verify that:
- JWT tokens are created with correct structure
- Tokens include required claims (username, role, exp, iat)
- Tokens can be decoded and verified
- Expired tokens are rejected
- Invalid/tampered tokens are rejected
- No sensitive data (passwords) in tokens
- Token expiration is enforced
"""

import pytest
import jwt
import datetime
import time
import sys
import os

# Add previous phase directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase_2_registration'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase_3_login'))

import database as db
import auth
import session
from session import create_access_token, decode_token, verify_token, SECRET_KEY, ALGORITHM


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """
    This runs before and after EACH test.
    Sets up a fresh database with test users.
    """
    # BEFORE TEST: Setup
    db.delete_database()
    db.init_database()

    # Create test users with specific roles
    # Note: auth.register_user() only accepts username and password (role defaults to 'guest')
    # So we need to use db.add_user() directly with hashed passwords for custom roles

    # Register JohnWick as guest
    password_hash_john = auth.hash_password('BabaYaga2023')
    db.add_user('JohnWick', password_hash_john, role='guest')

    # Register Winston as high_table member
    password_hash_winston = auth.hash_password('Continental123')
    db.add_user('Winston', password_hash_winston, role='high_table')

    yield  # This is where the test runs

    # AFTER TEST: Cleanup
    db.delete_database()


class TestTokenCreation:
    """Tests for creating JWT tokens"""

    def test_create_token_returns_string(self):
        """Test that create_access_token returns a string"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        assert isinstance(token, str), "Token should be a string"
        assert len(token) > 0, "Token should not be empty"
        print("✓ Token is a non-empty string")

    def test_token_has_three_parts(self):
        """Test that JWT has three parts: header.payload.signature"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        parts = token.split('.')
        assert len(parts) == 3, \
            f"JWT should have 3 parts (header.payload.signature), got {len(parts)}"
        print("✓ Token has 3 parts: header.payload.signature")

    def test_token_can_be_decoded(self):
        """Test that token can be decoded back to payload"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        assert payload is not None, "Should be able to decode token"
        assert isinstance(payload, dict), "Decoded payload should be a dictionary"
        print("✓ Token can be decoded")

    def test_token_includes_username(self):
        """Test that token includes username in payload"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        assert 'username' in payload, "Token payload should include 'username'"
        assert payload['username'] == 'JohnWick', "Username in token should match user"
        print("✓ Token includes username")

    def test_token_includes_role(self):
        """Test that token includes role in payload"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        assert 'role' in payload, "Token payload should include 'role'"
        assert payload['role'] == 'guest', "Role in token should match user"
        print("✓ Token includes role")

    def test_token_includes_expiration(self):
        """Test that token includes expiration time"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        assert 'exp' in payload, "Token payload should include 'exp' (expiration)"
        assert isinstance(payload['exp'], int), "Expiration should be a timestamp (int)"

        # Check that expiration is in the future
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        assert payload['exp'] > now, "Expiration should be in the future"

        print("✓ Token includes expiration (exp)")

    def test_token_includes_issued_at(self):
        """Test that token includes issued-at time"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        assert 'iat' in payload, "Token payload should include 'iat' (issued at)"
        assert isinstance(payload['iat'], int), "Issued-at should be a timestamp (int)"

        # Check that issued-at is recent (within last minute)
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        assert abs(now - payload['iat']) < 60, "Issued-at should be recent"

        print("✓ Token includes issued-at (iat)")

    def test_token_expiration_is_30_minutes(self):
        """Test that default token expiration is 30 minutes"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Calculate time difference
        exp_time = payload['exp']
        iat_time = payload['iat']
        duration_seconds = exp_time - iat_time

        # Should be approximately 30 minutes (1800 seconds)
        # Allow small variance for processing time
        assert 1790 <= duration_seconds <= 1810, \
            f"Token should expire in ~30 minutes (1800s), got {duration_seconds}s"

        print("✓ Token expires in 30 minutes")

    def test_custom_expiration_time(self):
        """Test that custom expiration time can be set"""
        user = {'username': 'JohnWick', 'role': 'guest'}

        # Create token with 1-hour expiration
        custom_delta = datetime.timedelta(hours=1)
        token = create_access_token(user, expires_delta=custom_delta)

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Calculate time difference
        exp_time = payload['exp']
        iat_time = payload['iat']
        duration_seconds = exp_time - iat_time

        # Should be approximately 1 hour (3600 seconds)
        assert 3590 <= duration_seconds <= 3610, \
            f"Token should expire in ~1 hour (3600s), got {duration_seconds}s"

        print("✓ Custom expiration time works")

    def test_different_users_get_different_tokens(self):
        """Test that different users get different tokens"""
        user1 = {'username': 'JohnWick', 'role': 'guest'}
        user2 = {'username': 'Winston', 'role': 'high_table'}

        token1 = create_access_token(user1)
        token2 = create_access_token(user2)

        assert token1 != token2, "Different users should get different tokens"

        payload1 = jwt.decode(token1, SECRET_KEY, algorithms=[ALGORITHM])
        payload2 = jwt.decode(token2, SECRET_KEY, algorithms=[ALGORITHM])

        assert payload1['username'] != payload2['username'], "Tokens should have different usernames"
        assert payload1['role'] != payload2['role'], "Tokens should have different roles"

        print("✓ Different users get different tokens")


class TestTokenDecoding:
    """Tests for decoding JWT tokens"""

    def test_decode_valid_token(self):
        """Test decoding a valid token"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        payload = decode_token(token)

        assert payload is not None, "Should successfully decode valid token"
        assert payload['username'] == 'JohnWick', "Should decode correct username"
        assert payload['role'] == 'guest', "Should decode correct role"
        print("✓ Valid token decodes successfully")

    def test_decode_expired_token(self):
        """Test that expired tokens are rejected"""
        user = {'username': 'JohnWick', 'role': 'guest'}

        # Create token that expires in 1 second
        token = create_access_token(user, expires_delta=datetime.timedelta(seconds=1))

        # Wait for token to expire
        time.sleep(2)

        # Try to decode expired token
        payload = decode_token(token)

        assert payload is None, "Expired token should return None"
        print("✓ Expired token is rejected")

    def test_decode_invalid_token(self):
        """Test that invalid tokens are rejected"""
        invalid_token = "this.is.not.a.valid.jwt.token"

        payload = decode_token(invalid_token)

        assert payload is None, "Invalid token should return None"
        print("✓ Invalid token is rejected")

    def test_decode_tampered_token(self):
        """Test that tampered tokens are rejected (signature verification)"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        # Tamper with the token (change payload)
        parts = token.split('.')
        # Modify the payload part (middle part)
        tampered_token = parts[0] + '.TAMPERED_PAYLOAD.' + parts[2]

        payload = decode_token(tampered_token)

        assert payload is None, \
            "Tampered token should be rejected (signature won't match)"
        print("✓ Tampered token is rejected (signature verification works)")

    def test_decode_empty_string(self):
        """Test handling of empty token string"""
        payload = decode_token("")

        assert payload is None, "Empty string should return None"
        print("✓ Empty token is rejected")


class TestTokenVerification:
    """Tests for verify_token function"""

    def test_verify_valid_token(self):
        """Test verifying a valid token"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        is_valid, user_data, message = verify_token(token)

        assert is_valid == True, "Valid token should pass verification"
        assert user_data is not None, "Should return user data"
        assert user_data['username'] == 'JohnWick', "Should return correct username"
        assert user_data['role'] == 'guest', "Should return correct role"
        assert len(message) > 0, "Should return a message"
        print("✓ Valid token passes verification")

    def test_verify_expired_token(self):
        """Test verifying an expired token"""
        user = {'username': 'JohnWick', 'role': 'guest'}

        # Create token that expires immediately
        token = create_access_token(user, expires_delta=datetime.timedelta(seconds=1))

        # Wait for expiration
        time.sleep(2)

        is_valid, user_data, message = verify_token(token)

        assert is_valid == False, "Expired token should fail verification"
        assert user_data is None, "Should not return user data for expired token"
        assert "expire" in message.lower(), \
            f"Message should mention expiration, got: '{message}'"
        print("✓ Expired token fails verification with helpful message")

    def test_verify_invalid_token(self):
        """Test verifying an invalid token"""
        invalid_token = "not.a.valid.token"

        is_valid, user_data, message = verify_token(invalid_token)

        assert is_valid == False, "Invalid token should fail verification"
        assert user_data is None, "Should not return user data for invalid token"
        assert len(message) > 0, "Should return error message"
        print("✓ Invalid token fails verification with helpful message")

    def test_verify_returns_correct_structure(self):
        """Test that verify_token returns correct tuple structure"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        result = verify_token(token)

        assert isinstance(result, tuple), "Should return a tuple"
        assert len(result) == 3, "Should return 3-element tuple: (is_valid, user_data, message)"

        is_valid, user_data, message = result

        assert isinstance(is_valid, bool), "First element should be boolean"
        assert isinstance(user_data, dict) or user_data is None, \
            "Second element should be dict or None"
        assert isinstance(message, str), "Third element should be string"

        print("✓ verify_token returns correct structure")


class TestTokenSecurity:
    """Security-focused tests"""

    def test_token_does_not_contain_password(self):
        """CRITICAL: Test that token doesn't include password or password_hash"""
        user = db.get_user('JohnWick')
        token = create_access_token(user)

        # Decode without verification to inspect payload
        payload = jwt.decode(token, options={"verify_signature": False})

        assert 'password' not in payload, \
            "Token should NOT contain 'password' field!"
        assert 'password_hash' not in payload, \
            "Token should NOT contain 'password_hash' field!"

        # Also check the raw token string (base64 decoded payload)
        parts = token.split('.')
        if len(parts) >= 2:
            # Base64 decode the payload (add padding if needed)
            import base64
            payload_part = parts[1]
            # Add padding
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding

            try:
                decoded_payload = base64.urlsafe_b64decode(payload_part).decode('utf-8')
                assert 'password' not in decoded_payload.lower(), \
                    "Token payload should not contain password!"
            except:
                pass  # If decode fails, that's okay

        print("✓ SECURITY: Token does not contain password")

    def test_signature_prevents_tampering(self):
        """Test that signature verification prevents payload tampering"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        # Try to decode and modify the payload
        parts = token.split('.')

        if len(parts) == 3:
            # Try to create token with modified role
            import base64
            import json

            # Decode payload
            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding

            payload_bytes = base64.urlsafe_b64decode(payload_part)
            payload = json.loads(payload_bytes)

            # Modify role to high_table (privilege escalation attempt!)
            payload['role'] = 'high_table'

            # Re-encode
            modified_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')

            # Create tampered token
            tampered_token = f"{parts[0]}.{modified_payload}.{parts[2]}"

            # Try to verify tampered token
            is_valid, user_data, message = verify_token(tampered_token)

            assert is_valid == False, \
                "Tampered token should be rejected! Signature verification failed!"

        print("✓ SECURITY: Signature prevents payload tampering")

    def test_secret_key_is_required(self):
        """Test that token can't be decoded without secret key"""
        user = {'username': 'JohnWick', 'role': 'guest'}
        token = create_access_token(user)

        # Try to decode with wrong secret key
        try:
            jwt.decode(token, "wrong_secret_key", algorithms=[ALGORITHM])
            assert False, "Should not be able to decode with wrong secret key"
        except jwt.InvalidTokenError:
            pass  # Expected

        print("✓ SECURITY: Token requires correct secret key")

    def test_token_expiration_is_enforced(self):
        """Test that expired tokens are actually rejected"""
        user = {'username': 'JohnWick', 'role': 'guest'}

        # Create token that's already expired (negative time)
        expired_token = create_access_token(
            user,
            expires_delta=datetime.timedelta(seconds=-1)
        )

        # Should not be able to use expired token
        is_valid, user_data, message = verify_token(expired_token)

        assert is_valid == False, \
            "Expired token should be rejected immediately"

        print("✓ SECURITY: Token expiration is enforced")

    def test_tokens_are_unique(self):
        """Test that each token creation generates unique token"""
        user = {'username': 'JohnWick', 'role': 'guest'}

        token1 = create_access_token(user)
        time.sleep(1.1)  # Small delay (must be >1s since JWT timestamps have second precision)
        token2 = create_access_token(user)

        assert token1 != token2, \
            "Tokens should be unique (different iat times)"

        print("✓ Each token is unique")


class TestIntegrationWithPreviousPhases:
    """Integration tests with login and authentication"""

    def test_token_after_successful_login(self):
        """Test creating token after user login"""
        import login

        # User logs in
        success, user, message = login.authenticate_user('JohnWick', 'BabaYaga2023')

        assert success == True, "Login should succeed"

        # Create token for logged-in user
        token = create_access_token(user)

        assert token is not None, "Should create token after login"

        # Verify token
        is_valid, user_data, msg = verify_token(token)

        assert is_valid == True, "Token should be valid"
        assert user_data['username'] == 'JohnWick', "Token should have correct username"

        print("✓ Token creation after login works")

    def test_token_preserves_role_from_database(self):
        """Test that token includes role from database"""
        user = db.get_user('Winston')

        assert user['role'] == 'high_table', "Winston should be high_table"

        # Create token
        token = create_access_token(user)
        payload = decode_token(token)

        assert payload['role'] == 'high_table', \
            "Token should preserve user's role from database"

        print("✓ Token preserves user role from database")

    def test_complete_authentication_flow(self):
        """Test complete flow: login → create token → verify token → use token"""
        import login

        # Step 1: User logs in
        success, user, message = login.authenticate_user('JohnWick', 'BabaYaga2023')
        assert success == True

        # Step 2: Create token
        token = create_access_token(user)
        assert token is not None

        # Step 3: Verify token
        is_valid, user_data, msg = verify_token(token)
        assert is_valid == True
        assert user_data['username'] == 'JohnWick'

        # Step 4: Use token for authenticated request (simulation)
        # In real app, user would send this token with each request
        # Server would verify token and know who's making the request

        print("✓ Complete authentication flow works")


class TestEdgeCases:
    """Tests for edge cases and error conditions"""

    def test_token_with_missing_claims(self):
        """Test handling of token with missing required claims"""
        # Create token manually without required claims
        payload = {'username': 'JohnWick'}  # Missing role, exp, iat

        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        # decode_token should still work (JWT is valid)
        decoded = decode_token(token)

        # But payload might be missing expected fields
        assert decoded is not None, "Technically valid JWT should decode"

        print("✓ Handles tokens with missing claims")

    def test_very_long_expiration(self):
        """Test token with very long expiration"""
        user = {'username': 'JohnWick', 'role': 'guest'}

        # Create token that expires in 10 years
        long_delta = datetime.timedelta(days=3650)
        token = create_access_token(user, expires_delta=long_delta)

        is_valid, user_data, message = verify_token(token)

        assert is_valid == True, "Long-lived token should still be valid"

        print("✓ Handles very long expiration times")

    def test_token_with_special_characters_in_username(self):
        """Test token with special characters in username"""
        user = {'username': 'John.Wick-123', 'role': 'guest'}

        token = create_access_token(user)
        payload = decode_token(token)

        assert payload['username'] == 'John.Wick-123', \
            "Should handle special characters in username"

        print("✓ Handles special characters in username")


class TestTokenRefresh:
    """BONUS tests for refresh token functionality"""

    def test_refresh_token_exists(self):
        """Test that refresh_access_token function exists"""
        assert hasattr(session, 'refresh_access_token'), \
            "BONUS: refresh_access_token function should exist"

        print("✓ BONUS: refresh_access_token function exists")


if __name__ == "__main__":
    """
    Run tests with color output and verbose mode
    """
    pytest.main([__file__, "-v", "--color=yes", "--tb=short"])

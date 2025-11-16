"""
Phase 3 Tests - The Continental Access Control System
Tests for User Login & Authentication

Run these tests with: pytest test_phase3.py -v

These tests verify that:
- Users can login with correct credentials
- Wrong passwords are rejected
- Non-existent users are rejected
- Error messages don't leak information
- Password verification uses bcrypt
"""

import pytest
import sys
import os

# Add Phase 2 to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase_2_registration'))

import database as db
import auth
import final_project.login as login


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """
    This runs before and after EACH test.
    It ensures we start with a fresh database with test users.
    """
    # BEFORE TEST: Create fresh database with test users
    db.delete_database()
    db.init_database()

    # Register test users
    auth.register_user("JohnWick", "BabaYaga2023")
    auth.register_user("Winston", "Continental123")
    auth.register_user("Marcus", "Sniper999")

    yield  # This is where the test runs

    # AFTER TEST: Clean up
    db.delete_database()


class TestBasicAuthentication:
    """Tests for basic login functionality"""

    def test_successful_login(self):
        """Test that correct credentials allow login"""
        success, user, message = login.authenticate_user("JohnWick", "BabaYaga2023")

        assert success == True, "Login with correct credentials should succeed"
        assert user is not None, "User data should be returned on successful login"
        assert user['username'] == "JohnWick", "Returned user should match login username"
        assert "success" in message.lower() or "welcome" in message.lower(), \
            "Success message should indicate successful login"
        print("✓ Successful login works")

    def test_wrong_password(self):
        """Test that wrong password is rejected"""
        success, user, message = login.authenticate_user("JohnWick", "WrongPassword")

        assert success == False, "Login with wrong password should fail"
        assert user is None, "User data should be None on failed login"
        assert len(message) > 0, "Should return an error message"
        print("✓ Wrong password is rejected")

    def test_nonexistent_user(self):
        """Test that non-existent username is rejected"""
        success, user, message = login.authenticate_user("NonExistentUser", "password123")

        assert success == False, "Login with non-existent user should fail"
        assert user is None, "User data should be None when user doesn't exist"
        assert len(message) > 0, "Should return an error message"
        print("✓ Non-existent user is rejected")

    def test_multiple_users_can_login(self):
        """Test that different users can login independently"""
        # Test all three registered users
        test_users = [
            ("JohnWick", "BabaYaga2023"),
            ("Winston", "Continental123"),
            ("Marcus", "Sniper999"),
        ]

        for username, password in test_users:
            success, user, message = login.authenticate_user(username, password)
            assert success == True, f"User {username} should be able to login"
            assert user['username'] == username, f"Should return correct user data for {username}"

        print("✓ Multiple users can login independently")

    def test_case_sensitive_password(self):
        """Test that passwords are case-sensitive"""
        # Original: "BabaYaga2023"
        wrong_case_passwords = ["babayaga2023", "BABAYAGA2023", "BabaYAGA2023"]

        for wrong_password in wrong_case_passwords:
            success, user, message = login.authenticate_user("JohnWick", wrong_password)
            assert success == False, \
                f"Password '{wrong_password}' should be rejected (case sensitive)"

        print("✓ Passwords are case-sensitive")


class TestReturnValueStructure:
    """Tests for correct return value format"""

    def test_return_value_is_tuple(self):
        """Test that authenticate_user returns a tuple"""
        result = login.authenticate_user("JohnWick", "BabaYaga2023")

        assert isinstance(result, tuple), "Should return a tuple"
        assert len(result) == 3, "Should return tuple of length 3: (success, user, message)"
        print("✓ Returns correct tuple structure")

    def test_success_value_is_boolean(self):
        """Test that success value is a boolean"""
        success, user, message = login.authenticate_user("JohnWick", "BabaYaga2023")

        assert isinstance(success, bool), "Success value should be a boolean (True/False)"
        print("✓ Success value is boolean")

    def test_user_data_on_success(self):
        """Test that user data is a dict on successful login"""
        success, user, message = login.authenticate_user("JohnWick", "BabaYaga2023")

        assert isinstance(user, dict), "User data should be a dictionary"
        assert 'username' in user, "User dict should contain 'username'"
        assert 'password_hash' in user, "User dict should contain 'password_hash'"
        assert 'role' in user, "User dict should contain 'role'"
        print("✓ User data has correct structure")

    def test_user_data_on_failure(self):
        """Test that user data is None on failed login"""
        # Test wrong password
        success, user, message = login.authenticate_user("JohnWick", "WrongPassword")
        assert user is None, "User should be None when password is wrong"

        # Test non-existent user
        success, user, message = login.authenticate_user("FakeUser", "password")
        assert user is None, "User should be None when user doesn't exist"

        print("✓ User data is None on failure")


class TestSecurity:
    """Security-focused tests"""

    def test_error_messages_are_generic(self):
        """
        CRITICAL: Test that error messages don't reveal whether username exists
        """
        # Wrong password for existing user
        success1, user1, message1 = login.authenticate_user("JohnWick", "WrongPassword")

        # Non-existent user
        success2, user2, message2 = login.authenticate_user("NonExistentUser", "password123")

        # Both should return the same generic message
        # This prevents hackers from enumerating valid usernames
        assert message1.lower() == message2.lower(), \
            f"Error messages should be identical! Got:\n" \
            f"  Wrong password: '{message1}'\n" \
            f"  Non-existent user: '{message2}'\n" \
            f"This helps hackers! Use same message for both."

        # Message should be generic
        generic_keywords = ["invalid", "incorrect", "failed"]
        message_lower = message1.lower()
        has_generic = any(keyword in message_lower for keyword in generic_keywords)

        assert has_generic, \
            f"Error message should be generic like 'Invalid username or password', got '{message1}'"

        # Message should NOT reveal specific information
        bad_keywords = ["not found", "doesn't exist", "wrong password", "incorrect password"]
        has_specific = any(keyword in message_lower for keyword in bad_keywords)

        assert not has_specific, \
            f"Error message is too specific! It reveals information to hackers. Got: '{message1}'"

        print("✓ SECURITY: Error messages are generic (don't leak info)")

    def test_uses_bcrypt_not_plain_comparison(self):
        """Test that password verification uses bcrypt, not plain comparison"""
        # Get user from database
        user = db.get_user("JohnWick")

        # The password hash should be bcrypt format
        assert user['password_hash'].startswith('$2'), \
            "Password should be stored as bcrypt hash"

        # Try to login
        success, user_data, message = login.authenticate_user("JohnWick", "BabaYaga2023")

        # Should succeed (meaning bcrypt verification worked)
        assert success == True, "Should authenticate with bcrypt"

        print("✓ SECURITY: Uses bcrypt for password verification")

    def test_empty_credentials(self):
        """Test handling of empty username or password"""
        # Empty username
        success, user, message = login.authenticate_user("", "password123")
        assert success == False, "Empty username should be rejected"

        # Empty password
        success, user, message = login.authenticate_user("JohnWick", "")
        assert success == False, "Empty password should be rejected"

        print("✓ Empty credentials are rejected")

    def test_special_characters_in_credentials(self):
        """Test that special characters are handled safely"""
        # SQL injection attempt in username
        sql_injection_attempts = [
            "admin' OR '1'='1",
            "'; DROP TABLE users; --",
            "admin'--",
        ]

        for injection in sql_injection_attempts:
            success, user, message = login.authenticate_user(injection, "password")
            assert success == False, \
                f"SQL injection attempt '{injection}' should be rejected"

        print("✓ SECURITY: SQL injection attempts are rejected")


class TestEdgeCases:
    """Tests for edge cases and error conditions"""

    def test_consecutive_failed_logins(self):
        """Test multiple failed login attempts"""
        # Try wrong password 5 times
        for i in range(5):
            success, user, message = login.authenticate_user("JohnWick", "WrongPassword")
            assert success == False, f"Attempt {i+1} should fail"

        # Correct password should still work (unless you implement rate limiting)
        success, user, message = login.authenticate_user("JohnWick", "BabaYaga2023")
        # Note: If you implement rate limiting, this might fail
        # For basic version, it should still succeed

        print("✓ Handles consecutive failed logins")

    def test_login_after_correct_attempt(self):
        """Test that user can login multiple times"""
        # Login successfully
        success1, user1, msg1 = login.authenticate_user("JohnWick", "BabaYaga2023")
        assert success1 == True

        # Login again
        success2, user2, msg2 = login.authenticate_user("JohnWick", "BabaYaga2023")
        assert success2 == True, "Should be able to login multiple times"

        print("✓ User can login multiple times")

    def test_whitespace_in_credentials(self):
        """Test handling of whitespace in username/password"""
        # Username with whitespace should fail (our validation doesn't allow it)
        success, user, message = login.authenticate_user("John Wick", "BabaYaga2023")
        assert success == False, "Username with space should be rejected"

        # Password with leading/trailing spaces should fail (different password)
        success, user, message = login.authenticate_user("JohnWick", " BabaYaga2023")
        assert success == False, "Password with leading space is different password"

        success, user, message = login.authenticate_user("JohnWick", "BabaYaga2023 ")
        assert success == False, "Password with trailing space is different password"

        print("✓ Whitespace in credentials is handled correctly")


class TestIntegrationWithPhase2:
    """Tests that Phase 3 correctly integrates with Phase 2"""

    def test_can_login_after_registration(self):
        """Test that newly registered user can immediately login"""
        # Register new user
        success, message = auth.register_user("NewUser", "newpassword123")
        assert success == True, "Registration should succeed"

        # Login with new user
        login_success, user, login_msg = login.authenticate_user("NewUser", "newpassword123")
        assert login_success == True, "Should be able to login immediately after registration"
        assert user['username'] == "NewUser", "Should return correct user data"

        print("✓ Can login immediately after registration")

    def test_password_hash_not_returned_directly(self):
        """Test that we're using the hash from database, not hardcoded"""
        # Get user's hash from database
        user_from_db = db.get_user("JohnWick")
        hash_from_db = user_from_db['password_hash']

        # Login successfully
        success, user_from_login, message = login.authenticate_user("JohnWick", "BabaYaga2023")

        # The hash should match what's in the database
        assert user_from_login['password_hash'] == hash_from_db, \
            "Should return the actual hash from database"

        print("✓ Uses actual password hash from database")


class TestBonusFeatures:
    """Optional bonus tests for advanced features"""

    def test_timing_attack_protection_exists(self):
        """Test that timing-attack resistant function exists (bonus)"""
        # Check if function exists
        assert hasattr(login, 'authenticate_user_secure'), \
            "BONUS: Consider implementing authenticate_user_secure for timing attack protection"

        print("✓ BONUS: Timing-attack resistant function exists")


if __name__ == "__main__":
    """
    Run tests with color output and verbose mode
    """
    pytest.main([__file__, "-v", "--color=yes", "--tb=short"])

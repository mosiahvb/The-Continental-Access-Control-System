"""
Phase 2 Tests - The Continental Access Control System
Tests for User Registration & Password Security

Run these tests with: pytest test_phase2.py -v

These tests verify that:
- Passwords are hashed (NOT stored in plain text)
- Database stores users correctly
- Validation works properly
- Registration flow works end-to-end
"""

import pytest
import os
import bcrypt
import final_project.database as db
import final_project.auth as auth


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """
    This runs before and after EACH test.
    It ensures we start with a fresh database for every test.
    """
    # BEFORE TEST: Delete old database and create new one
    db.delete_database()
    db.init_database()

    yield  # This is where the test runs

    # AFTER TEST: Clean up
    db.delete_database()


class TestDatabaseSetup:
    """Tests for database initialization and structure"""

    def test_database_file_created(self):
        """Test that database file is created"""
        assert os.path.exists(db.DB_FILE), \
            f"Database file '{db.DB_FILE}' should be created"
        print("✓ Database file created")

    def test_users_table_exists(self):
        """Test that users table was created"""
        conn = db.get_connection()
        cursor = conn.cursor()

        # Query to check if table exists
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='users'
        """)
        result = cursor.fetchone()
        conn.close()

        assert result is not None, "Users table should exist"
        print("✓ Users table exists")

    def test_users_table_structure(self):
        """Test that users table has correct columns"""
        conn = db.get_connection()
        cursor = conn.cursor()

        # Get table structure
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        conn.close()

        column_names = [col[1] for col in columns]

        assert 'id' in column_names, "Table should have 'id' column"
        assert 'username' in column_names, "Table should have 'username' column"
        assert 'password_hash' in column_names, "Table should have 'password_hash' column"
        assert 'role' in column_names, "Table should have 'role' column"
        assert 'created_at' in column_names, "Table should have 'created_at' column"

        print("✓ Users table has correct structure")


class TestPasswordHashing:
    """Tests for password hashing with bcrypt"""

    def test_passwords_are_hashed(self):
        """Test that passwords are actually hashed, not stored as plain text"""
        plain_password = "MyPassword123"
        hashed = auth.hash_password(plain_password)

        assert hashed != plain_password, \
            "Hashed password should NOT be the same as plain text password!"
        assert len(hashed) > 0, "Hashed password should not be empty"
        print("✓ Passwords are hashed")

    def test_hash_uses_bcrypt_format(self):
        """Test that hash follows bcrypt format"""
        hashed = auth.hash_password("test123")

        # Bcrypt hashes start with $2b$ or $2a$ or $2y$
        assert hashed.startswith('$2'), \
            f"Bcrypt hash should start with '$2', got: {hashed[:10]}"
        assert len(hashed) == 60, \
            f"Bcrypt hash should be 60 characters, got: {len(hashed)}"
        print("✓ Hash uses bcrypt format")

    def test_same_password_different_hashes(self):
        """Test that same password produces different hashes (salt working)"""
        password = "password123"
        hash1 = auth.hash_password(password)
        hash2 = auth.hash_password(password)

        assert hash1 != hash2, \
            "Same password should produce different hashes (salt should be random)"
        print("✓ Bcrypt salt is working (same password → different hashes)")

    def test_verify_password_works(self):
        """Test that password verification works correctly"""
        password = "CorrectPassword"
        hashed = auth.hash_password(password)

        # Correct password should verify
        assert auth.verify_password(password, hashed), \
            "Correct password should verify successfully"

        # Wrong password should NOT verify
        assert not auth.verify_password("WrongPassword", hashed), \
            "Wrong password should NOT verify"

        print("✓ Password verification works")


class TestDatabaseOperations:
    """Tests for database CRUD operations"""

    def test_add_user_success(self):
        """Test adding a user to database"""
        success = db.add_user("JohnWick", "fake_hash_123", "guest")

        assert success == True, "Adding valid user should return True"
        print("✓ Can add user to database")

    def test_add_duplicate_username_fails(self):
        """Test that duplicate usernames are rejected"""
        db.add_user("JohnWick", "hash1", "guest")
        success = db.add_user("JohnWick", "hash2", "guest")

        assert success == False, \
            "Adding duplicate username should return False"
        print("✓ Duplicate usernames are rejected")

    def test_username_exists_true(self):
        """Test username_exists returns True when user exists"""
        db.add_user("Winston", "hash", "guest")

        assert db.username_exists("Winston") == True, \
            "username_exists should return True for existing user"
        print("✓ username_exists returns True for existing users")

    def test_username_exists_false(self):
        """Test username_exists returns False when user doesn't exist"""
        assert db.username_exists("NonExistentUser") == False, \
            "username_exists should return False for non-existent user"
        print("✓ username_exists returns False for non-existent users")

    def test_get_user_success(self):
        """Test retrieving a user from database"""
        db.add_user("Marcus", "hash_value", "guest")

        user = db.get_user("Marcus")

        assert user is not None, "get_user should return user data"
        assert user['username'] == "Marcus", "Username should match"
        assert user['password_hash'] == "hash_value", "Password hash should match"
        assert user['role'] == "guest", "Role should match"
        print("✓ Can retrieve user from database")

    def test_get_user_not_found(self):
        """Test get_user returns None for non-existent user"""
        user = db.get_user("DoesNotExist")

        assert user is None, "get_user should return None for non-existent user"
        print("✓ get_user returns None for non-existent users")


class TestUsernameValidation:
    """Tests for username validation"""

    def test_valid_username(self):
        """Test that valid usernames pass validation"""
        is_valid, error = auth.validate_username("JohnWick")

        assert is_valid == True, f"Valid username should pass: {error}"
        assert error == "", "Error message should be empty for valid username"
        print("✓ Valid usernames pass validation")

    def test_username_too_short(self):
        """Test that usernames under 3 characters are rejected"""
        is_valid, error = auth.validate_username("Jo")

        assert is_valid == False, "Username with 2 characters should be rejected"
        assert "3" in error or "short" in error.lower(), \
            "Error message should mention minimum length"
        print("✓ Short usernames are rejected")

    def test_username_too_long(self):
        """Test that usernames over 20 characters are rejected"""
        is_valid, error = auth.validate_username("ThisIsAVeryLongUsernameThatExceeds20Characters")

        assert is_valid == False, "Username over 20 characters should be rejected"
        assert "20" in error or "long" in error.lower(), \
            "Error message should mention maximum length"
        print("✓ Long usernames are rejected")

    def test_username_special_characters(self):
        """Test that usernames with special characters are rejected"""
        invalid_usernames = ["John@Wick", "John.Wick", "John-Wick", "John_Wick", "John Wick"]

        for username in invalid_usernames:
            is_valid, error = auth.validate_username(username)
            assert is_valid == False, \
                f"Username '{username}' with special characters should be rejected"

        print("✓ Usernames with special characters are rejected")

    def test_username_alphanumeric(self):
        """Test that alphanumeric usernames are accepted"""
        valid_usernames = ["John123", "Player1", "User42", "ABC123"]

        for username in valid_usernames:
            is_valid, error = auth.validate_username(username)
            assert is_valid == True, \
                f"Alphanumeric username '{username}' should be accepted: {error}"

        print("✓ Alphanumeric usernames are accepted")

    def test_username_already_taken(self):
        """Test that existing usernames are rejected"""
        # Add a user first
        db.add_user("ExistingUser", "hash", "guest")

        # Try to validate same username
        is_valid, error = auth.validate_username("ExistingUser")

        assert is_valid == False, "Existing username should be rejected"
        assert "taken" in error.lower() or "exists" in error.lower(), \
            "Error message should mention username is taken"
        print("✓ Duplicate usernames are rejected during validation")


class TestPasswordValidation:
    """Tests for password validation"""

    def test_valid_password(self):
        """Test that valid passwords pass validation"""
        is_valid, error = auth.validate_password("MyPassword123")

        assert is_valid == True, f"Valid password should pass: {error}"
        assert error == "", "Error message should be empty for valid password"
        print("✓ Valid passwords pass validation")

    def test_password_too_short(self):
        """Test that passwords under 8 characters are rejected"""
        is_valid, error = auth.validate_password("short")

        assert is_valid == False, "Password under 8 characters should be rejected"
        assert "8" in error, "Error message should mention minimum length"
        print("✓ Short passwords are rejected")

    def test_empty_password(self):
        """Test that empty passwords are rejected"""
        is_valid, error = auth.validate_password("")

        assert is_valid == False, "Empty password should be rejected"
        print("✓ Empty passwords are rejected")


class TestUserRegistration:
    """Tests for the complete registration flow"""

    def test_successful_registration(self):
        """Test that valid registration works end-to-end"""
        success, message = auth.register_user("JohnWick", "BabaYaga2023")

        assert success == True, f"Valid registration should succeed: {message}"
        assert "success" in message.lower(), \
            "Success message should mention success"
        print("✓ Valid registration succeeds")

    def test_user_stored_in_database(self):
        """Test that registered user is actually stored in database"""
        auth.register_user("Winston", "Continental123")

        user = db.get_user("Winston")
        assert user is not None, "Registered user should be in database"
        assert user['username'] == "Winston", "Username should match"
        print("✓ Registered users are stored in database")

    def test_password_hashed_in_database(self):
        """CRITICAL TEST: Verify password is HASHED, not plain text!"""
        plain_password = "MySecretPassword123"
        auth.register_user("TestUser", plain_password)

        user = db.get_user("TestUser")

        # Password hash should NOT equal plain password
        assert user['password_hash'] != plain_password, \
            "CRITICAL: Password is stored in PLAIN TEXT! It should be HASHED!"

        # Password hash should be bcrypt format
        assert user['password_hash'].startswith('$2'), \
            "Password should be stored as bcrypt hash"

        # Verify password with bcrypt
        assert auth.verify_password(plain_password, user['password_hash']), \
            "Hashed password should verify correctly"

        print("✓ CRITICAL: Passwords are hashed in database (NOT plain text)")

    def test_registration_invalid_username(self):
        """Test that registration fails with invalid username"""
        success, message = auth.register_user("Jo", "ValidPassword123")

        assert success == False, "Registration with invalid username should fail"
        assert len(message) > 0, "Should return error message"
        print("✓ Registration fails with invalid username")

    def test_registration_invalid_password(self):
        """Test that registration fails with invalid password"""
        success, message = auth.register_user("ValidUser", "short")

        assert success == False, "Registration with invalid password should fail"
        assert len(message) > 0, "Should return error message"
        print("✓ Registration fails with invalid password")

    def test_registration_duplicate_username(self):
        """Test that registering same username twice fails"""
        auth.register_user("JohnWick", "Password123")
        success, message = auth.register_user("JohnWick", "DifferentPassword456")

        assert success == False, "Duplicate username registration should fail"
        assert "taken" in message.lower() or "exists" in message.lower(), \
            "Error message should mention username is taken"
        print("✓ Cannot register duplicate username")

    def test_user_role_defaults_to_guest(self):
        """Test that new users get 'guest' role by default"""
        auth.register_user("NewUser", "Password123")

        user = db.get_user("NewUser")
        assert user['role'] == "guest", \
            "New users should have 'guest' role by default"
        print("✓ New users default to 'guest' role")


class TestSecurity:
    """Security-focused tests"""

    def test_no_plain_text_passwords_in_database(self):
        """CRITICAL: Verify NO plain text passwords are stored"""
        passwords = ["password123", "qwerty", "letmein", "admin", "12345678"]

        for pwd in passwords:
            auth.register_user(f"User{pwd[:3]}", pwd)

        # Get all users and check their password hashes
        all_users = db.get_all_users()

        for user in all_users:
            for pwd in passwords:
                assert user['password_hash'] != pwd, \
                    f"CRITICAL: Password '{pwd}' is stored in PLAIN TEXT!"

        print("✓ SECURITY: No plain text passwords found in database")

    def test_bcrypt_cost_factor_adequate(self):
        """Test that bcrypt cost factor is reasonable (at least 10)"""
        hashed = auth.hash_password("test")

        # Bcrypt hash format: $2b$12$... where 12 is the cost factor
        parts = hashed.split('$')
        cost_factor = int(parts[2])

        assert cost_factor >= 10, \
            f"Bcrypt cost factor should be at least 10 for security, got {cost_factor}"
        print(f"✓ Bcrypt cost factor is adequate ({cost_factor} rounds)")


if __name__ == "__main__":
    """
    Run tests with color output and verbose mode
    """
    pytest.main([__file__, "-v", "--color=yes", "--tb=short"])

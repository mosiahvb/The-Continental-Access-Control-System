"""
Tests for Phase 7: Encrypted Audit Logging

Run with: pytest test_phase7.py -v
"""

import pytest
import os
import sys
import json
from datetime import datetime, timedelta

# Import the module to test
import final_project.audit_log as audit_log

# Import from previous phases for integration tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase_2_registration'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase_3_login'))

import database as db
import login as auth


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """Setup and teardown for each test"""
    # Setup: Clean slate for each test
    audit_log.delete_log_database()
    audit_log.init_log_database()

    yield

    # Teardown: Clean up after test
    # (Keep database for inspection, or uncomment to delete)
    # audit_log.delete_log_database()


class TestLogDatabaseSetup:
    """Test log database initialization"""

    def test_log_database_created(self):
        """Test that log database file is created"""
        assert os.path.exists(audit_log.LOG_DB_FILE), "Log database file should be created"

    def test_logs_table_exists(self):
        """Test that logs table exists with correct schema"""
        conn = audit_log.get_log_connection()
        cursor = conn.cursor()

        # Get table info
        cursor.execute("PRAGMA table_info(logs)")
        columns = cursor.fetchall()
        conn.close()

        # Check that table has columns
        assert len(columns) > 0, "Logs table should exist"

        # Check for required columns
        column_names = [col[1] for col in columns]
        assert 'id' in column_names
        assert 'timestamp' in column_names
        assert 'username' in column_names
        assert 'action' in column_names
        assert 'details' in column_names
        assert 'ip_address' in column_names
        assert 'success' in column_names


class TestEncryption:
    """Test encryption and decryption"""

    def test_encrypt_details(self):
        """Test that details can be encrypted"""
        details = {'ip': '192.168.1.100', 'reason': 'Test'}
        encrypted = audit_log.encrypt_log_details(details)

        assert encrypted is not None, "Should return encrypted string"
        assert isinstance(encrypted, str), "Should return string"
        assert len(encrypted) > 0, "Encrypted string should not be empty"
        assert encrypted != json.dumps(details), "Encrypted data should not match plaintext"

    def test_decrypt_details(self):
        """Test that details can be decrypted"""
        original = {'ip': '192.168.1.100', 'reason': 'Invalid password'}
        encrypted = audit_log.encrypt_log_details(original)
        decrypted = audit_log.decrypt_log_details(encrypted)

        assert decrypted == original, "Decrypted data should match original"

    def test_encryption_is_different_each_time(self):
        """Test that encryption produces different ciphertext (includes IV)"""
        details = {'test': 'data'}
        encrypted1 = audit_log.encrypt_log_details(details)
        encrypted2 = audit_log.encrypt_log_details(details)

        # Fernet includes timestamp, so encryptions will be different
        assert encrypted1 != encrypted2, "Each encryption should produce different ciphertext"

    def test_encrypted_data_not_readable(self):
        """Test that encrypted data doesn't contain plaintext"""
        details = {
            'secret': 'this_is_sensitive',
            'ip': '192.168.1.100'
        }
        encrypted = audit_log.encrypt_log_details(details)

        # Encrypted data should not contain the plaintext
        assert 'this_is_sensitive' not in encrypted
        assert '192.168.1.100' not in encrypted


class TestEventLogging:
    """Test logging events"""

    def test_log_event_creates_entry(self):
        """Test that log_event creates a database entry"""
        details = {'ip': '192.168.1.100', 'test': 'data'}
        audit_log.log_event('TestUser', 'test_action', True, details)

        # Verify entry was created
        conn = audit_log.get_log_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM logs')
        count = cursor.fetchone()[0]
        conn.close()

        assert count == 1, "Should create one log entry"

    def test_log_event_encrypts_details(self):
        """Test that details are encrypted in database"""
        details = {'secret': 'sensitive_data', 'ip': '192.168.1.100'}
        audit_log.log_event('TestUser', 'test_action', True, details)

        # Read directly from database
        conn = audit_log.get_log_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT details FROM logs')
        stored_details = cursor.fetchone()[0]
        conn.close()

        # Details should not contain plaintext
        assert 'sensitive_data' not in stored_details
        assert '192.168.1.100' not in stored_details

    def test_log_event_stores_all_fields(self):
        """Test that all fields are stored correctly"""
        details = {'ip': '192.168.1.100'}
        audit_log.log_event('JohnWick', 'login_attempt', True, details, '192.168.1.100')

        # Retrieve and verify
        conn = audit_log.get_log_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username, action, success, ip_address FROM logs')
        row = cursor.fetchone()
        conn.close()

        assert row[0] == 'JohnWick'
        assert row[1] == 'login_attempt'
        assert row[2] == 1  # True = 1
        assert row[3] == '192.168.1.100'

    def test_log_event_with_failure(self):
        """Test logging failed events"""
        details = {'reason': 'Invalid password'}
        audit_log.log_event('TestUser', 'login_attempt', False, details)

        conn = audit_log.get_log_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT success FROM logs')
        success = cursor.fetchone()[0]
        conn.close()

        assert success == 0, "Failed event should have success = 0"


class TestLogRetrieval:
    """Test retrieving and filtering logs"""

    def test_get_all_logs(self):
        """Test retrieving all logs"""
        # Create some logs
        for i in range(3):
            audit_log.log_event(f'User{i}', 'test', True, {'test': i})

        logs = audit_log.get_logs()

        assert len(logs) == 3, "Should retrieve all logs"

    def test_get_logs_decrypts_details(self):
        """Test that get_logs decrypts details"""
        original_details = {'ip': '192.168.1.100', 'test': 'data'}
        audit_log.log_event('TestUser', 'test', True, original_details)

        logs = audit_log.get_logs()

        assert len(logs) > 0
        assert logs[0]['details'] == original_details, "Details should be decrypted"

    def test_filter_by_username(self):
        """Test filtering logs by username"""
        audit_log.log_event('JohnWick', 'login', True, {'ip': '1.1.1.1'})
        audit_log.log_event('Winston', 'login', True, {'ip': '2.2.2.2'})
        audit_log.log_event('JohnWick', 'logout', True, {'ip': '1.1.1.1'})

        logs = audit_log.get_logs(username='JohnWick')

        assert len(logs) == 2, "Should retrieve 2 logs for JohnWick"
        assert all(log['username'] == 'JohnWick' for log in logs)

    def test_filter_by_action(self):
        """Test filtering logs by action"""
        audit_log.log_event('User1', 'login_attempt', True, {})
        audit_log.log_event('User2', 'registration', True, {})
        audit_log.log_event('User3', 'login_attempt', False, {})

        logs = audit_log.get_logs(action='login_attempt')

        assert len(logs) == 2, "Should retrieve 2 login_attempt logs"
        assert all(log['action'] == 'login_attempt' for log in logs)

    def test_limit_logs(self):
        """Test limiting number of logs returned"""
        # Create 10 logs
        for i in range(10):
            audit_log.log_event('TestUser', 'test', True, {'num': i})

        logs = audit_log.get_logs(limit=5)

        assert len(logs) == 5, "Should respect limit parameter"

    def test_logs_ordered_by_timestamp(self):
        """Test that logs are returned in reverse chronological order"""
        import time

        # Create logs with small delays
        for i in range(3):
            audit_log.log_event('TestUser', 'test', True, {'num': i})
            time.sleep(0.01)  # Small delay to ensure different timestamps

        logs = audit_log.get_logs()

        # Most recent should be first
        assert logs[0]['details']['num'] == 2
        assert logs[2]['details']['num'] == 0


class TestFailedLoginCounting:
    """Test counting failed login attempts"""

    def test_count_failed_logins(self):
        """Test counting failed login attempts"""
        # Log 3 failed and 2 successful
        for i in range(3):
            audit_log.log_login_attempt('JohnWick', False, {'reason': 'Invalid password'})

        for i in range(2):
            audit_log.log_login_attempt('JohnWick', True, {'ip': '192.168.1.100'})

        count = audit_log.get_failed_login_attempts('JohnWick', hours=1)

        assert count == 3, "Should count only failed login attempts"

    def test_count_only_login_attempts(self):
        """Test that only login_attempt actions are counted"""
        audit_log.log_login_attempt('TestUser', False, {})
        audit_log.log_registration('TestUser', {})  # Different action
        audit_log.log_permission_denied('TestUser', '/admin', 'admin')  # Different action

        count = audit_log.get_failed_login_attempts('TestUser', hours=1)

        assert count == 1, "Should only count login_attempt actions"

    def test_count_respects_username(self):
        """Test that counting is per-user"""
        audit_log.log_login_attempt('JohnWick', False, {})
        audit_log.log_login_attempt('JohnWick', False, {})
        audit_log.log_login_attempt('Winston', False, {})

        count_john = audit_log.get_failed_login_attempts('JohnWick', hours=1)
        count_winston = audit_log.get_failed_login_attempts('Winston', hours=1)

        assert count_john == 2
        assert count_winston == 1

    def test_count_respects_time_window(self):
        """Test that old logs are not counted"""
        # This test logs events and checks recent window
        # In real scenario, you'd need to manipulate timestamps

        audit_log.log_login_attempt('TestUser', False, {})

        # Check last 24 hours (should include the log)
        count_24h = audit_log.get_failed_login_attempts('TestUser', hours=24)
        assert count_24h == 1

        # Check last 0.0001 hours (should not include the log if enough time passed)
        # Note: This test might be flaky depending on execution speed
        import time
        time.sleep(0.01)
        count_recent = audit_log.get_failed_login_attempts('TestUser', hours=0.000001)
        assert count_recent == 0, "Old logs should not be counted in very short time window"


class TestConvenienceFunctions:
    """Test convenience logging functions"""

    def test_log_login_attempt(self):
        """Test log_login_attempt function"""
        audit_log.log_login_attempt('JohnWick', True, {'ip': '192.168.1.100'})

        logs = audit_log.get_logs()
        assert len(logs) == 1
        assert logs[0]['action'] == 'login_attempt'
        assert logs[0]['username'] == 'JohnWick'
        assert logs[0]['success'] == True

    def test_log_registration(self):
        """Test log_registration function"""
        audit_log.log_registration('NewUser', {'role': 'guest'})

        logs = audit_log.get_logs()
        assert len(logs) == 1
        assert logs[0]['action'] == 'registration'
        assert logs[0]['username'] == 'NewUser'
        assert logs[0]['success'] == True

    def test_log_permission_denied(self):
        """Test log_permission_denied function"""
        audit_log.log_permission_denied('Winston', '/admin', 'high_table')

        logs = audit_log.get_logs()
        assert len(logs) == 1
        assert logs[0]['action'] == 'permission_denied'
        assert logs[0]['username'] == 'Winston'
        assert logs[0]['success'] == False
        assert logs[0]['details']['attempted_action'] == '/admin'
        assert logs[0]['details']['required_role'] == 'high_table'


class TestBruteForceDetection:
    """Test brute force attack detection"""

    def test_detect_brute_force(self):
        """Test detecting brute force attack (5+ failed logins)"""
        # Simulate brute force attack
        for i in range(6):
            audit_log.log_login_attempt('TargetUser', False, {'reason': 'Invalid password'})

        count = audit_log.get_failed_login_attempts('TargetUser', hours=1)

        assert count >= 5, "Should detect 5+ failed login attempts"

    def test_no_false_positive_on_successful_logins(self):
        """Test that successful logins don't trigger brute force detection"""
        # Log successful logins
        for i in range(10):
            audit_log.log_login_attempt('GoodUser', True, {'ip': '192.168.1.100'})

        count = audit_log.get_failed_login_attempts('GoodUser', hours=1)

        assert count == 0, "Successful logins should not be counted"


class TestLogIntegrity:
    """Test that logs are tamper-resistant"""

    def test_cannot_decrypt_tampered_data(self):
        """Test that tampering with encrypted data is detectable"""
        details = {'test': 'data'}
        encrypted = audit_log.encrypt_log_details(details)

        # Tamper with encrypted data
        tampered = encrypted[:-5] + 'XXXXX'

        # Attempting to decrypt should fail
        with pytest.raises(Exception):
            audit_log.decrypt_log_details(tampered)


class TestLogStructure:
    """Test log entry structure"""

    def test_log_has_timestamp(self):
        """Test that logs include timestamp"""
        audit_log.log_event('TestUser', 'test', True, {})

        logs = audit_log.get_logs()
        assert 'timestamp' in logs[0]
        assert logs[0]['timestamp'] is not None

    def test_log_has_all_required_fields(self):
        """Test that log entries have all required fields"""
        audit_log.log_event('TestUser', 'test_action', True, {'test': 'data'}, '192.168.1.100')

        logs = audit_log.get_logs()
        log = logs[0]

        assert 'id' in log
        assert 'timestamp' in log
        assert 'username' in log
        assert 'action' in log
        assert 'details' in log
        assert 'ip_address' in log
        assert 'success' in log


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_details(self):
        """Test logging with empty details"""
        audit_log.log_event('TestUser', 'test', True, {})

        logs = audit_log.get_logs()
        assert logs[0]['details'] == {}

    def test_complex_details(self):
        """Test logging with complex nested details"""
        details = {
            'ip': '192.168.1.100',
            'headers': {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/html'
            },
            'attempts': [1, 2, 3]
        }

        audit_log.log_event('TestUser', 'test', True, details)

        logs = audit_log.get_logs()
        assert logs[0]['details'] == details

    def test_get_logs_with_no_results(self):
        """Test getting logs when none match filters"""
        audit_log.log_event('User1', 'action1', True, {})

        logs = audit_log.get_logs(username='NonexistentUser')

        assert logs == [], "Should return empty list when no logs match"

    def test_failed_login_count_for_nonexistent_user(self):
        """Test counting failed logins for user with no logs"""
        count = audit_log.get_failed_login_attempts('NonexistentUser', hours=1)

        assert count == 0, "Should return 0 for user with no logs"


class TestSecurityPrinciples:
    """Test that security best practices are followed"""

    def test_details_encrypted_in_database(self):
        """Test that sensitive details are encrypted at rest"""
        sensitive_data = {
            'ip': '192.168.1.100',
            'location': 'New York',
            'device': 'iPhone'
        }

        audit_log.log_event('TestUser', 'login', True, sensitive_data)

        # Read directly from database
        conn = audit_log.get_log_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT details FROM logs')
        stored = cursor.fetchone()[0]
        conn.close()

        # Verify data is encrypted
        assert 'New York' not in stored
        assert 'iPhone' not in stored

    def test_username_not_encrypted(self):
        """Test that username is NOT encrypted (needed for queries)"""
        audit_log.log_event('JohnWick', 'test', True, {})

        conn = audit_log.get_log_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM logs')
        username = cursor.fetchone()[0]
        conn.close()

        assert username == 'JohnWick', "Username should be plaintext for filtering"

    def test_action_not_encrypted(self):
        """Test that action is NOT encrypted (needed for queries)"""
        audit_log.log_event('TestUser', 'login_attempt', True, {})

        conn = audit_log.get_log_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT action FROM logs')
        action = cursor.fetchone()[0]
        conn.close()

        assert action == 'login_attempt', "Action should be plaintext for filtering"


if __name__ == "__main__":
    pytest.main([__file__, '-v'])

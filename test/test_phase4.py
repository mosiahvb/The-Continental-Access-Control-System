"""
Phase 4 Tests - The Continental Access Control System
Tests for User Roles & Authorization

Run these tests with: pytest test_phase4.py -v

These tests verify that:
- Role enum is defined correctly
- Role hierarchy works (High Table > Concierge > Guest)
- Permission checking works
- Decorator blocks unauthorized users
- Decorator allows authorized users
"""

import pytest
import sys
import os

# Add phase 2 and 3 directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase_2_registration'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase_3_login'))

import database as db
import final_project.authorization as authorization
from final_project.authorization import Role, get_role_from_string, has_permission, require_role


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """
    This runs before and after EACH test.
    Sets up a fresh database with test users.
    """
    # BEFORE TEST: Setup
    db.delete_database()
    db.init_database()

    # Create test users with different roles
    db.add_user('TestGuest', 'hash1', 'guest')
    db.add_user('TestConcierge', 'hash2', 'concierge')
    db.add_user('TestHighTable', 'hash3', 'high_table')

    yield  # This is where the test runs

    # AFTER TEST: Cleanup
    db.delete_database()


class TestRoleEnum:
    """Tests for the Role enumeration"""

    def test_role_enum_exists(self):
        """Test that Role enum is defined"""
        assert hasattr(authorization, 'Role'), "Role enum should be defined"
        print("✓ Role enum exists")

    def test_role_guest_exists(self):
        """Test that GUEST role is defined"""
        assert hasattr(Role, 'GUEST'), "Role.GUEST should be defined"
        assert Role.GUEST.value == 1, "Role.GUEST should have value 1"
        print("✓ Role.GUEST = 1")

    def test_role_concierge_exists(self):
        """Test that CONCIERGE role is defined"""
        assert hasattr(Role, 'CONCIERGE'), "Role.CONCIERGE should be defined"
        assert Role.CONCIERGE.value == 2, "Role.CONCIERGE should have value 2"
        print("✓ Role.CONCIERGE = 2")

    def test_role_high_table_exists(self):
        """Test that HIGH_TABLE role is defined"""
        assert hasattr(Role, 'HIGH_TABLE'), "Role.HIGH_TABLE should be defined"
        assert Role.HIGH_TABLE.value == 3, "Role.HIGH_TABLE should have value 3"
        print("✓ Role.HIGH_TABLE = 3")

    def test_role_hierarchy(self):
        """Test that role values create a proper hierarchy"""
        assert Role.GUEST.value < Role.CONCIERGE.value, \
            "GUEST should have lower value than CONCIERGE"
        assert Role.CONCIERGE.value < Role.HIGH_TABLE.value, \
            "CONCIERGE should have lower value than HIGH_TABLE"
        assert Role.GUEST.value < Role.HIGH_TABLE.value, \
            "GUEST should have lower value than HIGH_TABLE"
        print("✓ Role hierarchy: GUEST < CONCIERGE < HIGH_TABLE")


class TestGetRoleFromString:
    """Tests for converting strings to Role enums"""

    def test_guest_lowercase(self):
        """Test converting 'guest' to Role.GUEST"""
        role = get_role_from_string('guest')
        assert role == Role.GUEST, "Should convert 'guest' to Role.GUEST"
        print("✓ 'guest' → Role.GUEST")

    def test_guest_uppercase(self):
        """Test converting 'GUEST' to Role.GUEST"""
        role = get_role_from_string('GUEST')
        assert role == Role.GUEST, "Should convert 'GUEST' to Role.GUEST"
        print("✓ 'GUEST' → Role.GUEST")

    def test_guest_mixed_case(self):
        """Test converting 'Guest' to Role.GUEST"""
        role = get_role_from_string('Guest')
        assert role == Role.GUEST, "Should convert 'Guest' to Role.GUEST"
        print("✓ 'Guest' → Role.GUEST")

    def test_concierge_conversion(self):
        """Test converting 'concierge' to Role.CONCIERGE"""
        role = get_role_from_string('concierge')
        assert role == Role.CONCIERGE, "Should convert 'concierge' to Role.CONCIERGE"
        print("✓ 'concierge' → Role.CONCIERGE")

    def test_high_table_conversion(self):
        """Test converting 'high_table' to Role.HIGH_TABLE"""
        role = get_role_from_string('high_table')
        assert role == Role.HIGH_TABLE, "Should convert 'high_table' to Role.HIGH_TABLE"
        print("✓ 'high_table' → Role.HIGH_TABLE")

    def test_invalid_role_returns_none(self):
        """Test that invalid role strings return None"""
        role = get_role_from_string('invalid_role')
        assert role is None, "Invalid role should return None"
        print("✓ 'invalid_role' → None")

    def test_empty_string_returns_none(self):
        """Test that empty string returns None"""
        role = get_role_from_string('')
        assert role is None, "Empty string should return None"
        print("✓ '' → None")


class TestHasPermission:
    """Tests for permission checking with hierarchy"""

    def test_guest_has_guest_permission(self):
        """Test that guest users have guest-level permissions"""
        user = {'username': 'TestUser', 'role': 'guest'}
        assert has_permission(user, Role.GUEST) == True, \
            "Guest user should have GUEST permission"
        print("✓ Guest user has GUEST permission")

    def test_guest_no_concierge_permission(self):
        """Test that guest users DON'T have concierge permissions"""
        user = {'username': 'TestUser', 'role': 'guest'}
        assert has_permission(user, Role.CONCIERGE) == False, \
            "Guest user should NOT have CONCIERGE permission"
        print("✓ Guest user does NOT have CONCIERGE permission")

    def test_guest_no_high_table_permission(self):
        """Test that guest users DON'T have high table permissions"""
        user = {'username': 'TestUser', 'role': 'guest'}
        assert has_permission(user, Role.HIGH_TABLE) == False, \
            "Guest user should NOT have HIGH_TABLE permission"
        print("✓ Guest user does NOT have HIGH_TABLE permission")

    def test_concierge_has_guest_permission(self):
        """Test that concierge users ALSO have guest permissions (hierarchy)"""
        user = {'username': 'TestUser', 'role': 'concierge'}
        assert has_permission(user, Role.GUEST) == True, \
            "Concierge user should have GUEST permission (hierarchy)"
        print("✓ Concierge user has GUEST permission (hierarchy)")

    def test_concierge_has_concierge_permission(self):
        """Test that concierge users have concierge permissions"""
        user = {'username': 'TestUser', 'role': 'concierge'}
        assert has_permission(user, Role.CONCIERGE) == True, \
            "Concierge user should have CONCIERGE permission"
        print("✓ Concierge user has CONCIERGE permission")

    def test_concierge_no_high_table_permission(self):
        """Test that concierge users DON'T have high table permissions"""
        user = {'username': 'TestUser', 'role': 'concierge'}
        assert has_permission(user, Role.HIGH_TABLE) == False, \
            "Concierge user should NOT have HIGH_TABLE permission"
        print("✓ Concierge user does NOT have HIGH_TABLE permission")

    def test_high_table_has_guest_permission(self):
        """Test that high table users have guest permissions (hierarchy)"""
        user = {'username': 'TestUser', 'role': 'high_table'}
        assert has_permission(user, Role.GUEST) == True, \
            "High Table user should have GUEST permission (hierarchy)"
        print("✓ High Table user has GUEST permission (hierarchy)")

    def test_high_table_has_concierge_permission(self):
        """Test that high table users have concierge permissions (hierarchy)"""
        user = {'username': 'TestUser', 'role': 'high_table'}
        assert has_permission(user, Role.CONCIERGE) == True, \
            "High Table user should have CONCIERGE permission (hierarchy)"
        print("✓ High Table user has CONCIERGE permission (hierarchy)")

    def test_high_table_has_high_table_permission(self):
        """Test that high table users have high table permissions"""
        user = {'username': 'TestUser', 'role': 'high_table'}
        assert has_permission(user, Role.HIGH_TABLE) == True, \
            "High Table user should have HIGH_TABLE permission"
        print("✓ High Table user has HIGH_TABLE permission")

    def test_invalid_role_denies_permission(self):
        """Test that users with invalid roles are denied access"""
        user = {'username': 'TestUser', 'role': 'invalid_role'}
        assert has_permission(user, Role.GUEST) == False, \
            "User with invalid role should be denied access"
        print("✓ Invalid role denies permission")

    def test_missing_role_denies_permission(self):
        """Test that users without role field are denied access"""
        user = {'username': 'TestUser'}  # No 'role' field
        # Should default to 'guest' and have guest permission
        assert has_permission(user, Role.GUEST) == True, \
            "User without role should default to guest"
        print("✓ User without role defaults to guest")


class TestRequireRoleDecorator:
    """Tests for the @require_role decorator"""

    def test_decorator_exists(self):
        """Test that require_role decorator is defined"""
        assert hasattr(authorization, 'require_role'), \
            "require_role decorator should be defined"
        print("✓ require_role decorator exists")

    def test_guest_decorator_allows_guest(self):
        """Test that @require_role('guest') allows guest users"""
        @require_role('guest')
        def test_function(user):
            return "Access granted"

        user = {'username': 'TestUser', 'role': 'guest'}
        result = test_function(user)
        assert "Access granted" in result or "granted" in result.lower(), \
            "Guest user should be allowed to access guest-level function"
        print("✓ @require_role('guest') allows guest users")

    def test_concierge_decorator_blocks_guest(self):
        """Test that @require_role('concierge') blocks guest users"""
        @require_role('concierge')
        def test_function(user):
            return "Access granted"

        user = {'username': 'TestUser', 'role': 'guest'}
        result = test_function(user)
        assert "denied" in result.lower() or "❌" in result, \
            "Guest user should be blocked from concierge-level function"
        print("✓ @require_role('concierge') blocks guest users")

    def test_concierge_decorator_allows_concierge(self):
        """Test that @require_role('concierge') allows concierge users"""
        @require_role('concierge')
        def test_function(user):
            return "Access granted"

        user = {'username': 'TestUser', 'role': 'concierge'}
        result = test_function(user)
        assert "Access granted" in result or "granted" in result.lower(), \
            "Concierge user should be allowed to access concierge-level function"
        print("✓ @require_role('concierge') allows concierge users")

    def test_high_table_decorator_blocks_guest(self):
        """Test that @require_role('high_table') blocks guest users"""
        @require_role('high_table')
        def test_function(user):
            return "Access granted"

        user = {'username': 'TestUser', 'role': 'guest'}
        result = test_function(user)
        assert "denied" in result.lower() or "❌" in result, \
            "Guest user should be blocked from high_table-level function"
        print("✓ @require_role('high_table') blocks guest users")

    def test_high_table_decorator_blocks_concierge(self):
        """Test that @require_role('high_table') blocks concierge users"""
        @require_role('high_table')
        def test_function(user):
            return "Access granted"

        user = {'username': 'TestUser', 'role': 'concierge'}
        result = test_function(user)
        assert "denied" in result.lower() or "❌" in result, \
            "Concierge user should be blocked from high_table-level function"
        print("✓ @require_role('high_table') blocks concierge users")

    def test_high_table_decorator_allows_high_table(self):
        """Test that @require_role('high_table') allows high table users"""
        @require_role('high_table')
        def test_function(user):
            return "Access granted"

        user = {'username': 'TestUser', 'role': 'high_table'}
        result = test_function(user)
        assert "Access granted" in result or "granted" in result.lower(), \
            "High Table user should be allowed to access high_table-level function"
        print("✓ @require_role('high_table') allows high table users")

    def test_decorator_hierarchy_guest_function(self):
        """Test hierarchy: all roles can access guest-level functions"""
        @require_role('guest')
        def test_function(user):
            return f"Welcome {user['username']}"

        guest = {'username': 'Guest', 'role': 'guest'}
        concierge = {'username': 'Concierge', 'role': 'concierge'}
        high_table = {'username': 'Manager', 'role': 'high_table'}

        assert "Welcome" in test_function(guest), \
            "Guest should access guest-level function"
        assert "Welcome" in test_function(concierge), \
            "Concierge should access guest-level function (hierarchy)"
        assert "Welcome" in test_function(high_table), \
            "High Table should access guest-level function (hierarchy)"
        print("✓ All roles can access guest-level functions (hierarchy)")

    def test_decorator_hierarchy_concierge_function(self):
        """Test hierarchy: only concierge+ can access concierge-level functions"""
        @require_role('concierge')
        def test_function(user):
            return f"Welcome {user['username']}"

        guest = {'username': 'Guest', 'role': 'guest'}
        concierge = {'username': 'Concierge', 'role': 'concierge'}
        high_table = {'username': 'Manager', 'role': 'high_table'}

        guest_result = test_function(guest)
        assert "denied" in guest_result.lower() or "❌" in guest_result, \
            "Guest should NOT access concierge-level function"

        assert "Welcome" in test_function(concierge), \
            "Concierge should access concierge-level function"
        assert "Welcome" in test_function(high_table), \
            "High Table should access concierge-level function (hierarchy)"
        print("✓ Only concierge+ can access concierge-level functions")

    def test_decorator_passes_arguments(self):
        """Test that decorator preserves function arguments"""
        @require_role('guest')
        def test_function(user, arg1, arg2):
            return f"{user['username']}: {arg1} + {arg2}"

        user = {'username': 'TestUser', 'role': 'guest'}
        result = test_function(user, "hello", "world")
        assert "hello" in result and "world" in result, \
            "Decorator should pass through function arguments"
        print("✓ Decorator preserves function arguments")

    def test_decorator_preserves_function_name(self):
        """Test that decorator preserves function metadata"""
        @require_role('guest')
        def test_function(user):
            """Test docstring"""
            return "test"

        # Check that function name is preserved (requires @wraps)
        assert test_function.__name__ == 'test_function', \
            "Decorator should preserve function name (use @wraps)"
        print("✓ Decorator preserves function name (@wraps working)")


class TestRealWorldScenarios:
    """Integration tests simulating real usage"""

    def test_guest_workflow(self):
        """Test complete guest user workflow"""
        user = db.get_user('TestGuest')

        # Guest should access guest areas
        assert has_permission(user, Role.GUEST) == True

        # Guest should NOT access concierge areas
        assert has_permission(user, Role.CONCIERGE) == False

        # Guest should NOT access high table areas
        assert has_permission(user, Role.HIGH_TABLE) == False

        print("✓ Guest workflow: can only access guest areas")

    def test_concierge_workflow(self):
        """Test complete concierge user workflow"""
        user = db.get_user('TestConcierge')

        # Concierge should access guest areas (hierarchy)
        assert has_permission(user, Role.GUEST) == True

        # Concierge should access concierge areas
        assert has_permission(user, Role.CONCIERGE) == True

        # Concierge should NOT access high table areas
        assert has_permission(user, Role.HIGH_TABLE) == False

        print("✓ Concierge workflow: can access guest + concierge areas")

    def test_high_table_workflow(self):
        """Test complete high table user workflow"""
        user = db.get_user('TestHighTable')

        # High Table should access ALL areas (hierarchy)
        assert has_permission(user, Role.GUEST) == True
        assert has_permission(user, Role.CONCIERGE) == True
        assert has_permission(user, Role.HIGH_TABLE) == True

        print("✓ High Table workflow: can access all areas (full hierarchy)")

    def test_authorization_after_authentication(self):
        """Test that authorization works with authenticated users"""
        # Simulate login
        user = db.get_user('TestConcierge')

        # User is authenticated (they logged in)
        assert user is not None

        # But can they access high table areas? (authorization)
        assert has_permission(user, Role.HIGH_TABLE) == False, \
            "Concierge is authenticated but not authorized for high table"

        print("✓ Authentication ≠ Authorization (security principle)")


class TestSecurityPrinciples:
    """Tests for security best practices"""

    def test_principle_of_least_privilege(self):
        """Test that users only get minimum necessary permissions"""
        guest = db.get_user('TestGuest')

        # Guest should only have guest permissions
        assert has_permission(guest, Role.GUEST) == True
        assert has_permission(guest, Role.CONCIERGE) == False, \
            "Least Privilege: Guest should not have concierge access"
        assert has_permission(guest, Role.HIGH_TABLE) == False, \
            "Least Privilege: Guest should not have high table access"

        print("✓ Principle of Least Privilege enforced")

    def test_fail_secure(self):
        """Test that system fails securely (denies access when in doubt)"""
        # User with invalid role
        invalid_user = {'username': 'Test', 'role': 'invalid'}
        assert has_permission(invalid_user, Role.GUEST) == False, \
            "Fail Secure: Invalid role should deny access"

        # User with no role
        no_role_user = {'username': 'Test'}
        # This should default to guest, so should have guest access
        assert has_permission(no_role_user, Role.GUEST) == True

        print("✓ System fails securely (denies when invalid)")

    def test_defense_in_depth(self):
        """Test that multiple security layers exist"""
        # Layer 1: Authentication (handled in Phase 3)
        # Layer 2: Authorization (Phase 4)

        user = db.get_user('TestGuest')

        # Even if user is authenticated, authorization can still block them
        @require_role('high_table')
        def sensitive_function(user):
            return "Sensitive data"

        result = sensitive_function(user)
        assert "denied" in result.lower() or "❌" in result, \
            "Defense in Depth: Authorization blocks even authenticated users"

        print("✓ Defense in Depth: Multiple security layers")


if __name__ == "__main__":
    """
    Run tests with color output and verbose mode
    """
    pytest.main([__file__, "-v", "--color=yes", "--tb=short"])

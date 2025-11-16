"""
The Continental Access Control System
Authorization & Role-Based Access Control Module

This module implements Role-Based Access Control (RBAC) for The Continental.
RBAC is a security system where users are assigned roles (like "Guest" or "Manager"),
and each role has different permissions (what they're allowed to do).

Key Concepts:
- Authentication: Who you are (handled by login module)
- Authorization: What you're allowed to do (handled by this module)
- Role Hierarchy: Higher roles automatically get all lower role permissions
"""

from enum import Enum
from typing import Optional, Dict
from functools import wraps


class Role(Enum):
    """
    Defines the three user roles in The Continental system.

    Roles create a hierarchy using numeric values:
    - GUEST (1): Basic access level - can view public areas
    - CONCIERGE (2): Employee access level - can access staff areas
    - HIGH_TABLE (3): Manager access level - can access all areas

    The hierarchy works like this:
    - High Table users can do everything (they have value 3, which is >= 1, 2, and 3)
    - Concierge users can do Guest things and their own things (value 2 is >= 1 and 2)
    - Guest users can only do Guest things (value 1 is only >= 1)

    Think of it like clearance levels: higher clearance gives you access to
    everything below it, plus your own level.
    """
    GUEST = 1         # Basic user role - lowest privileges
    CONCIERGE = 2     # Staff member role - medium privileges
    HIGH_TABLE = 3    # Management role - highest privileges


def get_role_from_string(role_str: str) -> Optional[Role]:
    """
    Converts a role string into a Role enum object.

    The database stores roles as strings like "guest" or "concierge",
    but our code works with Role enums for type safety and consistency.
    This function bridges that gap.

    Args:
        role_str: The role as a string (e.g., "guest", "concierge", "high_table")
                  Case-insensitive - "GUEST", "Guest", and "guest" all work

    Returns:
        The matching Role enum if valid, or None if the string doesn't match any role

    Examples:
        get_role_from_string("guest") returns Role.GUEST
        get_role_from_string("CONCIERGE") returns Role.CONCIERGE
        get_role_from_string("invalid") returns None
    """
    # Convert to uppercase so we can match the enum names
    # "guest" becomes "GUEST", which matches Role.GUEST
    role_str = role_str.upper()

    try:
        # Try to look up the role in the enum
        # This is like doing Role["GUEST"] to get Role.GUEST
        return Role[role_str]
    except KeyError:
        # If the role name doesn't exist in the enum, return None
        # This handles invalid roles like "admin" or "superuser"
        return None


def has_permission(user: Dict, required_role: Role) -> bool:
    """
    Checks if a user has permission to perform an action based on role hierarchy.

    This function implements the core logic of RBAC: checking if someone's role
    is high enough to do something. It uses the numeric values from the Role enum
    to determine if a user has sufficient privileges.

    The hierarchy allows higher roles to do everything lower roles can do:
    - High Table (3) can do Concierge (2) and Guest (1) actions
    - Concierge (2) can do Guest (1) actions
    - Guest (1) can only do Guest actions

    Args:
        user: A dictionary containing user info, must have a 'role' key
              Example: {'username': 'John', 'role': 'guest'}
        required_role: The minimum role needed (as a Role enum)

    Returns:
        True if the user has permission (their role is >= required role)
        False if the user doesn't have permission or has an invalid role

    Examples:
        guest_user = {'username': 'John', 'role': 'guest'}
        has_permission(guest_user, Role.GUEST) returns True
        has_permission(guest_user, Role.CONCIERGE) returns False

        manager = {'username': 'Winston', 'role': 'high_table'}
        has_permission(manager, Role.GUEST) returns True (managers can do guest things)
    """
    # Get the user's role from their data, default to 'guest' if not found
    # This makes the system fail-safe: unknown users get minimal permissions
    user_role_str = user.get('role', 'guest')

    # Convert the string role to a Role enum so we can work with it
    user_role = get_role_from_string(user_role_str)

    # If the conversion failed (invalid role), deny access for security
    # Better to be safe and deny access than risk allowing invalid permissions
    if user_role is None:
        return False

    # Check if the user's role value is high enough
    # Example: If user is CONCIERGE (2) and required is GUEST (1):
    #          2 >= 1 is True, so permission granted
    # Example: If user is GUEST (1) and required is CONCIERGE (2):
    #          1 >= 2 is False, so permission denied
    return user_role.value >= required_role.value


def require_role(required_role_str: str):
    """
    Decorator that protects functions by requiring a specific role.

    A decorator is a special function that "wraps" another function to add
    extra behavior. This decorator adds permission checking before running
    the protected function.

    This is a three-level nested function (advanced Python pattern):
    Level 1 (require_role): Takes the configuration - which role is required
    Level 2 (decorator): Takes the function to protect
    Level 3 (wrapper): Runs each time the protected function is called

    Think of it like security checkpoints:
    - Level 1: Sets up the checkpoint rules ("only concierge and above")
    - Level 2: Attaches the checkpoint to a specific door (function)
    - Level 3: Checks each person who tries to go through the door

    Usage:
        @require_role('concierge')
        def access_staff_area(user):
            return "Welcome to staff area!"

        # Now when someone calls access_staff_area(user):
        # 1. Wrapper checks if user has 'concierge' role
        # 2. If yes: runs the function and returns result
        # 3. If no: returns error message, never runs function

    Args:
        required_role_str: The role required to use the function (e.g., "concierge")

    Returns:
        A decorator function that can be applied to other functions
    """
    # Level 2: This function receives the function we're protecting
    def decorator(func):
        # @wraps preserves the original function's name and documentation
        # Without this, the wrapped function would look like "wrapper" in error messages
        @wraps(func)
        # Level 3: This function runs every time someone calls the protected function
        def wrapper(user, *args, **kwargs):
            # Convert the required role string to a Role enum
            # This happens once per call to validate the role requirement
            required_role = get_role_from_string(required_role_str)

            # If the role string was invalid, return an error
            # This catches configuration mistakes (like @require_role('admin'))
            if required_role is None:
                return f"❌ Invalid role: {required_role_str}"

            # Check if the user has permission using our permission hierarchy
            # This is where the actual security check happens
            if not has_permission(user, required_role):
                # User doesn't have permission - deny access with clear message
                return f"❌ Access denied. Requires {required_role_str} role."

            # User has permission - run the original function with all its arguments
            # *args and **kwargs pass through any additional parameters
            return func(user, *args, **kwargs)

        # Return the wrapper function that replaces the original
        return wrapper
    # Return the decorator function
    return decorator


# =============================================================================
# Example Protected Functions (Demonstration of the Authorization System)
# =============================================================================
# These functions demonstrate how the @require_role decorator works in practice.
# Each function is protected by different role requirements, showing the hierarchy.


# Example 1: Guest-level access (lowest level - everyone can access)
# Any authenticated user can call this, even those with just guest privileges
@require_role('guest')
def view_guest_rooms(user):
    """Shows available guest rooms. Accessible to all users."""
    return f"✓ {user['username']} viewing available guest rooms"


# Example 2: Concierge-level access (staff only)
# Only users with concierge or high_table roles can call this
# Guest users will be denied access
@require_role('concierge')
def access_concierge_desk(user):
    """Accesses concierge services. Requires concierge role or higher."""
    return f"✓ {user['username']} accessing concierge services"


# Example 3: High Table-level access (management only)
# Only users with high_table role can call this
# Both guest and concierge users will be denied access
@require_role('high_table')
def access_armory(user):
    """Enters the Continental armory. Requires high_table role."""
    return f"✓ {user['username']} entering the Continental armory"


# Example 4: Another High Table function (demonstrates multiple protected functions)
@require_role('high_table')
def view_all_members(user):
    """Views all Continental members. Requires high_table role."""
    return f"✓ {user['username']} viewing all Continental members"

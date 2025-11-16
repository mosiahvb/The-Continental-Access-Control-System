#!/usr/bin/env python3
"""
The Continental Hotel Access Control System - Complete CLI Application

This is the main entry point that integrates all authentication, authorization,
session management, 2FA, and audit logging components into a cohesive user experience.

Think of this as the "front desk" of The Continental Hotel - it's where users
interact with all the security systems we've built. This CLI (Command Line Interface)
brings together all the separate security modules into one complete application.

Author: Continental Security Team
Theme: John Wick Continental Hotel
"""

# ==================== IMPORTS ====================
# These are all the Python libraries and our custom modules we need

import os  # For operating system operations like clearing the screen
import sys  # For system operations like exiting the program
import getpass  # For hiding password input when users type
from typing import Optional, Dict  # For type hints to make code clearer
import datetime  # For working with dates and times

# Import all our custom security modules
# We use try/except to handle both direct execution and package imports
# This makes the code work whether you run it directly or import it as a module
try:
    # Try direct imports first (when running the file directly)
    import database as db
    import auth
    import login
    import authorization as authz
    import session
    import two_factor as tfa
    import audit_log as audit
except ImportError:
    # If that fails, try relative imports (when importing as a package)
    from . import database as db
    from . import auth
    from . import login
    from . import authorization as authz
    from . import session
    from . import two_factor as tfa
    from . import audit_log as audit


# ==================== MAIN CLI CLASS ====================

class ContinentalCLI:
    """
    Main CLI Application for The Continental Access Control System

    This class manages the entire user interface for The Continental's security system.
    Think of it as the "control center" that coordinates all the security features:
    - User registration and login
    - Session management (keeping track of who's logged in)
    - Access control (making sure users can only do what they're allowed to)
    - 2FA setup and verification
    - Audit logging (recording what users do)

    The class maintains three key pieces of state information:
    - current_user: Information about who is logged in (username, role, etc.)
    - current_token: A security token that proves the user is authenticated
    - session_active: A flag that tells us if someone is currently logged in
    """

    def __init__(self):
        """
        Initialize the CLI application

        This is the constructor - it runs when we create a new ContinentalCLI object.
        It sets up the initial state (nobody logged in) and prepares the databases.

        State variables explained:
        - current_user: Stores user info when someone logs in (None means nobody is logged in)
        - current_token: A JWT token that proves the user authenticated successfully
        - session_active: A boolean flag - True when someone is logged in, False otherwise
        """
        # Nobody is logged in when we start, so everything is None/False
        self.current_user: Optional[Dict] = None
        self.current_token: Optional[str] = None
        self.session_active = False

        # Initialize databases - make sure all tables exist
        self._init_databases()

    def _init_databases(self):
        """
        Initialize all database tables

        This ensures that all the database tables we need are created before
        anyone tries to use them. We call this at startup to avoid errors later.

        Steps:
        1. Initialize the main user database (for storing usernames, passwords, roles)
        2. Initialize the audit log database (for recording all security events)
        3. Add the 2FA column to the user table if it doesn't already exist
        """
        # Create the main users table
        db.init_database()

        # Create the audit log table
        audit.init_log_database()

        # Add 2FA support to the database
        # We use try/except because the column might already exist from a previous run
        try:
            tfa.add_2fa_column_to_database()
        except:
            # If this fails, it's probably because the column already exists
            # That's fine - we can just continue
            pass

    # ==================== UI HELPER METHODS ====================
    # These methods handle displaying information and getting input from users

    def clear_screen(self):
        """
        Clear the terminal screen

        This makes the interface cleaner by removing old text before showing new menus.
        We use different commands depending on the operating system:
        - Windows uses 'cls'
        - Mac/Linux use 'clear'
        """
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self):
        """
        Display The Continental Hotel banner

        This is purely cosmetic - it makes the application look professional
        and reinforces the John Wick theme. We use ASCII art with box-drawing
        characters to create a fancy header.
        """
        print("\n")
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║                                                           ║")
        print("║        🏨  THE CONTINENTAL HOTEL SECURITY SYSTEM          ║")
        print("║                                                           ║")
        print("║              'Weapons check required'                     ║")
        print("║         Where every assassin needs credentials            ║")
        print("║                                                           ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        print()

    def show_main_menu(self):
        """
        Display main menu options (for users who are NOT logged in)

        This is what users see when they first start the application.
        They can either login (if they have an account), register (to create
        a new account), or exit the program.
        """
        print("\n" + "=" * 60)
        print("MAIN MENU - Continental Access Control")
        print("=" * 60)
        print("\n1. Login to The Continental")
        print("2. Register as New Assassin")
        print("3. Exit System")
        print("\n" + "=" * 60)

    def show_authenticated_menu(self):
        """
        Display menu for authenticated users (users who ARE logged in)

        Once someone logs in successfully, they see this menu instead.
        It shows their username and role at the top, then gives them options
        for things they can do while logged in (view profile, access services, etc.).
        """
        print("\n" + "=" * 60)
        # Show who's logged in and their role
        print(f"AUTHENTICATED - Welcome {self.current_user['username']}")
        print(f"Role: {self.current_user['role'].upper()}")
        print("=" * 60)
        print("\n1. View My Profile")
        print("2. Access Continental Services")
        print("3. Security & 2FA Settings")
        print("4. View My Activity Log")
        print("5. Logout")
        print("\n" + "=" * 60)

    def show_services_menu(self):
        """
        Display available Continental services based on user's role

        This is where role-based access control (RBAC) becomes visible to users.
        The menu dynamically changes based on what role the user has:

        - Guest: Can see basic guest services (rooms, assistance)
        - Concierge: Can also see staff services (concierge desk, guest management)
        - High Table: Can see everything including admin services (member list, armory, audit logs)

        We check the user's role and only show menu options they have permission to access.
        This prevents confusion - users won't see options they can't use.
        """
        # Convert the user's role string to a Role enum for comparison
        role = authz.get_role_from_string(self.current_user['role'])

        print("\n" + "=" * 60)
        print("CONTINENTAL SERVICES")
        print("=" * 60)

        # Everyone sees guest services (minimum access level)
        print("\n--- Guest Services (All Members) ---")
        print("1. View Guest Rooms")
        print("2. Request Continental Assistance")

        # Only Concierge and above see these options
        # We compare role values: Concierge=2, so anyone with value >= 2 sees this
        if role and role.value >= authz.Role.CONCIERGE.value:
            print("\n--- Concierge Services (Staff Only) ---")
            print("3. Access Concierge Desk")
            print("4. Manage Guest Requests")

        # Only High Table sees these options
        # High Table=3, so only users with value >= 3 see this section
        if role and role.value >= authz.Role.HIGH_TABLE.value:
            print("\n--- High Table Services (Management Only) ---")
            print("5. View All Continental Members")
            print("6. Access Continental Armory")
            print("7. Review Security Audit Logs")

        print("\n0. Back to Main Menu")
        print("=" * 60)

    def get_input(self, prompt: str) -> str:
        """
        Get user input with a prompt

        This is a helper method to make getting input consistent throughout the app.
        It adds a newline before the prompt for better formatting and strips whitespace
        from the user's input (removes extra spaces at the beginning or end).

        Args:
            prompt: The question or instruction to show the user

        Returns:
            The user's input as a string with whitespace removed
        """
        return input(f"\n{prompt}: ").strip()

    def get_password(self, prompt: str = "Password") -> str:
        """
        Get password input (hidden from view)

        This uses the getpass module to hide the password as the user types.
        When you type a password, you won't see the characters on screen - this
        prevents someone looking over your shoulder from seeing your password.

        Args:
            prompt: The password prompt to display

        Returns:
            The password the user typed (as a string)
        """
        return getpass.getpass(f"\n{prompt}: ")

    def pause(self, message: str = "Press Enter to continue..."):
        """
        Pause execution until user presses Enter

        This gives users time to read messages before the screen clears and
        shows the next menu. Without this, messages would flash by too quickly.

        Args:
            message: What to tell the user (default is "Press Enter to continue...")
        """
        input(f"\n{message}")

    def display_message(self, message: str, msg_type: str = "info"):
        """
        Display a formatted message with an appropriate symbol

        This makes messages more visually distinct and easier to understand.
        Different types of messages get different symbols:
        - Success: ✓ (checkmark)
        - Error: ✗ (X mark)
        - Info: ℹ (information symbol)
        - Warning: ⚠ (warning triangle)

        Args:
            message: The text to display
            msg_type: Type of message - "success", "error", "info", or "warning"
        """
        # Dictionary mapping message types to their symbols
        symbols = {
            "success": "✓",
            "error": "✗",
            "info": "ℹ",
            "warning": "⚠"
        }
        # Get the symbol for this message type (use bullet point if type is unknown)
        symbol = symbols.get(msg_type, "•")
        print(f"\n{symbol} {message}")

    # ==================== REGISTRATION ====================
    # This section handles new user registration

    def handle_registration(self):
        """
        Handle new user registration

        This walks a new user through the registration process:
        1. Get a username from the user
        2. Get a password (and confirmation to make sure they didn't make a typo)
        3. Validate the input (make sure nothing is empty, passwords match)
        4. Call the auth module to create the account
        5. Log the registration attempt in the audit log

        All security events (both successful and failed) are logged for monitoring.
        This helps detect suspicious activity like repeated registration attempts.
        """
        # Clear screen and show banner for a fresh start
        self.clear_screen()
        self.show_banner()

        print("\n" + "=" * 60)
        print("CONTINENTAL REGISTRATION - New Assassin Check-In")
        print("=" * 60)

        print("\nPlease provide your credentials for Continental membership.")

        # Step 1: Get username
        username = self.get_input("Choose Username (3-20 characters, alphanumeric)")

        # Validate username is not empty
        if not username:
            self.display_message("Username cannot be empty!", "error")
            # Log the failed attempt (username is "unknown" since they didn't provide one)
            audit.log_event(username or "unknown", "registration_attempt", False,
                          {"reason": "Empty username"})
            self.pause()
            return

        # Step 2: Get password
        password = self.get_password("Choose Password (minimum 8 characters)")

        # Validate password is not empty
        if not password:
            self.display_message("Password cannot be empty!", "error")
            audit.log_event(username, "registration_attempt", False,
                          {"reason": "Empty password"})
            self.pause()
            return

        # Step 3: Get password confirmation
        # This ensures the user didn't make a typo when entering their password
        password_confirm = self.get_password("Confirm Password")

        # Step 4: Verify passwords match
        if password != password_confirm:
            self.display_message("Passwords do not match!", "error")
            audit.log_event(username, "registration_attempt", False,
                          {"reason": "Password mismatch"})
            self.pause()
            return

        # Step 5: Attempt to create the account
        # The auth module will check if username is valid, password meets requirements, etc.
        success, message = auth.register_user(username, password)

        # Step 6: Show result to user and log the outcome
        if success:
            # Registration worked! Welcome the new user
            self.display_message(message, "success")
            self.display_message(f"Welcome to The Continental, {username}!", "success")
            # Log successful registration with details
            audit.log_registration(username, {"role": "guest", "registration_method": "cli"})
        else:
            # Registration failed - show why and log the failure
            self.display_message(f"Registration failed: {message}", "error")
            audit.log_event(username, "registration_attempt", False,
                          {"reason": message})

        # Pause so user can read the result before returning to main menu
        self.pause()

    # ==================== LOGIN ====================
    # This section handles user authentication with optional 2FA

    def handle_login(self):
        """
        Handle user login with optional 2FA verification

        This is the authentication flow - the process of proving you are who you say you are.
        The login process has multiple steps:

        1. Get username and password from user
        2. Verify credentials against the database
        3. If 2FA is enabled for this user, require a 2FA code
        4. Create a session token (JWT) to keep the user logged in
        5. Log the login attempt (success or failure)

        Security features:
        - Failed logins are logged for brute force detection
        - After 3 failed attempts, we warn the user
        - 2FA adds an extra layer of security (something you know + something you have)
        - Session tokens expire after a set time for security
        """
        # Clear screen and show banner
        self.clear_screen()
        self.show_banner()

        print("\n" + "=" * 60)
        print("CONTINENTAL LOGIN - Member Authentication")
        print("=" * 60)

        # Step 1: Get username
        username = self.get_input("Username")

        if not username:
            self.display_message("Username cannot be empty!", "error")
            self.pause()
            return

        # Step 2: Get password (hidden from view)
        password = self.get_password("Password")

        if not password:
            self.display_message("Password cannot be empty!", "error")
            self.pause()
            return

        # Step 3: Verify username and password
        # The login module checks if the credentials are correct
        success, user, message = login.authenticate_user(username, password)

        if not success:
            # Login failed - show error and log the failure
            self.display_message(f"Login failed: {message}", "error")
            audit.log_login_attempt(username, False, {"reason": message})

            # Security check: Look for brute force attacks
            # If there have been 3+ failed logins in the past hour, warn the user
            failed_attempts = audit.get_failed_login_attempts(username, hours=1)
            if failed_attempts >= 3:
                self.display_message(
                    f"WARNING: {failed_attempts} failed login attempts detected!",
                    "warning"
                )

            self.pause()
            return

        # Step 4: Check if 2FA (Two-Factor Authentication) is enabled
        # If the user has set up 2FA, they need to provide a 6-digit code
        if user.get('totp_secret'):
            print("\n" + "-" * 60)
            self.display_message("2FA is enabled for this account", "info")
            print("-" * 60)

            # Ask for the 6-digit code from their authenticator app
            totp_code = self.get_input("Enter 6-digit 2FA code from your authenticator app")

            # Verify the 2FA code is correct
            # The code changes every 30 seconds, so it must match the current time window
            if not tfa.verify_totp_code(user['totp_secret'], totp_code):
                # 2FA code was wrong - deny login
                self.display_message("Invalid 2FA code!", "error")
                audit.log_2fa_attempt(username, False, {"reason": "Invalid TOTP code"})
                audit.log_login_attempt(username, False, {"reason": "Invalid 2FA code"})
                self.pause()
                return

            # 2FA code was correct - log it
            audit.log_2fa_attempt(username, True, {"method": "TOTP"})

        # Step 5: Login successful! Set up the user's session
        # Store user information in the class state
        self.current_user = user

        # Create a session token (JWT) that proves the user is authenticated
        # This token will be checked on each action to ensure the session is still valid
        self.current_token = session.create_access_token(user)

        # Mark the session as active
        self.session_active = True

        # Step 6: Welcome the user
        self.display_message(f"Welcome back, {username}!", "success")
        self.display_message(f"Role: {user['role'].upper()}", "info")

        # Step 7: Log the successful login with details
        audit.log_login_attempt(username, True, {
            "role": user['role'],
            "2fa_used": bool(user.get('totp_secret')),
            "login_time": datetime.datetime.now().isoformat()
        })

        self.pause()

    # ==================== PROFILE ====================
    # This section handles viewing user profile information

    def view_profile(self):
        """
        Display current user's profile information

        Shows the user their account details:
        - Username and role
        - When they joined (created_at timestamp)
        - Whether 2FA is enabled
        - What permissions their role gives them

        This helps users understand their access level and security settings.
        """
        self.clear_screen()
        self.show_banner()

        print("\n" + "=" * 60)
        print("MY CONTINENTAL PROFILE")
        print("=" * 60)

        # Display basic user information
        print(f"\nUsername:     {self.current_user['username']}")
        print(f"Role:         {self.current_user['role'].upper()}")
        print(f"Member Since: {self.current_user['created_at']}")

        # Show 2FA status with a checkmark if enabled
        print(f"2FA Enabled:  {'Yes ✓' if self.current_user.get('totp_secret') else 'No'}")

        # Show what permissions this role has
        # Convert the role string to a Role enum for comparison
        user_role = authz.get_role_from_string(self.current_user['role'])
        if user_role:
            # Show access level as a number (1-3)
            print(f"\nAccess Level: {user_role.value} / 3")

            # List all permissions this role grants
            print("\nPermissions:")
            # Everyone has guest services (level 1)
            print("  ✓ Guest Services")
            # Concierge (level 2) and above get concierge services
            if user_role.value >= authz.Role.CONCIERGE.value:
                print("  ✓ Concierge Services")
            # High Table (level 3) gets everything
            if user_role.value >= authz.Role.HIGH_TABLE.value:
                print("  ✓ High Table Services")

        self.pause()

    # ==================== SERVICES ====================
    # This section handles the Continental services menu and role-gated features

    def handle_services(self):
        """
        Handle Continental services menu navigation

        This is the main hub for accessing different services based on the user's role.
        It's a loop that keeps showing the services menu until the user chooses to
        go back to the main menu.

        The menu dynamically adjusts based on role, but users can still try to access
        services above their level. When they do, the @require_role decorator will
        catch it and deny access - this demonstrates defense in depth (multiple layers
        of security).
        """
        # Keep showing the services menu until user chooses to go back
        while self.session_active:
            self.clear_screen()
            self.show_banner()
            self.show_services_menu()

            choice = self.get_input("Select service")

            # Route to the appropriate service based on user's choice
            # Options 1-2 are guest services (available to all)
            if choice == "1":
                self.access_guest_rooms()
            elif choice == "2":
                self.request_assistance()
            # Options 3-4 are concierge services (staff only)
            elif choice == "3":
                self.access_concierge_desk()
            elif choice == "4":
                self.manage_guest_requests()
            # Options 5-7 are high table services (management only)
            elif choice == "5":
                self.view_all_members()
            elif choice == "6":
                self.access_armory()
            elif choice == "7":
                self.review_audit_logs()
            # Option 0 exits the loop and returns to main menu
            elif choice == "0":
                break
            else:
                self.display_message("Invalid selection", "error")
                self.pause()

    # ==================== ROLE-GATED SERVICE METHODS ====================
    # These methods demonstrate the decorator pattern for access control
    # Each method has a @require_role decorator that checks permissions BEFORE the method runs

    @authz.require_role('guest')
    def access_guest_rooms(self, user):
        """
        Guest level service: View guest rooms

        This demonstrates the DECORATOR PATTERN for access control:

        1. The @authz.require_role('guest') decorator wraps this method
        2. When called, the decorator runs FIRST, checking if the user has 'guest' role or higher
        3. If authorized, the decorator calls this method and passes the user object
        4. If NOT authorized, the decorator stops execution and shows an error - this method never runs

        The 'user' parameter is automatically provided by the decorator, not by the caller.
        The decorator gets it from self.current_user and passes it to us.

        This is available to ALL roles (guest, concierge, high_table) because everyone
        is at least a guest level.
        """
        self.clear_screen()
        self.show_banner()
        print("\n" + "=" * 60)
        print("GUEST ROOMS - Available Accommodations")
        print("=" * 60)
        # Show available room types
        print("\n✓ Continental Suite - Premium")
        print("✓ Standard Suite - Comfortable")
        print("✓ Executive Suite - Luxurious")

        # Log that the user accessed this service
        audit.log_event(user['username'], 'view_guest_rooms', True,
                       {"service": "guest_rooms"})
        self.pause()

    @authz.require_role('guest')
    def request_assistance(self, user):
        """
        Guest level service: Request Continental assistance

        Uses the same decorator pattern as access_guest_rooms.
        All users can request assistance since everyone is at least 'guest' level.
        """
        self.clear_screen()
        self.show_banner()
        print("\n" + "=" * 60)
        print("CONTINENTAL ASSISTANCE")
        print("=" * 60)
        print("\n✓ Request logged with Concierge")
        print("✓ Someone will assist you shortly")

        # Log the assistance request
        audit.log_event(user['username'], 'request_assistance', True,
                       {"service": "assistance"})
        self.pause()

    @authz.require_role('concierge')
    def access_concierge_desk(self, user):
        """
        Concierge level service: Access concierge desk

        This requires 'concierge' role or higher. The decorator will DENY access if:
        - User has 'guest' role (level 1) - NOT high enough

        The decorator will ALLOW access if:
        - User has 'concierge' role (level 2) - exactly the required level
        - User has 'high_table' role (level 3) - higher than required level

        This demonstrates hierarchical role-based access control (RBAC).
        """
        self.clear_screen()
        self.show_banner()
        print("\n" + "=" * 60)
        print("CONCIERGE DESK - Staff Services")
        print("=" * 60)
        print("\n✓ Access granted to Concierge systems")
        print("✓ Guest management tools available")

        # Log concierge desk access
        audit.log_event(user['username'], 'access_concierge_desk', True,
                       {"service": "concierge_desk"})
        self.pause()

    @authz.require_role('concierge')
    def manage_guest_requests(self, user):
        """
        Concierge level service: Manage guest requests

        Another concierge-level service. Requires concierge role or higher.
        Staff members can see and manage requests from guests.
        """
        self.clear_screen()
        self.show_banner()
        print("\n" + "=" * 60)
        print("GUEST REQUEST MANAGEMENT")
        print("=" * 60)
        print("\n✓ Viewing pending guest requests...")
        print("✓ 3 requests pending")

        # Log guest management activity
        audit.log_event(user['username'], 'manage_guest_requests', True,
                       {"service": "guest_management"})
        self.pause()

    @authz.require_role('high_table')
    def view_all_members(self, user):
        """
        High Table level service: View all Continental members

        This requires 'high_table' role (level 3) - the HIGHEST level.
        Only management can see the complete member list, as it's sensitive information.

        The decorator will DENY access unless the user is 'high_table'.
        Even 'concierge' users cannot access this - they're level 2, we need level 3.

        This method also demonstrates database interaction - it fetches all users
        and displays them in a formatted table.
        """
        self.clear_screen()
        self.show_banner()
        print("\n" + "=" * 60)
        print("ALL CONTINENTAL MEMBERS - High Table Access")
        print("=" * 60)

        # Fetch all users from the database
        members = db.get_all_users()
        print(f"\nTotal Members: {len(members)}")

        # Create a formatted table header
        print("\n{:<20} {:<15} {:<25}".format("Username", "Role", "Member Since"))
        print("-" * 60)

        # Display each member's information in a table row
        for member in members:
            print("{:<20} {:<15} {:<25}".format(
                member['username'],
                member['role'],
                member['created_at']
            ))

        # Log this sensitive operation with the number of members viewed
        audit.log_event(user['username'], 'view_all_members', True,
                       {"service": "member_directory", "count": len(members)})
        self.pause()

    @authz.require_role('high_table')
    def access_armory(self, user):
        """
        High Table level service: Access Continental armory

        Highest level service - only high_table can access the armory.
        This is marked as a high-security operation in the audit log.

        In a real system, this might control access to sensitive resources
        like weapons inventory, classified documents, or admin tools.
        """
        self.clear_screen()
        self.show_banner()
        print("\n" + "=" * 60)
        print("CONTINENTAL ARMORY - High Table Only")
        print("=" * 60)
        print("\n✓ Armory access granted")
        print("✓ Weapons inventory available")
        print("\n⚠ All armory access is logged and monitored")

        # Log with high security level flag
        audit.log_event(user['username'], 'access_armory', True,
                       {"service": "armory", "security_level": "high"})
        self.pause()

    @authz.require_role('high_table')
    def review_audit_logs(self, user):
        """
        High Table level service: Review security audit logs

        Only management can view audit logs - these contain sensitive information
        about all user activities in the system.

        This method fetches recent logs from the audit database and displays them
        in a formatted table, showing who did what and when.

        Note: This is an example of a privileged operation that itself gets logged.
        When someone views the audit logs, that action is also recorded in the audit log!
        """
        self.clear_screen()
        self.show_banner()
        print("\n" + "=" * 60)
        print("SECURITY AUDIT LOGS - High Table Access")
        print("=" * 60)

        # Fetch the 20 most recent audit log entries
        logs = audit.get_logs(limit=20)

        print(f"\nShowing last {len(logs)} events")

        # Create table header for log display
        print("\n{:<20} {:<25} {:<20} {:<10}".format(
            "Username", "Timestamp", "Action", "Status"
        ))
        print("-" * 80)

        # Display each log entry
        for log in logs:
            # Show checkmark for success, X for failure
            status = "✓" if log['success'] else "✗"
            print("{:<20} {:<25} {:<20} {:<10}".format(
                log['username'][:19],  # Truncate long usernames to fit
                str(log['timestamp'])[:24],  # Truncate timestamp to fit
                log['action'][:19],  # Truncate long action names to fit
                status
            ))

        # Log that someone viewed the audit logs (meta-logging!)
        audit.log_event(user['username'], 'review_audit_logs', True,
                       {"service": "audit_review", "logs_viewed": len(logs)})
        self.pause()

    # ==================== 2FA SETTINGS ====================
    # This section handles Two-Factor Authentication setup and management

    def handle_2fa_settings(self):
        """
        Handle 2FA setup and management menu

        Two-Factor Authentication (2FA) adds an extra layer of security.
        Instead of just username + password (one factor), users also need
        a 6-digit code from their phone (second factor).

        This menu lets users:
        - Enable 2FA if they don't have it yet
        - Disable 2FA if they want to turn it off

        The menu options change based on whether 2FA is currently enabled.
        """
        self.clear_screen()
        self.show_banner()

        print("\n" + "=" * 60)
        print("TWO-FACTOR AUTHENTICATION (2FA) SETTINGS")
        print("=" * 60)

        # Check if user has 2FA enabled
        # If they have a totp_secret stored, 2FA is enabled
        has_2fa = bool(self.current_user.get('totp_secret'))

        # Show current status
        print(f"\n2FA Status: {'Enabled ✓' if has_2fa else 'Disabled'}")

        # Show appropriate options based on current state
        if has_2fa:
            # User has 2FA - offer to disable it
            print("\n1. Disable 2FA")
            print("0. Back")

            choice = self.get_input("Select option")

            if choice == "1":
                self.disable_2fa()
        else:
            # User doesn't have 2FA - offer to enable it
            print("\n1. Enable 2FA")
            print("0. Back")

            choice = self.get_input("Select option")

            if choice == "1":
                self.enable_2fa()

    def enable_2fa(self):
        """
        Enable 2FA for current user

        This walks the user through setting up TOTP (Time-based One-Time Password)
        authentication. The process:

        1. Generate a secret key unique to this user
        2. Create a QR code that encodes this secret
        3. User scans the QR code with Google Authenticator (or similar app)
        4. App generates 6-digit codes that change every 30 seconds
        5. User must enter a code each time they login

        The secret key is what links the user's account to their authenticator app.
        It must be kept secret - if someone else gets it, they can generate valid codes!
        """
        self.clear_screen()
        self.show_banner()

        print("\n" + "=" * 60)
        print("ENABLE TWO-FACTOR AUTHENTICATION")
        print("=" * 60)

        print("\nSetting up 2FA for your Continental account...")

        # Generate secret and QR code for this user
        # Returns: success status, the secret key, and path to the QR code image
        success, secret, qr_path = tfa.enable_2fa_for_user(self.current_user['username'])

        if not success:
            self.display_message("Failed to enable 2FA!", "error")
            self.pause()
            return

        self.display_message("2FA has been enabled!", "success")

        # Show detailed setup instructions
        print("\n" + "=" * 60)
        print("SETUP INSTRUCTIONS")
        print("=" * 60)

        print(f"\n1. Open Google Authenticator or similar app on your phone")
        print(f"2. Scan the QR code saved to: {qr_path}")
        print(f"3. Or manually enter this secret: {secret}")
        print(f"\n4. Your app will generate 6-digit codes every 30 seconds")
        print(f"5. You'll need to enter a code each time you login")

        print("\n⚠ IMPORTANT: Save this secret key in a safe place!")
        print("   If you lose your phone, you'll need it to regain access.")

        # Update current user data to reflect the new 2FA status
        # We re-fetch from database to get the updated user object with the totp_secret
        self.current_user = db.get_user(self.current_user['username'])

        # Log the 2FA enablement
        audit.log_event(self.current_user['username'], 'enable_2fa', True,
                       {"method": "TOTP", "setup": "cli"})

        self.pause()

    def disable_2fa(self):
        """
        Disable 2FA for current user

        This removes 2FA protection from the account. Since this reduces security,
        we require explicit confirmation from the user (they must type 'CONFIRM').

        This prevents accidental disabling and makes the user think about the
        security implications of their choice.
        """
        self.clear_screen()
        self.show_banner()

        print("\n" + "=" * 60)
        print("DISABLE TWO-FACTOR AUTHENTICATION")
        print("=" * 60)

        # Warn the user about the security implications
        print("\n⚠ WARNING: This will reduce your account security!")

        # Require explicit confirmation
        # User must type exactly 'CONFIRM' (case-sensitive)
        confirm = self.get_input("Type 'CONFIRM' to disable 2FA")

        if confirm != "CONFIRM":
            # User changed their mind or didn't type it correctly
            self.display_message("2FA disable cancelled", "info")
            self.pause()
            return

        # Remove the TOTP secret from the user's account
        tfa.disable_2fa_for_user(self.current_user['username'])

        # Update current user data to reflect 2FA is now off
        self.current_user = db.get_user(self.current_user['username'])

        self.display_message("2FA has been disabled", "success")

        # Log the 2FA disabling
        audit.log_event(self.current_user['username'], 'disable_2fa', True,
                       {"method": "TOTP", "action": "disabled"})

        self.pause()

    # ==================== ACTIVITY LOG ====================
    # This section handles viewing user activity logs

    def view_my_activity(self):
        """
        View current user's activity log

        Shows the user a history of their recent actions in the system.
        This helps users:
        - See what they've been doing (useful for tracking their own activity)
        - Detect unauthorized access (if they see actions they didn't perform)

        We only show logs for the current user (their own activity), not everyone's.
        Only High Table users can view all logs through the review_audit_logs method.
        """
        self.clear_screen()
        self.show_banner()

        print("\n" + "=" * 60)
        print("MY ACTIVITY LOG")
        print("=" * 60)

        # Fetch the 15 most recent logs for this user
        # We filter by username so users only see their own activity
        logs = audit.get_logs(username=self.current_user['username'], limit=15)

        print(f"\nShowing last {len(logs)} activities")

        # Create table header
        print("\n{:<25} {:<25} {:<10}".format("Timestamp", "Action", "Status"))
        print("-" * 60)

        # Display each activity
        for log in logs:
            # Show checkmark for success, X for failure
            status = "✓" if log['success'] else "✗"
            print("{:<25} {:<25} {:<10}".format(
                str(log['timestamp'])[:24],  # Truncate timestamp
                log['action'][:24],  # Truncate action name
                status
            ))

        self.pause()

    # ==================== LOGOUT ====================
    # This section handles user logout

    def handle_logout(self):
        """
        Handle user logout

        Logging out is the process of ending a user's session. We need to:
        1. Log the logout event (for audit trail)
        2. Clear all session state (current_user, current_token, session_active)
        3. Inform the user they've been logged out

        After logout, the user returns to the main menu and must login again
        to access any services.
        """
        # Log the logout before clearing user data
        if self.current_user:
            audit.log_event(self.current_user['username'], 'logout', True,
                          {"logout_time": datetime.datetime.now().isoformat()})

        # Clear all session state
        # This effectively "forgets" that anyone was logged in
        self.current_user = None
        self.current_token = None
        self.session_active = False

        # Inform the user
        self.display_message("You have been logged out from The Continental", "success")
        self.pause()

    # ==================== MAIN APPLICATION LOOP ====================
    # This section contains the main loops that keep the application running

    def run_authenticated_session(self):
        """
        Main loop for authenticated users

        Once a user logs in successfully, they enter this loop. This loop:
        1. Verifies the session token is still valid (checks for expiration)
        2. Shows the authenticated user menu
        3. Handles the user's menu choices
        4. Continues until the user logs out or the session expires

        KEY SECURITY FEATURE: Token verification
        Before each action, we check if the session token is still valid.
        Tokens expire after a certain time (like 30 minutes). This means:
        - If you walk away from your computer, your session will eventually expire
        - An attacker can't use an old stolen token forever
        - Sessions automatically end if left inactive

        This is called "stateful session management" - we maintain and check
        the state (validity) of the session on each request.
        """
        # Keep showing the menu until session ends
        while self.session_active:
            # SECURITY CHECK: Verify the session token is still valid
            # This checks if the token has expired or been tampered with
            is_valid, user_data, message = session.verify_token(self.current_token)

            if not is_valid:
                # Token is invalid or expired - force logout
                self.display_message(f"Session expired: {message}", "warning")
                # Clear session state
                self.session_active = False
                self.current_user = None
                self.current_token = None
                self.pause()
                break  # Exit the loop and return to main menu

            # Token is valid - show the authenticated menu
            self.clear_screen()
            self.show_banner()
            self.show_authenticated_menu()

            # Get user's menu choice
            choice = self.get_input("Select option")

            # Route to the appropriate handler based on choice
            if choice == "1":
                self.view_profile()
            elif choice == "2":
                self.handle_services()
            elif choice == "3":
                self.handle_2fa_settings()
            elif choice == "4":
                self.view_my_activity()
            elif choice == "5":
                self.handle_logout()
            else:
                self.display_message("Invalid selection", "error")
                self.pause()

    def run(self):
        """
        Main application loop - the heart of the entire program

        This is the primary loop that keeps the application running. It works like this:

        1. Show welcome screen
        2. Enter infinite loop that continues until user exits
        3. Check if a user is logged in (session_active)
           - If YES: Run the authenticated session loop (logged-in menu)
           - If NO: Show the main menu (login/register/exit options)
        4. Handle user's choice and repeat

        This creates a state machine with two states:
        - Unauthenticated state: Show main menu (login, register, exit)
        - Authenticated state: Show authenticated menu (profile, services, logout)

        The application stays in whichever state matches the current session status.
        """
        # Show welcome screen
        self.clear_screen()
        self.show_banner()

        print("Welcome to The Continental Access Control System")
        print("Initializing security protocols...")

        self.pause("Press Enter to continue")

        # Main application loop - runs forever until user exits
        while True:
            # Check authentication state and show appropriate menu
            if self.session_active:
                # User is logged in - run authenticated session
                self.run_authenticated_session()
            else:
                # User is NOT logged in - show main menu
                self.clear_screen()
                self.show_banner()
                self.show_main_menu()

                # Get user's choice from main menu
                choice = self.get_input("Select option")

                # Handle the user's choice
                if choice == "1":
                    # User wants to login
                    self.handle_login()
                elif choice == "2":
                    # User wants to register
                    self.handle_registration()
                elif choice == "3":
                    # User wants to exit - show goodbye message and break the loop
                    self.display_message("Goodbye, assassin. Stay safe out there.", "info")
                    # Log system shutdown
                    audit.log_event("system", "shutdown", True,
                                  {"shutdown_time": datetime.datetime.now().isoformat()})
                    break  # Exit the infinite loop, ending the program
                else:
                    # Invalid choice - show error and loop again
                    self.display_message("Invalid selection", "error")
                    self.pause()


# ==================== APPLICATION ENTRY POINT ====================

def main():
    """
    Entry point for the CLI application

    This function is called when the script is run. It:
    1. Creates a ContinentalCLI instance
    2. Starts the application by calling run()
    3. Handles any errors that occur during execution

    We wrap everything in a try/except block to handle:
    - Keyboard interrupts (Ctrl+C) - allows graceful exit
    - Unexpected errors - shows error message instead of crashing

    This is considered best practice for CLI applications.
    """
    try:
        # Create the CLI application instance and run it
        cli = ContinentalCLI()
        cli.run()
    except KeyboardInterrupt:
        # User pressed Ctrl+C to interrupt - exit gracefully
        print("\n\nSystem interrupted. Exiting...")
        sys.exit(0)
    except Exception as e:
        # Something unexpected went wrong - show error details
        print(f"\n\nCritical error: {e}")
        # Print full stack trace for debugging
        import traceback
        traceback.print_exc()
        sys.exit(1)


# ==================== SCRIPT EXECUTION ====================
# This is the standard Python pattern for making a script executable

if __name__ == "__main__":
    """
    This block runs when the script is executed directly (not imported as a module)

    IMPORTANT: This is NOT test code - it's the proper entry point for the application!

    In Python, when you run a script directly (python continental_cli.py), the special
    variable __name__ is set to "__main__". When you import the script as a module,
    __name__ is set to the module name instead.

    This pattern allows the script to be both:
    1. Run directly as a standalone application (calls main())
    2. Imported as a module by other scripts (doesn't auto-run, just defines the classes)

    This is standard Python practice and should NOT be removed.
    """
    main()

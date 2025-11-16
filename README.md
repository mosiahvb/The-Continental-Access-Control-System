# The Continental Access Control System

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         THE CONTINENTAL HOTEL SECURITY SYSTEM             ║
║                                                           ║
║              'Weapons check required'                     ║
║         Where every assassin needs credentials            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

## Table of Contents

1. [Project Overview](#project-overview)
2. [Core Features](#core-features)
3. [Architecture](#architecture)
4. [Installation & Setup](#installation--setup)
5. [Usage](#usage)
6. [Security Features](#security-features)
7. [Future Enhancements](#future-enhancements)

---

## Project Overview

### What Is This Project?

Imagine the secret hotel from John Wick - only the world's most dangerous assassins can get in. **The Continental Access Control System** is a digital recreation of that hotel's security system, built as a command-line application with real-world enterprise security features.

This project simulates a secure access control system where users can:
- Register for membership
- Login with secure credentials
- Access services based on their role (Guest, Concierge, or High Table)
- Enable two-factor authentication for extra security
- Have all their actions tracked in an encrypted audit log

### The John Wick Theme

The project uses the Continental Hotel universe as its theme:
- **Users = Assassins** - Members of the Continental Hotel network
- **Roles = Guest / Concierge / High Table** - Hierarchy of access levels
- **Gold Coins = JWT Tokens** - Digital tokens that prove identity
- **Services = Hotel Amenities** - Features gated by role permissions

### Real-World Applications

While themed around John Wick, this system demonstrates real security concepts used by:
- Corporate employee login systems
- Banking applications
- Healthcare patient portals
- Government access control systems
- Any system requiring authentication, authorization, and auditing

---

## Core Features

### Implemented Features

#### 1. User Authentication (auth.py)
- **Password Hashing with bcrypt**: Passwords are never stored in plain text - they're hashed using bcrypt with automatic salt generation
- **Username Validation**: Enforces 3-20 character usernames with alphanumeric characters only
- **Password Strength Requirements**: Minimum 8 characters (industry standard)
- **Secure Registration**: Complete user registration with validation and database storage

#### 2. Login System (login.py)
- **Credential Verification**: Validates username and password against database
- **Timing Attack Prevention**: `authenticate_user_secure()` function prevents attackers from discovering valid usernames by timing response delays
- **Generic Error Messages**: Returns same error for "user not found" and "wrong password" to prevent username enumeration

#### 3. Session Management (session.py)
- **JWT Token Generation**: Creates signed JSON Web Tokens for authenticated users
- **Token Expiration**: Tokens expire after 30 minutes for security
- **Token Verification**: Validates tokens on each request to ensure session is still valid
- **Token Refresh**: Allows renewing expired tokens without full re-authentication
- **Payload Encryption**: JWT contains username, role, issued time, and expiration

#### 4. Two-Factor Authentication (two_factor.py)
- **TOTP Implementation**: Time-based One-Time Password using pyotp library
- **QR Code Generation**: Creates scannable QR codes for easy setup with authenticator apps
- **App Compatibility**: Works with Google Authenticator, Authy, Microsoft Authenticator, etc.
- **Secret Key Management**: Generates and stores unique secrets per user
- **Login Integration**: Seamlessly integrated into login flow when enabled
- **Enable/Disable Capability**: Users can turn 2FA on or off via settings menu

#### 5. Role-Based Access Control (authorization.py)
- **Three-Tier Role Hierarchy**:
  - **Guest (Level 1)**: Basic access to public services
  - **Concierge (Level 2)**: Staff access to management tools
  - **High Table (Level 3)**: Full administrative access
- **Hierarchical Permissions**: Higher roles automatically inherit lower role permissions
- **Decorator Pattern**: `@require_role()` decorator protects functions from unauthorized access
- **Permission Checking**: `has_permission()` function validates user roles against requirements
- **Role Validation**: Converts string roles to enum for type-safe comparisons

#### 6. Encrypted Audit Logging (audit_log.py)
- **Fernet Encryption**: All sensitive log details encrypted using Fernet symmetric encryption
- **Persistent Encryption Key**: Key stored in file for cross-session decryption
- **Comprehensive Event Logging**:
  - Login attempts (successful and failed)
  - User registrations
  - Permission denied events
  - 2FA attempts
  - Service access
  - Logout events
- **Brute Force Detection**: Tracks failed login attempts to identify attack patterns
- **Timestamps**: High-precision timestamps (microsecond accuracy) for all events
- **Log Querying**: Filter logs by username, action type, and time limit
- **Decryption on Read**: Logs automatically decrypted when retrieved

#### 7. Database Management (database.py)
- **SQLite Database**: Lightweight, serverless database for user storage
- **User Table Schema**:
  - id (auto-incrementing primary key)
  - username (unique, not null)
  - password_hash (bcrypt hash)
  - role (guest/concierge/high_table)
  - totp_secret (for 2FA)
  - created_at (timestamp)
- **Parameterized Queries**: All database queries use parameterized statements to prevent SQL injection
- **Connection Management**: Proper connection opening/closing to prevent resource leaks
- **Row Factory**: Returns database rows as dictionaries for easy access by column name

#### 8. Command-Line Interface (continental_cli.py)
- **Interactive Menu System**: Clean, user-friendly menus for all operations
- **State Management**: Tracks current user, session token, and authentication state
- **Session Loop**: Authenticated users stay in session until logout or token expiration
- **Dynamic Menus**: Service menus change based on user's role
- **Password Hiding**: Uses getpass to hide password input
- **Screen Clearing**: Clears terminal for clean UI between screens
- **ASCII Art Banner**: Professional-looking Continental Hotel branding
- **Error Handling**: Handling of keyboard interrupts and exceptions

---

## Architecture

### System Components

The Continental Access Control System is built as a modular, layered architecture with 8 core modules:

```
┌─────────────────────────────────────────────────────────┐
│                  continental_cli.py                     │
│              (User Interface Layer)                     │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Authentication Layer                                   │
│  ├── auth.py        (Registration, password hashing)    │
│  ├── login.py       (Login verification)                │
│  ├── session.py     (JWT tokens)                        │
│  └── two_factor.py  (TOTP 2FA)                          │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Authorization Layer                                    │
│  └── authorization.py  (RBAC, role checking)            │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Data & Audit Layer                                     │
│  ├── database.py    (User data storage)                 │
│  └── audit_log.py   (Encrypted event logging)           │
└─────────────────────────────────────────────────────────┘
```

### How Components Work Together

1. **User Interaction** → User interacts with `continental_cli.py` (CLI menus)

2. **Registration Flow**:
   - CLI calls `auth.register_user()`
   - Auth validates input and hashes password with bcrypt
   - Database stores user with default "guest" role
   - Audit log records registration event

3. **Login Flow**:
   - CLI calls `login.authenticate_user()`
   - Login verifies credentials against database
   - If 2FA enabled, `two_factor.verify_totp_code()` checks code
   - Session creates JWT token with `session.create_access_token()`
   - Audit log records login attempt (success/failure)

4. **Authorization Flow**:
   - User attempts to access a service
   - Service method has `@require_role()` decorator
   - Decorator checks if user's role ≥ required role
   - If authorized: service runs, event logged
   - If denied: error shown, permission denied logged

5. **Audit Flow**:
   - All security events logged to `audit_log.py`
   - Sensitive details encrypted with Fernet
   - Logs stored in separate SQLite database
   - High Table users can view decrypted logs

### Security Layers Diagram

```
Layer 1: Physical Access     [Terminal/Computer]
           ↓
Layer 2: Authentication       [Username + Password]
           ↓
Layer 3: Two-Factor          [TOTP Code from Phone]
           ↓
Layer 4: Session Token       [JWT Token Verification]
           ↓
Layer 5: Authorization       [Role-Based Access Control]
           ↓
Layer 6: Audit Logging       [Encrypted Event Recording]
```

---

## Installation & Setup

### Prerequisites

- **Python 3.8 or higher**
- **pip** (Python package manager)
- **Terminal/Command Line** access

### Installation Steps

1. **Clone or Download the Project**
   ```bash
   cd "The Continental Access Control p2"
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

   This installs:
   - `bcrypt` - Password hashing
   - `PyJWT` - JWT token creation/verification
   - `pyotp` - TOTP two-factor authentication
   - `qrcode` - QR code generation for 2FA
   - `cryptography` - Fernet encryption for audit logs
   - `pytest` - Testing framework (optional)

3. **Initialize Databases**

   The databases are created automatically on first run, but you can initialize them manually:
   ```bash
   python -c "import final_project.database as db; import final_project.audit_log as audit; db.init_database(); audit.init_log_database()"
   ```

4. **Run the Application**
   ```bash
   cd final_project
   python continental_cli.py
   ```

### First-Time Setup

When you run the application for the first time:

1. **Database Creation**: `continental.db` is created for user data
2. **Audit Log Database**: `continental_logs.db` is created for audit logs
3. **Encryption Key**: `continental_encryption.key` is generated for log encryption

**IMPORTANT**: Keep `continental_encryption.key` safe! If you lose it, all audit logs become permanently unreadable.

---

## Usage

### Registration

1. Run the application
2. Select "2. Register as New Assassin"
3. Choose a username (3-20 alphanumeric characters)
4. Choose a password (minimum 8 characters)
5. Confirm your password
6. You're registered as a "Guest" by default

```
CONTINENTAL REGISTRATION - New Assassin Check-In
══════════════════════════════════════════════════

Choose Username (3-20 characters, alphanumeric): JohnWick

Choose Password (minimum 8 characters): ********

Confirm Password: ********

✓ User 'JohnWick' registered successfully!
✓ Welcome to The Continental, JohnWick!
```

### Login (Without 2FA)

1. Select "1. Login to The Continental"
2. Enter your username
3. Enter your password
4. You're logged in!

```
CONTINENTAL LOGIN - Member Authentication
══════════════════════════════════════════════════

Username: JohnWick

Password: ********

✓ Welcome back, JohnWick!
ℹ Role: GUEST
```

### Login (With 2FA)

1. Select "1. Login to The Continental"
2. Enter your username
3. Enter your password
4. Enter the 6-digit code from your authenticator app
5. You're logged in!

```
CONTINENTAL LOGIN - Member Authentication
══════════════════════════════════════════════════

Username: JohnWick

Password: ********

──────────────────────────────────────────────────
ℹ 2FA is enabled for this account
──────────────────────────────────────────────────

Enter 6-digit 2FA code from your authenticator app: 123456

✓ Welcome back, JohnWick!
ℹ Role: GUEST
```

### Setting Up Two-Factor Authentication

1. After logging in, select "3. Security & 2FA Settings"
2. Select "1. Enable 2FA"
3. A QR code image is saved to your directory (e.g., `JohnWick_2fa_qr.png`)
4. Open Google Authenticator or similar app on your phone
5. Scan the QR code (or manually enter the secret key shown)
6. Your app will generate 6-digit codes every 30 seconds
7. On future logins, you'll need to enter the current code

```
ENABLE TWO-FACTOR AUTHENTICATION
══════════════════════════════════════════════════

✓ 2FA has been enabled!

══════════════════════════════════════════════════
SETUP INSTRUCTIONS
══════════════════════════════════════════════════

1. Open Google Authenticator or similar app on your phone
2. Scan the QR code saved to: JohnWick_2fa_qr.png
3. Or manually enter this secret: JBSWY3DPEHPK3PXP

4. Your app will generate 6-digit codes every 30 seconds
5. You'll need to enter a code each time you login

⚠ IMPORTANT: Save this secret key in a safe place!
   If you lose your phone, you'll need it to regain access.
```

### Accessing Services by Role

#### Guest Services (All Users)
- **View Guest Rooms**: Browse available accommodations
- **Request Continental Assistance**: Submit help requests

#### Concierge Services (Staff Only)
- **Access Concierge Desk**: Staff management interface
- **Manage Guest Requests**: View and handle guest requests

#### High Table Services (Management Only)
- **View All Continental Members**: See complete user directory
- **Access Continental Armory**: High-security area access
- **Review Security Audit Logs**: View all system activity logs

### Viewing Your Activity Log

1. From the authenticated menu, select "4. View My Activity Log"
2. See your last 15 activities with timestamps and status
3. Check for any suspicious activity you didn't perform

```
MY ACTIVITY LOG
══════════════════════════════════════════════════

Showing last 15 activities

Timestamp                 Action                    Status
────────────────────────────────────────────────────────────
2024-01-15 14:30:45      login_attempt             ✓
2024-01-15 14:30:30      view_guest_rooms          ✓
2024-01-15 14:28:12      enable_2fa                ✓
2024-01-15 14:25:00      login_attempt             ✗
```

### Logout

1. Select "5. Logout" from the authenticated menu
2. Your session ends and you return to the main menu
3. Logout event is recorded in audit logs

---

## Security Features

### 1. Password Hashing (bcrypt)

**What it is**: Bcrypt is a password hashing function designed specifically for secure password storage.

**How it works**:
- Passwords are NEVER stored in plain text
- Each password is hashed with a unique random salt
- Salt prevents rainbow table attacks (pre-computed hash tables)
- Bcrypt is intentionally slow to make brute force attacks expensive
- Each hash takes ~100ms, making millions of guesses impractical

**Example**:
```
Plain password: "mypassword123"
Stored hash:    "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
                 ↑    ↑         ↑                                          ↑
                 alg  cost     salt (22 chars)                    hash (31 chars)
```

**Security benefit**: Even if an attacker steals the database, they cannot reverse the hashes to get passwords.

### 2. Session Tokens (JWT)

**What it is**: JSON Web Tokens are secure, stateless tokens that prove a user's identity.

**How it works**:
- After successful login, a JWT token is created
- Token contains: username, role, issued time, expiration time
- Token is cryptographically signed to prevent tampering
- Token expires after 30 minutes
- Each request verifies the token is still valid

**Token Structure**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IkpvaG5XaWNrIiwicm9sZSI6Imd1ZXN0IiwiZXhwIjoxNzA1MzM0NDAwfQ.signature
│                                      │                                                                              │
└─ Header (algorithm & type)           └─ Payload (user data)                                                         └─ Signature
```

**Security benefit**:
- No need to store session data on server
- Tokens can't be forged without the secret key
- Automatic expiration prevents old stolen tokens from working forever
- Can be revoked or invalidated

### 3. Two-Factor Authentication (TOTP)

**What it is**: Time-based One-Time Passwords add a second layer of security beyond passwords.

**How it works**:
- User and server share a secret key
- Authenticator app generates 6-digit codes based on current time + secret
- Codes change every 30 seconds
- Login requires BOTH password (something you know) AND code (something you have)

**Code Generation Algorithm**:
```
Code = TOTP(secret_key, current_time)
     = HMAC-SHA1(secret, time_counter) % 1,000,000
```

**Security benefit**:
- Even if someone steals your password, they can't login without your phone
- Codes expire in 30 seconds, preventing reuse
- Protects against password-only compromises

**Attack scenario prevented**:
```
❌ WITHOUT 2FA:
Attacker steals password → Attacker logs in → Account compromised

✅ WITH 2FA:
Attacker steals password → Tries to log in → Doesn't have phone → Login fails
```

### 4. Encrypted Audit Logs (Fernet)

**What it is**: All audit log details are encrypted using Fernet symmetric encryption.

**How it works**:
- A master encryption key is generated and stored securely
- All sensitive log details are encrypted before storage
- Logs can only be read with the encryption key
- Uses AES-128 in CBC mode with HMAC authentication

**Encryption Example**:
```
Original log details:
{"ip": "192.168.1.100", "reason": "Invalid password"}

Encrypted storage:
"gAAAAABl7x8Q9yH3KpL_mN5oP6qR7sT8uV9wX0yZ1a2B3c4D5e6F7g8H9i0J..."

Decrypted on authorized read:
{"ip": "192.168.1.100", "reason": "Invalid password"}
```

**What's encrypted**:
- IP addresses
- Failure reasons
- Service details
- Any sensitive metadata

**What's NOT encrypted** (for efficient querying):
- Username
- Action type
- Timestamp
- Success/failure flag

**Security benefit**:
- Database theft doesn't expose sensitive log information
- Logs can't be tampered with (HMAC verification)
- Compliance with data protection regulations

### 5. Brute Force Detection

**What it is**: System monitors failed login attempts to detect attack patterns.

**How it works**:
- Every failed login is logged with timestamp
- System counts failures per user in last 24 hours
- After 3+ failures, user sees a warning
- Security team can be alerted for investigation

**Example Detection**:
```
Failed Login Timeline for "JohnWick":
14:25:00 - Failed (wrong password)
14:25:15 - Failed (wrong password)
14:25:30 - Failed (wrong password)
14:25:45 - Failed (wrong password)

⚠ WARNING: 4 failed login attempts detected!
```

**Security benefit**:
- Early detection of password guessing attacks
- Account owners alerted to unauthorized access attempts
- Can trigger automatic account locks or CAPTCHA
- Provides evidence for security investigations

### 6. Timing Attack Prevention

**What it is**: `authenticate_user_secure()` function prevents attackers from discovering valid usernames by measuring response time.

**The Problem**:
```
❌ VULNERABLE CODE:
If user doesn't exist:
   return immediately (0.001 seconds)

If user exists but password wrong:
   check password hash (0.100 seconds)

→ Attacker measures timing to find valid usernames!
```

**The Solution**:
```
✅ SECURE CODE:
If user doesn't exist:
   perform fake password check (0.100 seconds)
   return error

If user exists but password wrong:
   check real password hash (0.100 seconds)
   return error

→ Both take same time - can't tell which usernames exist!
```

**Security benefit**:
- Prevents username enumeration
- Makes reconnaissance harder for attackers
- Protects user privacy

### 7. Role-Based Access Control (RBAC)

**What it is**: Access permissions are based on user roles, not individual users.

**Role Hierarchy**:
```
High Table (Level 3)
    ↓ inherits all permissions from
Concierge (Level 2)
    ↓ inherits all permissions from
Guest (Level 1)
```

**How it works**:
- Each user is assigned ONE role
- Each service requires a MINIMUM role level
- System checks: user_level >= required_level
- Higher roles automatically get lower role permissions

**Authorization Check**:
```python
@require_role('concierge')  # Requires level 2
def access_concierge_desk(user):
    # This runs ONLY if user's role >= concierge

Guest (1) tries:     1 >= 2 → DENIED ❌
Concierge (2) tries: 2 >= 2 → ALLOWED ✓
High Table (3) tries: 3 >= 2 → ALLOWED ✓
```

**Security benefit**:
- Principle of least privilege (users only get needed access)
- Easy to manage (change role vs change individual permissions)
- Defense in depth (decorator + UI both enforce)
- Audit trail shows what access was attempted/used

### 8. SQL Injection Prevention

**What it is**: All database queries use parameterized statements to prevent SQL injection attacks.

**The Vulnerability**:
```python
❌ VULNERABLE CODE:
query = f"SELECT * FROM users WHERE username = '{username}'"
# If username = "admin' OR '1'='1", entire table returned!
```

**The Protection**:
```python
✅ SECURE CODE:
cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
# The ? placeholder is safely escaped by the database
# Special characters are treated as data, not SQL code
```

**Security benefit**:
- Prevents attackers from injecting malicious SQL
- Protects against data theft, modification, or deletion
- Standard security practice for all database operations

---

## Future Enhancements

#### Security Threat Dashboard
**What**: Implement the `analyze_security_threats()` function
**Why**: Automated threat detection and reporting

#### Rate Limiting
**What**: Limit how many requests per minute a user can make
**Why**: Prevent API abuse and DoS attacks

#### Web Interface (FastAPI)
**What**: Build web UI on top of existing modules (FastAPI is already in requirements.txt)
**Why**: More accessible than CLI, better user experience

---

## Conclusion

**The Continental Access Control System** successfully demonstrates a comprehensive understanding of cybersecurity principles and secure software development. The project goes beyond a simple login system to showcase production-quality security features including:

- Multi-layer authentication (password + optional 2FA)
- Enterprise-grade encryption (bcrypt, JWT, Fernet)
- Role-based access control with least privilege
- Comprehensive audit logging with attack detection
- Defense against common attacks (SQL injection, timing attacks, brute force)

The code is well-documented, modular, and educational - perfect for a portfolio project that demonstrates both technical skills and clear communication.


---

*"Welcome to The Continental. Enjoy your stay."*

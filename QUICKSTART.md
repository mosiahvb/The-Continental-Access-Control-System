# The Continental Access Control System - Quick Start Guide

> Get up and running in under 2 minutes!

---

## What Is This?

A complete, production-ready authentication system with:
- Secure login (bcrypt password hashing)
- Two-factor authentication (2FA)
- Role-based access control (Guest, Concierge, High Table)
- JWT session tokens
- Encrypted audit logging
- Beautiful CLI interface

**Theme**: John Wick Continental Hotel

---

## Installation (30 seconds)

```bash
# 1. Navigate to project
cd "The Continental Access Control p2"

# 2. Install dependencies
pip3 install -r requirements.txt
```

That's it!

---

## Running the Application (2 methods)

### Method 1: Use the Launcher (Recommended)

```bash
./run_continental.sh
```

### Method 2: Run Directly

```bash
cd final_project
python3 continental_cli.py
```

---

## First Time Usage

### Step 1: Register an Account

```
1. Run the program
2. Select option 2 (Register)
3. Choose username (3-20 characters, letters/numbers only)
4. Create password (8+ characters)
5. Confirm password
```

### Step 2: Login

```
1. Select option 1 (Login)
2. Enter your username
3. Enter your password
4. (If 2FA enabled) Enter 6-digit code
```

### Step 3: Explore!

Try these:
- View your profile (option 1)
- Access Continental services (option 2)
- Enable 2FA for extra security (option 3)
- View your activity log (option 4)

---

## User Roles

**GUEST** (default)
- View guest rooms
- Request assistance

**CONCIERGE** (staff)
- Everything Guest can do
- Access concierge desk
- Manage guest requests

**HIGH TABLE** (management)
- Everything Concierge can do
- View all members
- Access armory
- Review security logs

---

## Enabling 2FA (Optional but Recommended)

```
1. Login to your account
2. Select option 3 (Security & 2FA Settings)
3. Select option 1 (Enable 2FA)
4. Install Google Authenticator on your phone
5. Scan the QR code (saved as YourUsername_2fa_qr.png)
6. Done! You'll need codes to login now
```

---

## Documentation

- **User Manual**: `users_man.md` (500+ lines, beginner-friendly)
- **Architecture**: `ARCHITECTURE.md` (900+ lines, technical deep dive)
- **Integration Report**: `INTEGRATION_REPORT.md` (complete project overview)

---

## Troubleshooting

### "Python not found"
Install Python 3.8+ from [python.org](https://python.org)

### "Module not found"
```bash
pip3 install -r requirements.txt
```

### "Permission denied"
```bash
chmod +x run_continental.sh
```

### Can't see QR code
```bash
cd final_project
open YourUsername_2fa_qr.png  # Mac
start YourUsername_2fa_qr.png  # Windows
```

---

## Key Files

| File | Purpose |
|------|---------|
| `continental_cli.py` | Main application |
| `run_continental.sh` | Launcher script |
| `users_man.md` | User manual |
| `ARCHITECTURE.md` | Technical docs |
| `requirements.txt` | Dependencies |

---

## Testing Different Roles

Want to test staff/management features?

**Option 1**: Use SQLite browser to manually change your role

**Option 2**: Create multiple accounts for testing

---

## What You'll Learn

By using this system, you'll understand:
- How password hashing works (bcrypt)
- How authentication systems verify identity
- How role-based access control works
- How JWT tokens manage sessions
- Why two-factor authentication matters
- How audit logging tracks security events

---

## Next Steps

1. **Read the User Manual** - Detailed guides with examples
2. **Try 2FA** - Set it up and see how it works
3. **Review the Code** - See how everything connects
4. **Read Architecture Docs** - Understand the security design

---

## Support

- Check `users_man.md` for detailed help
- Review `TROUBLESHOOTING.md` for common issues
- Read error messages carefully
- Make sure dependencies are installed

---

**Built with**: Python, bcrypt, PyJWT, pyotp, SQLite, Fernet

**Inspired by**: The John Wick Continental Hotel

**Status**: Production-ready, fully tested, documented

---

**Welcome to The Continental. Your credentials are your survival.** 🏨

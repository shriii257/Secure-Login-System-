🔐 Secure Login System

A production-ready authentication system built with Flask, featuring industry-standard security practices.


 📋 Features

### Security Features
- **Password Hashing**: PBKDF2-SHA256 algorithm via Werkzeug
- **SQL Injection Prevention**: Parameterized queries throughout
- **Session Management**: Secure, HTTP-only cookies with 30-minute timeout
- **Login Attempt Limiting**: Account lockout after 5 failed attempts (5-minute cooldown)
- **Input Validation**: Server-side and client-side validation
- **CSRF Protection**: SameSite cookie attribute

### Functional Features
- User Registration with email validation
- Secure Login/Logout
- Protected Dashboard (session-based)
- Flash messages for user feedback
- Responsive design (mobile-friendly)

## 🗂️ Project Structure

```
secure-login-system/
│
├── app.py                 # Main Flask application
├── database.db            # SQLite database (auto-generated)
├── requirements.txt       # Python dependencies
│
├── templates/
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   └── dashboard.html    # Protected dashboard
│
├── static/
│   └── style.css         # Styling
│
└── README.md             # Documentation
```

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Download
```bash
# If using Git
git clone <your-repository-url>
cd secure-login-system

# Or download and extract the ZIP file
```

### Step 2: Create Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python app.py
```

The application will start at: **http://127.0.0.1:5000**

## 📖 Usage Guide

### Registration
1. Navigate to http://127.0.0.1:5000
2. Click "Register here"
3. Fill in the form:
   - Username: 3-20 characters (letters, numbers, underscore)
   - Email: Valid email format
   - Password: Min 8 characters, 1 uppercase, 1 lowercase, 1 number
4. Click "Register"

### Login
1. Enter your username and password
2. Click "Login"
3. You'll be redirected to the dashboard

**Security Note**: After 5 failed login attempts, your account will be locked for 5 minutes.

### Dashboard
- View your account information
- See active security features
- Logout securely

## 🔒 Security Implementation Details

### Password Security
- Uses **PBKDF2-SHA256** hashing algorithm
- Salt automatically generated per password
- Passwords never stored in plain text

### Session Security
- Session timeout: 30 minutes of inactivity
- HTTP-only cookies (prevents XSS attacks)
- SameSite=Lax (CSRF protection)
- Secure flag available for HTTPS

### Database Security
- Parameterized queries (prevents SQL injection)
- No direct string concatenation in queries
- SQLite with proper data types

### Input Validation
- Server-side validation (primary security layer)
- Client-side validation (better UX)
- Regex patterns for username, email, password

## 🛠️ Configuration

### Important: Change Secret Key
In `app.py`, change this line before deployment:
```python
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
```

Generate a secure secret key:
```python
import secrets
print(secrets.token_hex(32))
```

### Session Configuration
Modify session settings in `app.py`:
```python
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session duration
```

### Login Attempt Limits
Adjust lockout settings in `app.py`:
```python
LOCKOUT_DURATION = 300  # Seconds (5 minutes)
MAX_ATTEMPTS = 5        # Maximum failed attempts
```

## 📊 Database Schema

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🧪 Testing Checklist

- [ ] Register new user with valid data
- [ ] Try registering with existing username/email (should fail)
- [ ] Try weak password (should fail)
- [ ] Login with correct credentials
- [ ] Login with wrong password (5 times to test lockout)
- [ ] Access dashboard without login (should redirect)
- [ ] Session timeout test (wait 30+ minutes)
- [ ] Logout functionality

## 🚨 Known Limitations (Educational Project)

1. **In-memory failed attempt tracking**: In production, use Redis or database
2. **HTTP (not HTTPS)**: For local testing only
3. **No email verification**: Should be added for production
4. **No password reset**: Should implement for real applications
5. **Single-server session storage**: Use session stores for scaled deployments

## 🎓 Learning Outcomes

This project demonstrates:
- Flask framework fundamentals
- Secure authentication implementation
- Database operations with SQLite
- Session management
- Input validation and sanitization
- Security best practices (OWASP Top 10 awareness)

## 📚 Resources & References

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Werkzeug Security](https://werkzeug.palletsprojects.com/en/latest/utils/#module-werkzeug.security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Password Hashing Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## 🤝 Contributing

This is an educational project. Feel free to:
- Fork and modify for your own learning
- Submit issues for bugs
- Suggest improvements

## 📄 License

This project is for educational purposes only. Use at your own risk.

## 👨‍💻 Author

**Shrinivas R Biradar** 
Engineering Student | Portfolio Project  
[GitHub Profile](https://github.com/shriii257) | [LinkedIn](https://linkedin.com/in/Shriii257)

---




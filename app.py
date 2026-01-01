"""
Secure Login System - Flask Backend
Author: Engineering Student Portfolio Project
Description: A security-focused authentication system with session management
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
from datetime import timedelta, datetime
from functools import wraps

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'  # Change this in production!
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout: 30 minutes
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# Database configuration
DATABASE = 'database.db'

# Failed login tracking (in-memory storage for demo purposes)
# In production, use Redis or database with timestamp cleanup
failed_attempts = {}
LOCKOUT_DURATION = 300  # 5 minutes in seconds
MAX_ATTEMPTS = 5


def get_db_connection():
    """Create and return a database connection with row factory"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enables column access by name
    return conn


def init_db():
    """Initialize the database with users table"""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def login_required(f):
    """Decorator to protect routes that require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def validate_email(email):
    """Validate email format using regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """
    Validate password strength
    Requirements: At least 8 characters, 1 uppercase, 1 lowercase, 1 number
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"


def validate_username(username):
    """Validate username format (alphanumeric and underscore only)"""
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None


def is_account_locked(identifier):
    """Check if account is locked due to failed login attempts"""
    if identifier in failed_attempts:
        attempts, last_attempt_time = failed_attempts[identifier]
        
        # Check if lockout period has passed
        if datetime.now().timestamp() - last_attempt_time < LOCKOUT_DURATION:
            if attempts >= MAX_ATTEMPTS:
                return True
        else:
            # Reset attempts if lockout period has passed
            del failed_attempts[identifier]
    
    return False


def record_failed_attempt(identifier):
    """Record a failed login attempt"""
    current_time = datetime.now().timestamp()
    
    if identifier in failed_attempts:
        attempts, _ = failed_attempts[identifier]
        failed_attempts[identifier] = (attempts + 1, current_time)
    else:
        failed_attempts[identifier] = (1, current_time)


def reset_failed_attempts(identifier):
    """Clear failed login attempts after successful login"""
    if identifier in failed_attempts:
        del failed_attempts[identifier]


@app.route('/')
def index():
    """Home page - redirect to login or dashboard"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page and handler"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Input validation
        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return render_template('register.html')
        
        # Validate username format
        if not validate_username(username):
            flash('Username must be 3-20 characters (letters, numbers, underscore only)', 'danger')
            return render_template('register.html')
        
        # Validate email format
        if not validate_email(email):
            flash('Invalid email format!', 'danger')
            return render_template('register.html')
        
        # Validate password strength
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')
        
        # Hash the password
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            conn = get_db_connection()
            # Use parameterized query to prevent SQL injection
            conn.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            conn.commit()
            conn.close()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page and handler"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Input validation
        if not username or not password:
            flash('Please enter both username and password!', 'danger')
            return render_template('login.html')
        
        # Check if account is locked
        if is_account_locked(username):
            remaining_time = LOCKOUT_DURATION // 60  # Convert to minutes
            flash(f'Account locked due to multiple failed attempts. Try again in {remaining_time} minutes.', 'danger')
            return render_template('login.html')
        
        try:
            conn = get_db_connection()
            # Use parameterized query to prevent SQL injection
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            conn.close()
            
            # Verify user exists and password is correct
            if user and check_password_hash(user['password_hash'], password):
                # Successful login
                session.permanent = True  # Enable session timeout
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                # Reset failed attempts
                reset_failed_attempts(username)
                
                flash(f'Welcome back, {user["username"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Failed login
                record_failed_attempt(username)
                
                # Get remaining attempts
                attempts = failed_attempts.get(username, (0, 0))[0]
                remaining = MAX_ATTEMPTS - attempts
                
                if remaining > 0:
                    flash(f'Invalid credentials! {remaining} attempts remaining.', 'danger')
                else:
                    flash('Account locked due to multiple failed attempts.', 'danger')
                
                return render_template('login.html')
        
        except Exception as e:
            flash('An error occurred. Please try again.', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard - accessible only after login"""
    return render_template('dashboard.html', username=session['username'])


@app.route('/logout')
@login_required
def logout():
    """Logout handler - clear session"""
    username = session.get('username', 'User')
    session.clear()  # Clear all session data
    flash(f'Goodbye, {username}! You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Initialize database on first run
    init_db()
    
    # Run the Flask app
    # Debug mode should be False in production
    app.run(debug=True, host='127.0.0.1', port=5000)
import os
import re
import sqlite3
import time
import logging
import secrets
from flask import Flask, request, session, redirect, url_for, render_template, g, abort
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# VULNERABILITY: hardcoded secret key allowed anyone with repo access to forge session cookies.
# app.secret_key = 'super-insecure-hardcoded-secret'
# REMEDIATED: secret key now loaded from the SECRET_KEY env var (set it in production!).
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

DATABASE = 'bank.db'

# VULNERABILITY*: logging was configured to capture plaintext sensitive data.
# REMEDIATED: sink is fine (audit trail); call sites below now log metadata only, never secrets.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('bank.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Brute-force protection (in-memory, per-username)
# ---------------------------------------------------------------------------
# Trade-off: keyed by username rather than source IP. Per-IP lockout is porous behind NAT/shared
# proxies (one attacker can lock out every legitimate user behind the same IP) and is trivially
# bypassed by rotating source IPs. Per-username lockout directly protects the account being
# targeted regardless of where the attacker connects from, at the cost of letting an attacker who
# controls many usernames spread a credential-stuffing attempt across them. For a small banking
# app, protecting individual accounts is the priority. In-memory storage is fine at this scale but
# does not survive a process restart or scale across multiple worker processes — a real deployment
# should back this with Redis or a database table instead.
_failed_login_attempts = {}  # username -> list[timestamp of failed attempt]
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_WINDOW_SECONDS = 300  # 5 minutes


def _record_failed_login(username):
    now = time.time()
    attempts = [t for t in _failed_login_attempts.get(username, []) if now - t < LOGIN_LOCKOUT_WINDOW_SECONDS]
    attempts.append(now)
    _failed_login_attempts[username] = attempts


def _clear_failed_logins(username):
    _failed_login_attempts.pop(username, None)


def _is_locked_out(username):
    now = time.time()
    attempts = [t for t in _failed_login_attempts.get(username, []) if now - t < LOGIN_LOCKOUT_WINDOW_SECONDS]
    _failed_login_attempts[username] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


# ---------------------------------------------------------------------------
# Memo validation (defense in depth for the stored-XSS fields)
# ---------------------------------------------------------------------------
# Jinja2 autoescaping (see templates/transactions.html and templates/dashboard.html) is the actual
# XSS control — it neutralizes any HTML/JS in the memo regardless of what's stored. This validation
# is a secondary, defense-in-depth layer that rejects obviously hostile input before it ever reaches
# the database, and keeps memo content limited to what a transaction note should look like.
MEMO_MAX_LENGTH = 140
_MEMO_ALLOWED_RE = re.compile(r"^[\w \-.,!?@#&()'\":;/]*$")


def is_valid_memo(memo):
    return len(memo) <= MEMO_MAX_LENGTH and bool(_MEMO_ALLOWED_RE.match(memo))


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------
# VULNERABILITY: state-changing POST routes had no CSRF token verification.
# REMEDIATED: a per-session CSRF token is now required and checked on every POST.
def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = get_csrf_token


@app.before_request
def _enforce_csrf():
    if request.method == 'POST':
        expected = session.get('csrf_token')
        submitted = request.form.get('csrf_token')
        if not expected or not submitted or not secrets.compare_digest(expected, submitted):
            abort(400, description='Invalid or missing CSRF token.')


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT UNIQUE NOT NULL,
                password     TEXT NOT NULL,
                email        TEXT,
                display_name TEXT,
                balance      REAL DEFAULT 0.0
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL,
                type      TEXT NOT NULL,
                amount    REAL NOT NULL,
                memo      TEXT,
                timestamp TEXT NOT NULL
            );
        ''')

        # Seed two demo accounts so the app is immediately usable
        existing = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing == 0:
            # VULNERABILITY: seed accounts were inserted with raw plaintext passwords.
            # db.execute(
            #     "INSERT INTO users (username, password, email, display_name, balance) "
            #     "VALUES ('kobe@opensafe.com', 'password123', 'kobe@opensafe.com', 'Kobe', 5000.00)"
            # )
            # db.execute(
            #     "INSERT INTO users (username, password, email, display_name, balance) "
            #     "VALUES ('kira@opensafe.com', 'letmein', 'kira@opensafe.com', 'Kira', 1250.75)"
            # )
            # REMEDIATED: seed accounts now get hashed passwords too (demo creds still work).
            db.execute(
                "INSERT INTO users (username, password, email, display_name, balance) "
                "VALUES (?, ?, ?, ?, ?)",
                ('kobe@opensafe.com', generate_password_hash('password123'), 'kobe@opensafe.com', 'Kobe', 5000.00)
            )
            db.execute(
                "INSERT INTO users (username, password, email, display_name, balance) "
                "VALUES (?, ?, ?, ?, ?)",
                ('kira@opensafe.com', generate_password_hash('letmein'), 'kira@opensafe.com', 'Kira', 1250.75)
            )
            # Seed a couple of opening transactions
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            db.execute(
                "INSERT INTO transactions (user_id, type, amount, memo, timestamp) "
                "VALUES (1, 'deposit', 5000.00, 'Initial account funding', ?)", (now,)
            )
            db.execute(
                "INSERT INTO transactions (user_id, type, amount, memo, timestamp) "
                "VALUES (2, 'deposit', 1250.75, 'Opening balance transfer', ?)", (now,)
            )
            db.commit()
        else:
            # This repo's bank.db may already exist from a previous run of the vulnerable version,
            # with plaintext passwords on disk. Migrate any non-hashed password to a hash in place
            # so existing accounts keep working under the new check_password_hash() login path.
            _migrate_plaintext_passwords(db)


def _migrate_plaintext_passwords(db):
    rows = db.execute("SELECT id, password FROM users").fetchall()
    for row in rows:
        pw = row['password']
        if not pw.startswith(('pbkdf2:', 'scrypt:')):
            db.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(pw), row['id']))
    db.commit()


# ---------------------------------------------------------------------------
# Routes — Authentication
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username     = request.form['username']
        password     = request.form['password']
        email        = request.form.get('email', '')
        display_name = request.form.get('display_name', username)
        db = get_db()
        try:
            # VULNERABILITY: raw password was inserted into the database as-is.
            # db.execute(
            #     "INSERT INTO users (username, password, email, display_name, balance) "
            #     "VALUES (?, ?, ?, ?, 0.0)",
            #     (username, password, email, display_name)
            # )
            # REMEDIATED: password is now hashed (generate_password_hash) before storage.
            db.execute(
                "INSERT INTO users (username, password, email, display_name, balance) "
                "VALUES (?, ?, ?, ?, 0.0)",
                (username, generate_password_hash(password), email, display_name)
            )
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Username already taken. Please choose another.'
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # VULNERABILITY*: raw plaintext password was logged on every attempt.
        # logger.info(f"LOGIN ATTEMPT | username={username} | password={password}")
        # REMEDIATED: only username is logged now.
        logger.info(f"LOGIN ATTEMPT | username={username}")

        # VULNERABILITY*: no brute-force protection — every attempt was processed unconditionally.
        # REMEDIATED: a per-username failed-attempt counter has been added (see _is_locked_out above).
        if _is_locked_out(username):
            error = 'Too many failed login attempts for this account. Please try again in a few minutes.'
            logger.info(f"LOGIN BLOCKED | username={username} | reason=lockout")
            return render_template('login.html', error=error)

        db = get_db()

        # VULNERABILITY*: SQL injection — query was built by direct string concatenation.
        # query = (
        #     "SELECT * FROM users WHERE username = '"
        #     + username
        #     + "' AND password = '"
        #     + password
        #     + "'"
        # )
        # logger.debug(f"Executing SQL: {query}")
        # user = db.execute(query).fetchone()
        # REMEDIATED: query now uses a parameterized placeholder instead of concatenation.
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # REMEDIATED: password check now uses check_password_hash() instead of a plaintext comparison.
        if user and check_password_hash(user['password'], password):
            session['user_id']  = user['id']
            session['username'] = user['username']
            _clear_failed_logins(username)
            # VULNERABILITY*: password and balance were logged on successful login.
            # logger.info(f"LOGIN SUCCESS | username={username} | password={password} | balance={user['balance']}")
            # REMEDIATED: only the outcome is logged now.
            logger.info(f"LOGIN SUCCESS | username={username}")
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'
            _record_failed_login(username)
            # logger.info(f"LOGIN FAILURE | username={username} | password={password}")
            logger.info(f"LOGIN FAILURE | username={username}")

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    recent = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5",
        (session['user_id'],)
    ).fetchall()
    return render_template('dashboard.html', user=user, transactions=recent)


# ---------------------------------------------------------------------------
# Routes — Deposit
# ---------------------------------------------------------------------------

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    message = None
    error   = None
    if request.method == 'POST':
        try:
            db          = get_db()
            amount      = float(request.form['amount'])
            # VULNERABILITY: full card number and CVV were collected with no PCI-compliant handling.
            # card_number = request.form.get('card_number', '')
            # card_expiry = request.form.get('card_expiry', '')
            # card_cvv    = request.form.get('card_cvv', '')
            # REMEDIATED: server no longer accepts raw card data at all (use a PCI processor client-side).
            memo = request.form.get('memo', '')

            # VULNERABILITY*: memo was written to the database with no sanitization (stored XSS).
            # REMEDIATED: Jinja2 autoescaping is the real fix; this check is defense in depth.
            if not is_valid_memo(memo):
                error = 'Memo contains invalid characters or is too long (max %d).' % MEMO_MAX_LENGTH
            else:
                db.execute(
                    "INSERT INTO transactions (user_id, type, amount, memo, timestamp) "
                    "VALUES (?, 'deposit', ?, ?, ?)",
                    (session['user_id'], amount, memo, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                db.commit()
                message = f'Deposit of ${amount:,.2f} was successful.'
        except ValueError:
            error = 'Invalid amount entered.'

    return render_template('deposit.html', message=message, error=error)


# ---------------------------------------------------------------------------
# Routes — Transfer
# ---------------------------------------------------------------------------

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    message = None
    error   = None
    if request.method == 'POST':
        try:
            recipient_username = request.form['recipient']
            amount             = float(request.form['amount'])
            memo               = request.form.get('memo', '')

            db        = get_db()
            sender    = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            recipient = db.execute("SELECT * FROM users WHERE username = ?", (recipient_username,)).fetchone()

            # VULNERABILITY*: sender balance, amount, and memo were logged in plaintext.
            # logger.info(
            #     f"TRANSFER | from={session['username']} | from_balance={sender['balance']} "
            #     f"| to={recipient_username} | amount={amount} | memo={memo}"
            # )
            # REMEDIATED: only who transferred to whom is logged now.
            logger.info(f"TRANSFER ATTEMPT | from={session['username']} | to={recipient_username}")

            if not recipient:
                error = f'User "{recipient_username}" not found.'
            elif recipient['id'] == session['user_id']:
                error = 'You cannot transfer to yourself.'
            elif sender['balance'] < amount:
                error = f'Insufficient funds. Your balance is ${sender["balance"]:,.2f}.'
            elif amount <= 0:
                error = 'Transfer amount must be positive.'
            # REMEDIATED: invalid memo content is rejected before it's stored (defense in depth).
            elif not is_valid_memo(memo):
                error = 'Memo contains invalid characters or is too long (max %d).' % MEMO_MAX_LENGTH
            else:
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                db.execute(
                    "UPDATE users SET balance = balance - ? WHERE id = ?",
                    (amount, session['user_id'])
                )
                db.execute(
                    "UPDATE users SET balance = balance + ? WHERE id = ?",
                    (amount, recipient['id'])
                )
                # VULNERABILITY*: memo was written to the database with no sanitization (stored XSS).
                # REMEDIATED: Jinja2 autoescaping on render is the real fix; is_valid_memo() above is defense in depth.
                db.execute(
                    "INSERT INTO transactions (user_id, type, amount, memo, timestamp) "
                    "VALUES (?, 'transfer_out', ?, ?, ?)",
                    (session['user_id'], amount, memo, now)
                )
                db.execute(
                    "INSERT INTO transactions (user_id, type, amount, memo, timestamp) "
                    "VALUES (?, 'transfer_in', ?, ?, ?)",
                    (recipient['id'], amount, memo, now)
                )
                db.commit()
                logger.info(f"TRANSFER SUCCESS | from={session['username']} | to={recipient_username}")
                message = f'Successfully transferred ${amount:,.2f} to {recipient["display_name"]} (@{recipient_username}).'
        except ValueError:
            error = 'Invalid amount entered.'

    return render_template('transfer.html', message=message, error=error)


# ---------------------------------------------------------------------------
# Routes — Transaction history
# ---------------------------------------------------------------------------

@app.route('/transactions')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db   = get_db()
    rows = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        (session['user_id'],)
    ).fetchall()
    return render_template('transactions.html', transactions=rows)


# ---------------------------------------------------------------------------
# Routes — Profile
# ---------------------------------------------------------------------------

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    message = None
    db      = get_db()
    if request.method == 'POST':
        display_name = request.form.get('display_name', '')
        email        = request.form.get('email', '')
        db.execute(
            "UPDATE users SET display_name = ?, email = ? WHERE id = ?",
            (display_name, email, session['user_id'])
        )
        db.commit()
        message = 'Profile updated successfully.'
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    return render_template('profile.html', user=user, message=message)


# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    # VULNERABILITY: debug mode exposed Werkzeug's interactive debugger (RCE) on any exception.
    # app.run(debug=True, host='0.0.0.0', port=5000)
    # REMEDIATED: debug mode now defaults to off; enable via FLASK_DEBUG=1 for local dev only.
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)

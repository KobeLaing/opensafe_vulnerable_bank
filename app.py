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

# VULNERABILITY: Hardcoded secret key — session-signing key committed to source control; anyone
# with repo access can forge session cookies (e.g. set user_id to any account) offline.
# app.secret_key = 'super-insecure-hardcoded-secret'
# REMEDIATED: Hardcoded secret key — loaded from the SECRET_KEY environment variable. A real
# deployment MUST set this to a long random value (e.g. `python -c "import secrets; print(secrets.token_hex(32))"`)
# and never commit it. Falling back to a per-process random key keeps the app runnable for local
# demos without ever hardcoding a real secret, at the cost of invalidating sessions on restart.
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

DATABASE = 'bank.db'

# VULNERABILITY*: Sensitive data in logs — logging module set up to write plaintext sensitive data to file and stdout
# REMEDIATED: Sensitive data in logs — the sink itself (file + stdout) is fine for an audit trail;
# the fix is at each call site below, which now logs only non-sensitive metadata (username, action,
# success/failure) and never passwords, balances, memo content, or raw card data. Level dropped from
# DEBUG to INFO since the DEBUG call that leaked the raw SQL string is also removed below.
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
# VULNERABILITY: Missing CSRF protection — state-changing POST routes (register, deposit, transfer,
# profile update) accept requests with no origin or token verification, so a malicious third-party
# page can submit them on behalf of a logged-in user's browser session.
# REMEDIATED: Missing CSRF protection — a random per-session token is generated on first use,
# exposed to templates via csrf_token(), embedded as a hidden field in every state-changing form,
# and verified against the session copy on every POST before any route logic runs.
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
            # VULNERABILITY: Plaintext password storage — seed accounts inserted with raw passwords
            # db.execute(
            #     "INSERT INTO users (username, password, email, display_name, balance) "
            #     "VALUES ('kobe@opensafe.com', 'password123', 'kobe@opensafe.com', 'Kobe', 5000.00)"
            # )
            # db.execute(
            #     "INSERT INTO users (username, password, email, display_name, balance) "
            #     "VALUES ('kira@opensafe.com', 'letmein', 'kira@opensafe.com', 'Kira', 1250.75)"
            # )
            # REMEDIATED: Plaintext password storage — seed accounts get hashed passwords too, via
            # the same generate_password_hash() path used at registration; the demo credentials
            # (password123 / letmein) still work for login since check_password_hash() verifies
            # the raw password against the stored hash.
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
            # VULNERABILITY: Plaintext password storage — raw password inserted into the database as-is
            # db.execute(
            #     "INSERT INTO users (username, password, email, display_name, balance) "
            #     "VALUES (?, ?, ?, ?, 0.0)",
            #     (username, password, email, display_name)
            # )
            # REMEDIATED: Plaintext password storage — password hashed with werkzeug's
            # generate_password_hash() (PBKDF2-SHA256 with a per-password salt) before storage;
            # the raw password is never written to the database.
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

        # VULNERABILITY*: Sensitive data in logs — username and raw plaintext password written to log on every attempt
        # logger.info(f"LOGIN ATTEMPT | username={username} | password={password}")
        # REMEDIATED: Sensitive data in logs — only non-sensitive metadata (username, action) is
        # logged; the password never reaches any log sink.
        logger.info(f"LOGIN ATTEMPT | username={username}")

        # VULNERABILITY*: No brute-force protection — no rate limiting, lockout counter, delay, or CAPTCHA; every attempt is processed unconditionally
        # REMEDIATED: No brute-force protection — a per-username failed-attempt counter (see
        # _is_locked_out / _record_failed_login above) rejects further attempts once a username has
        # LOGIN_MAX_ATTEMPTS failures within LOGIN_LOCKOUT_WINDOW_SECONDS, without touching the database.
        if _is_locked_out(username):
            error = 'Too many failed login attempts for this account. Please try again in a few minutes.'
            logger.info(f"LOGIN BLOCKED | username={username} | reason=lockout")
            return render_template('login.html', error=error)

        db = get_db()

        # VULNERABILITY*: SQL Injection — query built by direct string concatenation; no parameterized queries or prepared statements
        # query = (
        #     "SELECT * FROM users WHERE username = '"
        #     + username
        #     + "' AND password = '"
        #     + password
        #     + "'"
        # )
        # logger.debug(f"Executing SQL: {query}")
        # user = db.execute(query).fetchone()
        # REMEDIATED: SQL Injection — parameterized query with a placeholder; user input is passed
        # as a bound parameter and is never concatenated into the SQL string, so it cannot alter the
        # query's structure. The password is no longer part of the query at all (see below).
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # REMEDIATED: Plaintext password storage — the password comparison that used to happen
        # inside the SQL query is replaced with check_password_hash(), which verifies the submitted
        # password against the stored PBKDF2 hash using a constant-time comparison.
        if user and check_password_hash(user['password'], password):
            session['user_id']  = user['id']
            session['username'] = user['username']
            _clear_failed_logins(username)
            # VULNERABILITY*: Sensitive data in logs — balance logged on successful login
            # logger.info(f"LOGIN SUCCESS | username={username} | password={password} | balance={user['balance']}")
            # REMEDIATED: Sensitive data in logs — logs the outcome only, never the password or balance.
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
            # VULNERABILITY: Raw card data collected without purpose or PCI-compliant handling — the
            # full card number and CVV are accepted from the client even though nothing in this app
            # actually processes payments with them; collecting this data at all creates PCI-DSS
            # scope and breach exposure for zero functional benefit.
            # card_number = request.form.get('card_number', '')
            # card_expiry = request.form.get('card_expiry', '')
            # card_cvv    = request.form.get('card_cvv', '')
            # REMEDIATED: Raw card data collection — the server no longer accepts a full PAN or CVV
            # at all (data minimization). A real deployment would capture card details client-side
            # via a PCI-compliant processor's hosted fields/tokenization (e.g. Stripe Elements) so
            # raw card data never touches this app's servers or logs in the first place.
            memo = request.form.get('memo', '')

            # VULNERABILITY*: Stored XSS — memo written to the database with no sanitization or escaping
            # REMEDIATED: Stored XSS — Jinja2 autoescaping (templates/transactions.html,
            # templates/dashboard.html) is the real fix; this length/character check is a
            # defense-in-depth layer that rejects obviously hostile input before it's ever stored.
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

            # VULNERABILITY*: Sensitive data in logs — sender balance, recipient, amount, and memo logged in plaintext
            # logger.info(
            #     f"TRANSFER | from={session['username']} | from_balance={sender['balance']} "
            #     f"| to={recipient_username} | amount={amount} | memo={memo}"
            # )
            # REMEDIATED: Sensitive data in logs — logs who initiated a transfer to whom, never the
            # sender's balance or the memo content.
            logger.info(f"TRANSFER ATTEMPT | from={session['username']} | to={recipient_username}")

            if not recipient:
                error = f'User "{recipient_username}" not found.'
            elif recipient['id'] == session['user_id']:
                error = 'You cannot transfer to yourself.'
            elif sender['balance'] < amount:
                error = f'Insufficient funds. Your balance is ${sender["balance"]:,.2f}.'
            elif amount <= 0:
                error = 'Transfer amount must be positive.'
            # REMEDIATED: Stored XSS (defense in depth) — reject invalid memo content before it's stored.
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
                # VULNERABILITY*: Stored XSS — memo written to the database with no sanitization or escaping
                # REMEDIATED: Stored XSS — Jinja2 autoescaping on render is the real fix (see
                # templates/transactions.html, templates/dashboard.html); the is_valid_memo() check
                # above is the defense-in-depth layer for this route.
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
    # VULNERABILITY: Debug mode enabled — Werkzeug's interactive debugger exposes a Python shell
    # (arbitrary code execution) on any unhandled exception to whoever can reach the app, and leaks
    # full stack traces and source snippets in error pages.
    # app.run(debug=True, host='0.0.0.0', port=5000)
    # REMEDIATED: Debug mode enabled — defaults to off; only enabled by explicitly setting
    # FLASK_DEBUG=1 in the environment for local development, never on by default.
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)

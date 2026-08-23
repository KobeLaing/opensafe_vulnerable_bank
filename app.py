import sqlite3
import logging
from flask import Flask, request, session, redirect, url_for, render_template, g
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'super-insecure-hardcoded-secret'

DATABASE = 'bank.db'

# VULNERABILITY: Sensitive data in logs — logging module set up to write plaintext sensitive data to file and stdout
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('bank.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


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
            db.execute(
                "INSERT INTO users (username, password, email, display_name, balance) "
                "VALUES ('kobe@opensafe.com', 'password123', 'kobe@opensafe.com', 'Kobe', 5000.00)"
            )
            db.execute(
                "INSERT INTO users (username, password, email, display_name, balance) "
                "VALUES ('kira@opensafe.com', 'letmein', 'kira@opensafe.com', 'Kira', 1250.75)"
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
            db.execute(
                "INSERT INTO users (username, password, email, display_name, balance) "
                "VALUES (?, ?, ?, ?, 0.0)",
                (username, password, email, display_name)
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

        # VULNERABILITY: Sensitive data in logs — username and raw plaintext password written to log on every attempt
        logger.info(
            f"LOGIN ATTEMPT | username={username} | password={password}"
        )

        db = get_db()

        # VULNERABILITY: SQL Injection — query built by direct string concatenation; no parameterized queries or prepared statements
        # VULNERABILITY: No brute-force protection — no rate limiting, lockout counter, delay, or CAPTCHA; every attempt is processed unconditionally
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        logger.debug(f"Executing SQL: {query}")

        user = db.execute(query).fetchone()

        if user:
            session['user_id']  = user['id']
            session['username'] = user['username']
            # VULNERABILITY: Sensitive data in logs — balance logged on successful login
            logger.info(
                f"LOGIN SUCCESS | username={username} | password={password} | balance={user['balance']}"
            )
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'
            logger.info(
                f"LOGIN FAILURE | username={username} | password={password}"
            )

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
            amount      = float(request.form['amount'])
            card_number = request.form.get('card_number', '')
            card_expiry = request.form.get('card_expiry', '')
            card_cvv    = request.form.get('card_cvv', '')
            memo        = request.form.get('memo', '')

            
            # VULNERABILITY: Stored XSS — memo written to the database with no sanitization or escaping
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

            # VULNERABILITY: Sensitive data in logs — sender balance, recipient, amount, and memo logged in plaintext
            logger.info(
                f"TRANSFER | from={session['username']} | from_balance={sender['balance']} "
                f"| to={recipient_username} | amount={amount} | memo={memo}"
            )

            if not recipient:
                error = f'User "{recipient_username}" not found.'
            elif recipient['id'] == session['user_id']:
                error = 'You cannot transfer to yourself.'
            elif sender['balance'] < amount:
                error = f'Insufficient funds. Your balance is ${sender["balance"]:,.2f}.'
            elif amount <= 0:
                error = 'Transfer amount must be positive.'
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
                # VULNERABILITY: Stored XSS — memo written to the database with no sanitization or escaping
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
    app.run(debug=True, host='0.0.0.0', port=5000)

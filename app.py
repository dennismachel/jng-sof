
import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
import sqlite3

# --- Database existence check ---
def ensure_database_exists():
    """
    Checks if the target database exists, and creates it if not.
    Only runs if all required env vars are set and not in testing/sqlite mode.
    """
    dbname = os.environ.get('POSTGRES_DB')
    user = os.environ.get('POSTGRES_USER')
    password = os.environ.get('POSTGRES_PASSWORD')
    host = os.environ.get('POSTGRES_HOST')
    port = os.environ.get('POSTGRES_PORT', '5432')
    # Only run if all required vars are present
    if not all([dbname, user, password, host]):
        return
    # Skip if running in test/sqlite mode
    if os.environ.get('USE_SQLITE_TESTING') == '1':
        return
    try:
        # Connect to default 'postgres' DB
        conn = psycopg2.connect(
            dbname='postgres', user=user, password=password, host=host, port=port
        )
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
            exists = cur.fetchone()
            if not exists:
                cur.execute(f'CREATE DATABASE "{dbname}"')
        conn.close()
    except Exception as e:
        print(f"[WARN] Could not check/create database: {e}")

load_dotenv()

# Ensure DB exists before app starts
ensure_database_exists()
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, abort, g
import uuid
import json
import time
# Import bcrypt for secure password hashing
from flask_bcrypt import Bcrypt

# --- Configuration ---
# Postgres connection settings are pulled from environment variables or .env.
# Do NOT commit credentials. Use .env for local development and real environment variables in production.
POSTGRES_HOST = os.environ.get('POSTGRES_HOST')
POSTGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')
POSTGRES_DB = os.environ.get('POSTGRES_DB')
POSTGRES_USER = os.environ.get('POSTGRES_USER')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD')
#host=f"/cloudsql/{os.environ.get('INSTANCE_CONNECTION_NAME')}" if os.environ.get('INSTANCE_CONNECTION_NAME') else POSTGRES_HOST #GCP
# IMPORTANT: Use a strong, unique key. Get this from environment variables in production.
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
ALLOWED_DOMAINS = ('@jngroup.com', '@jnbank.com')
SESSION_TIMEOUT_MINUTES = 10 


SCHEMA = """
CREATE TABLE IF NOT EXISTS StatementOfAffairs (
    submission_id UUID PRIMARY KEY,
    name VARCHAR,
    employee_id VARCHAR,
    date_submitted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    real_estate_summary DOUBLE PRECISION,
    motor_vehicles_summary DOUBLE PRECISION,
    furniture_equipment DOUBLE PRECISION,
    life_insurance_cash_value DOUBLE PRECISION,
    other_non_cash_assets_summary DOUBLE PRECISION,
    amounts_owed_to_you DOUBLE PRECISION,
    savings_deposits DOUBLE PRECISION,
    other_accounts DOUBLE PRECISION,
    other_investments DOUBLE PRECISION,
    total_assets DOUBLE PRECISION,
    loan_real_estate DOUBLE PRECISION,
    loan_motor_vehicles DOUBLE PRECISION,
    loan_furniture_equipment DOUBLE PRECISION,
    current_account_overdraft DOUBLE PRECISION,
    other_loans_payable DOUBLE PRECISION,
    other_liabilities_not_described DOUBLE PRECISION,
    total_liabilities DOUBLE PRECISION,
    net_worth DOUBLE PRECISION,
    motor_vehicle_schedule JSONB,
    real_estate_schedule JSONB,
    other_non_cash_assets_schedule JSONB,
    employed_income_net DOUBLE PRECISION,
    utilities_expense DOUBLE PRECISION,
    transportation_expense DOUBLE PRECISION,
    other_living_expense DOUBLE PRECISION,
    other_income DOUBLE PRECISION,
    statutory_deductions DOUBLE PRECISION,
    total_inflows DOUBLE PRECISION,
    total_outflows DOUBLE PRECISION,
    residual_income DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS Users (
    user_id UUID PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE
);
"""

app = Flask(__name__)
# Load environment-specific config (APP_ENV or FLASK_ENV). Default to development.
from config import DevelopmentConfig, ProductionConfig, TestingConfig

env = os.environ.get('APP_ENV', os.environ.get('FLASK_ENV', 'development'))
if env.lower() == 'production':
    app.config.from_object(ProductionConfig)

elif env.lower() == 'testing':
    app.config.from_object(TestingConfig)
else:
    app.config.from_object(DevelopmentConfig)

# Allow overriding via environment for quick tweaks (keeps behavior compatible with tests)
app.config['FLASK_DEBUG'] = os.environ.get('FLASK_DEBUG', app.config.get('DEBUG'))

# Initialize Bcrypt
bcrypt = Bcrypt(app)


def get_db_connection():
    """Establishes connection to PostgreSQL and ensures schema exists."""
    # Testing fallback: if Flask testing is enabled or USE_SQLITE_TESTING=1, use sqlite file DB
    use_sqlite_testing = app.config.get('TESTING', False) or os.environ.get('USE_SQLITE_TESTING') == '1'
    if use_sqlite_testing:
        # Use a file-backed sqlite DB so connections across requests see the same data during tests
        sqlite_path = os.environ.get('TEST_SQLITE_PATH', 'test_db.sqlite3')
        raw_conn = sqlite3.connect(sqlite_path, check_same_thread=False)
        raw_conn.row_factory = sqlite3.Row

        # Provide a small wrapper so code using `with conn.cursor() as cur:` still works
        class CursorWrapper:
            def __init__(self, raw_cur, conn):
                self._raw = raw_cur
                self._conn = conn

            def execute(self, query, params=None):
                # Translate psycopg2 %s placeholders to sqlite ? placeholders
                if params is None:
                    q = query.replace('%s', '?')
                    return self._raw.execute(q)
                q = query.replace('%s', '?')
                return self._raw.execute(q, params)

            def executemany(self, query, seq_of_params):
                q = query.replace('%s', '?')
                return self._raw.executemany(q, seq_of_params)

            def fetchone(self):
                return self._raw.fetchone()

            def fetchall(self):
                return self._raw.fetchall()

            def close(self):
                try:
                    self._raw.close()
                except Exception:
                    pass

        class _SqliteConnWrapper:
            def __init__(self, raw_conn):
                self._conn = raw_conn

            def cursor(self, *args, **kwargs):
                raw_cur = self._conn.cursor()

                class _Ctx:
                    def __init__(self, raw_cur, conn):
                        self._wrapped = CursorWrapper(raw_cur, conn)
                        self._conn = conn

                    def __enter__(self):
                        return self._wrapped

                    def __exit__(self, exc_type, exc, tb):
                        if exc_type:
                            self._conn.rollback()
                        else:
                            self._conn.commit()
                        try:
                            self._wrapped.close()
                        except Exception:
                            pass

                return _Ctx(raw_cur, self._conn)

            def close(self):
                try:
                    self._conn.close()
                except Exception:
                    pass

        conn = _SqliteConnWrapper(raw_conn)

        # Ensure minimal Users table exists for auth tests (other tables optional)
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS Users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0
                )
            """)
        return conn

    # Production/Postgres path
    conn = psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
    return conn

def check_auth(is_admin_required=False):
    """Checks if the user is logged in and redirects if not."""
    if 'logged_in' not in session:
        return False
    if is_admin_required and not session.get('is_admin', False):
        # Logged in but not an admin, deny access
        return False
    return True

def validate_corporate_email(email):
    """Checks if the email ends with one of the allowed domains, case-insensitive and trims whitespace."""
    if not email:
        return False
    email = email.strip().lower()
    return any(email.endswith(domain) for domain in ALLOWED_DOMAINS)

@app.before_request
def check_session_timeout():
    """Middleware to check last activity and enforce timeout."""
    # Exclude static files, login, and register pages
    if request.path in [url_for('login'), url_for('register'), url_for('logout')] or request.path.startswith('/static/'):
        return

    if 'logged_in' in session:
        now = time.time()
        # Check if last_activity is set and if time elapsed exceeds the timeout
        if 'last_activity' in session:
            time_since_activity = now - session['last_activity']
            if time_since_activity > (SESSION_TIMEOUT_MINUTES * 60):
                # Timeout occurred, log out the user
                session.pop('logged_in', None)
                session.pop('email', None)
                session.pop('is_admin', None)
                session.pop('last_activity', None)
                return redirect(url_for('login', timeout=True))
        
        # Update last activity time for the current request
        session['last_activity'] = now


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        #if not validate_corporate_email(email):
            #return render_template('login.html', error="Invalid email format. Must end with @jngroup.com or @jnbank.com.")

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT password, is_admin FROM Users WHERE email = %s", (email,))
            user_data = cur.fetchone()
        conn.close()

        if user_data:
            stored_hash = user_data[0].encode('utf-8')
            if bcrypt.check_password_hash(stored_hash, password):
                session['logged_in'] = True
                session['email'] = email
                session['is_admin'] = user_data[1]
                session['last_activity'] = time.time()
                return redirect(url_for('index'))
            # Do not reveal whether the email exists; show a unified message on failure
            return render_template('login.html', error="Email and password do not match.")
        else:
            # User not found
            return render_template('login.html', error="Email and password do not match.")
    
    error = "Session timed out due to inactivity." if request.args.get('timeout') else None
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user self-registration."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not validate_corporate_email(email):
            return render_template('register.html', error="Registration failed: Invalid email format. Must end with @jngroup.com or @jnbank.com.")
        
        if len(password) < 8:
            return render_template('register.html', error="Registration failed: Password must be at least 8 characters long.")

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM Users WHERE email = %s", (email,))
                existing_user = cur.fetchone()
                if existing_user:
                    conn.close()
                    return render_template('register.html', error="Registration failed: This email address is already in use.")

                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cur.execute("""
                    INSERT INTO Users (user_id, email, password, is_admin)
                    VALUES (%s, %s, %s, FALSE)
                """, (str(uuid.uuid4()), email, hashed_password))
            conn.close()
            session['logged_in'] = True
            session['email'] = email
            session['is_admin'] = False
            session['last_activity'] = time.time()
            return redirect(url_for('index'))
        except Exception as e:
            conn.close()
            return render_template('register.html', error=f"A database error occurred during registration: {e}")

    return render_template('register.html')


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('logged_in', None)
    session.pop('email', None)
    session.pop('is_admin', None)
    session.pop('last_activity', None) # Clear activity time
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    """Admin panel to create employee accounts."""
    if not check_auth(is_admin_required=True):
        return redirect(url_for('login'))

    message = None
    new_user_password = None

    if request.method == 'POST':
        email = request.form.get('email')
        
        if not validate_corporate_email(email):
            message = "Error: Invalid email format. Must end with @jngroup.com or @jnbank.com."
        else:
            # Generate a secure, one-time password
            new_user_password = secrets.token_hex(8) 
            
            conn = get_db_connection()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT email FROM Users WHERE email = %s", (email,))
                    existing_user = cur.fetchone()
                    if existing_user:
                        conn.close()
                        message = f"Error: User {email} already exists."
                    else:
                        hashed_password = bcrypt.generate_password_hash(new_user_password).decode('utf-8')
                        cur.execute("""
                            INSERT INTO Users (user_id, email, password, is_admin)
                            VALUES (%s, %s, %s, FALSE)
                        """, (str(uuid.uuid4()), email, hashed_password))
                        conn.close()
                        message = f"Success! User {email} created."
            except Exception as e:
                conn.close()
                message = f"Database Error: {e}"

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT email, is_admin FROM Users")
        users = cur.fetchall()
    conn.close()
    return render_template('admin.html', message=message, new_user_password=new_user_password, users=users)


@app.route('/', methods=['GET'])
def index():
    """Displays the Confidential Statement of Affairs form, restricted to logged-in users."""
    if not check_auth():
        return redirect(url_for('login'))
        
    return render_template('form.html')

@app.route('/submit', methods=['POST'])
def submit():
    """Handles the form submission and inserts data into DuckDB."""
    if not check_auth():
        # Prevent unauthorized submissions
        abort(403) 
        
    try:
        data = request.form
        
        # Helper function for safe float conversion
        def safe_float(val):
            try:
                # Remove currency symbols and thousands separators before conversion
                return float(str(val).replace('$', '').replace(',', '') or 0.0)
            except ValueError:
                return 0.0

        # --- 1. ASSET & LIABILITY SUMMARY (Section 1) ---
        
        # Assets
        real_estate_summary = safe_float(data.get('real_estate_summary'))
        motor_vehicles_summary = safe_float(data.get('motor_vehicles_summary'))
        furniture_equipment = safe_float(data.get('furniture_equipment'))
        life_insurance_cash_value = safe_float(data.get('life_insurance_cash_value'))
        other_non_cash_assets_summary = safe_float(data.get('other_non_cash_assets_summary'))
        amounts_owed_to_you = safe_float(data.get('amounts_owed_to_you'))
        savings_deposits = safe_float(data.get('savings_deposits'))
        other_accounts = safe_float(data.get('other_accounts'))
        other_investments = safe_float(data.get('other_investments'))
        
        total_assets = (real_estate_summary + motor_vehicles_summary + furniture_equipment + 
                        life_insurance_cash_value + other_non_cash_assets_summary + 
                        amounts_owed_to_you + savings_deposits + other_accounts + other_investments)

        # Liabilities
        loan_real_estate = safe_float(data.get('loan_real_estate'))
        loan_motor_vehicles = safe_float(data.get('loan_motor_vehicles'))
        loan_furniture_equipment = safe_float(data.get('loan_furniture_equipment'))
        current_account_overdraft = safe_float(data.get('current_account_overdraft'))
        other_loans_payable = safe_float(data.get('other_loans_payable'))
        other_liabilities_not_described = safe_float(data.get('other_liabilities_not_described'))
        
        total_liabilities = (loan_real_estate + loan_motor_vehicles + loan_furniture_equipment + 
                             current_account_overdraft + other_loans_payable + other_liabilities_not_described)
        
        net_worth = total_assets - total_liabilities


        # --- 2. DETAILED SCHEDULES (Section 2) ---
        
        # Motor Vehicle Schedule (Fixed 3 rows for input simplicity)
        motor_vehicle_schedule_list = []
        for i in range(1, 4):
            motor_vehicle_schedule_list.append({
                "type_make": data.get(f'mv_type_make_{i}', None),
                "year_model": data.get(f'mv_year_model_{i}', None),
                "value": safe_float(data.get(f'mv_value_{i}', 0.0)),
                "loan_balance": safe_float(data.get(f'mv_loan_balance_{i}', 0.0)),
                "monthly_payment": safe_float(data.get(f'mv_monthly_payment_{i}', 0.0)),
            })
            
        # Real Estate Schedule (Fixed 3 rows)
        real_estate_schedule_list = []
        for i in range(1, 4):
            real_estate_schedule_list.append({
                "address": data.get(f're_address_{i}', None),
                "valuation": safe_float(data.get(f're_valuation_{i}', 0.0)),
                "loan_balance": safe_float(data.get(f're_loan_balance_{i}', 0.0)),
                "monthly_payment": safe_float(data.get(f're_monthly_payment_{i}', 0.0)),
                "account_number": data.get(f're_account_number_{i}', None),
                "lender": data.get(f're_lender_{i}', None),
            })

        # Other Non-Cash Assets Schedule (Fixed 3 rows)
        other_non_cash_assets_schedule_list = []
        for i in range(1, 4):
            other_non_cash_assets_schedule_list.append({
                "description": data.get(f'oa_description_{i}', None),
                "value": safe_float(data.get(f'oa_value_{i}', 0.0)),
            })

        motor_vehicle_schedule_json = json.dumps(motor_vehicle_schedule_list)
        real_estate_schedule_json = json.dumps(real_estate_schedule_list)
        other_non_cash_assets_schedule_json = json.dumps(other_non_cash_assets_schedule_list)


        # --- 3. INCOME & EXPENSES (Section 3) ---
        
        employed_income_net = safe_float(data.get('employed_income_net'))
        utilities_expense = safe_float(data.get('utilities_expense'))
        transportation_expense = safe_float(data.get('transportation_expense'))
        other_living_expense = safe_float(data.get('other_living_expense'))
        other_income = safe_float(data.get('other_income'))
        statutory_deductions = safe_float(data.get('statutory_deductions'))

        total_inflows = employed_income_net + other_income
        total_outflows = utilities_expense + transportation_expense + other_living_expense + statutory_deductions
        residual_income = total_inflows - total_outflows
        
        # --- 4. Database Insertion ---
        
        # Collect all parameters in a tuple for the parameterized query
        params = (
            data.get('name'),
            data.get('employee_id'),
            real_estate_summary, motor_vehicles_summary, furniture_equipment, life_insurance_cash_value, 
            other_non_cash_assets_summary, amounts_owed_to_you, savings_deposits, other_accounts, other_investments, total_assets, 
            loan_real_estate, loan_motor_vehicles, loan_furniture_equipment, current_account_overdraft, 
            other_loans_payable, other_liabilities_not_described, total_liabilities, net_worth,
            motor_vehicle_schedule_json, real_estate_schedule_json, other_non_cash_assets_schedule_json,
            employed_income_net, utilities_expense, transportation_expense, other_living_expense, 
            other_income, statutory_deductions, total_inflows, total_outflows, residual_income
        )

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO StatementOfAffairs (
                    submission_id, name, employee_id, date_submitted,
                    real_estate_summary, motor_vehicles_summary, furniture_equipment, life_insurance_cash_value,
                    other_non_cash_assets_summary, amounts_owed_to_you, savings_deposits, other_accounts, other_investments, total_assets,
                    loan_real_estate, loan_motor_vehicles, loan_furniture_equipment, current_account_overdraft,
                    other_loans_payable, other_liabilities_not_described, total_liabilities, net_worth,
                    motor_vehicle_schedule, real_estate_schedule, other_non_cash_assets_schedule,
                    employed_income_net, utilities_expense, transportation_expense, other_living_expense,
                    other_income, statutory_deductions, total_inflows, total_outflows, residual_income
                ) VALUES (
                    %s, %s, %s, CURRENT_TIMESTAMP,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s::jsonb, %s::jsonb, %s::jsonb,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, (
                str(uuid.uuid4()), data.get('name'), data.get('employee_id'),
                real_estate_summary, motor_vehicles_summary, furniture_equipment, life_insurance_cash_value,
                other_non_cash_assets_summary, amounts_owed_to_you, savings_deposits, other_accounts, other_investments, total_assets,
                loan_real_estate, loan_motor_vehicles, loan_furniture_equipment, current_account_overdraft,
                other_loans_payable, other_liabilities_not_described, total_liabilities, net_worth,
                motor_vehicle_schedule_json, real_estate_schedule_json, other_non_cash_assets_schedule_json,
                employed_income_net, utilities_expense, transportation_expense, other_living_expense,
                other_income, statutory_deductions, total_inflows, total_outflows, residual_income
            ))
        conn.close()

        # Redirect to a success page
        return redirect(url_for('success'))

    except Exception as e:
        # Log the error (in production, use a proper logger)
        print(f"Submission Error: {e}")
        # Return a user-friendly error message 
        return render_template('error.html', error=f"An error occurred during submission. Please try again. Error detail: {str(e)}"), 500

@app.route('/success')
def success():
    """Simple success confirmation page."""
    if not check_auth():
        return redirect(url_for('login'))
    return render_template('success.html')

@app.route('/view_data')
def view_data():
    """Internal route to quickly view the data for testing."""
    if not check_auth(is_admin_required=True):
        # Only admins can view the raw data
        abort(403) 
        
    conn = get_db_connection()
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute("SELECT * FROM StatementOfAffairs ORDER BY date_submitted DESC")
        data = cur.fetchall()
    conn.close()
    return f"<pre>{data}</pre>"


@app.route('/health')
def health():
    """Simple health check for Cloud Run / load balancers."""
    return ("ok", 200)

def initialize_admin_user():
    """Creates the initial admin user if the Users table is empty."""
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM Users")
        count = cur.fetchone()[0]
        if count == 0:
            print("--- Creating Initial Admin User ---")
            hashed_password = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8')
            cur.execute("""
                INSERT INTO Users (user_id, email, password, is_admin)
                VALUES (%s, %s, %s, TRUE)
            """, (str(uuid.uuid4()), ADMIN_EMAIL, hashed_password))
            print(f"Admin User created: {ADMIN_EMAIL}")
            print("(Password is set from environment variables and not printed for security.)")
            print("---------------------------------")
    conn.close()

if __name__ == '__main__':
    # Initialize DB connection and create admin user on startup
    # It MUST be 0.0.0.0, not localhost
    # It MUST use the PORT environment variable
    app.debug = True
    app.run()
    try:
        initialize_admin_user()
    except Exception as e:
        print(f"Database initialization failed: {e}")
    
    # Run the Flask app (local/dev). Respect PORT env var so containerized runs can bind correctly.
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    app.run(host="0.0.0.0", port=port, debug=(os.environ.get('FLASK_DEBUG') == '1'))


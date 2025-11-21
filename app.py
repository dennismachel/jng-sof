import os
import duckdb
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, abort, g
import uuid
import json
import time
# Import bcrypt for secure password hashing
from flask_bcrypt import Bcrypt

# --- Configuration ---
DATABASE_FILE = 'statement_of_affairs.duckdb'
# IMPORTANT: Use a strong, unique key. Get this from environment variables in production.
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@jngroup.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'secure_admin_password_123')
ALLOWED_DOMAINS = ('@corporate.com', '@jngroup.com', '@jnbank.com')
SESSION_TIMEOUT_MINUTES = 3 

# --- DuckDB Schema Definition ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS StatementOfAffairs (
    submission_id VARCHAR PRIMARY KEY,
    name VARCHAR,
    employee_id VARCHAR,
    date_submitted TIMESTAMP,
    
    -- SECTION 1: ASSETS SUMMARY (Matching the two-column layout)
    real_estate_summary DOUBLE,
    motor_vehicles_summary DOUBLE,
    furniture_equipment DOUBLE,
    life_insurance_cash_value DOUBLE,
    other_non_cash_assets_summary DOUBLE,
    amounts_owed_to_you DOUBLE,
    savings_deposits DOUBLE,
    other_accounts DOUBLE,
    other_investments DOUBLE,
    total_assets DOUBLE, -- Calculated
    
    -- SECTION 1: LIABILITIES SUMMARY
    loan_real_estate DOUBLE,
    loan_motor_vehicles DOUBLE,
    loan_furniture_equipment DOUBLE,
    current_account_overdraft DOUBLE,
    other_loans_payable DOUBLE,
    other_liabilities_not_described DOUBLE,
    total_liabilities DOUBLE, -- Calculated
    net_worth DOUBLE, -- Calculated
    
    -- SECTION 2: DETAILED SCHEDULES (Stored as JSON for multiple entries)
    motor_vehicle_schedule JSON, 
    real_estate_schedule JSON,    
    other_non_cash_assets_schedule JSON,
    
    -- SECTION 3: INCOME & EXPENSES
    employed_income_net DOUBLE,
    utilities_expense DOUBLE,
    transportation_expense DOUBLE,
    other_living_expense DOUBLE,
    other_income DOUBLE,
    statutory_deductions DOUBLE,
    total_inflows DOUBLE, -- Calculated
    total_outflows DOUBLE, -- Calculated
    residual_income DOUBLE -- Calculated
);

CREATE TABLE IF NOT EXISTS Users (
    user_id VARCHAR PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    -- Store bcrypt hash (BLOB/BYTEA is ideal, but TEXT is acceptable for DuckDB/SQLite for portability/demo)
    password TEXT NOT NULL, 
    is_admin BOOLEAN DEFAULT FALSE
);
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_change_me_in_prod') 
app.config['PERMANENT_SESSION_LIFETIME'] = 180 # 3 minutes in seconds

# Initialize Bcrypt
bcrypt = Bcrypt(app)


def get_db_connection():
    """Establishes connection to DuckDB and ensures schema exists."""
    conn = duckdb.connect(database=DATABASE_FILE, read_only=False)
    conn.sql(SCHEMA)
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
        
        if not validate_corporate_email(email):
             return render_template('login.html', error="Invalid email format. Must end with @jngroup.com or @jnbank.com.")

        conn = get_db_connection()
        # Use parameterized query for SELECT
        user_data = conn.execute("SELECT password, is_admin FROM Users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user_data:
            # Check password hash using bcrypt
            stored_hash = user_data[0].encode('utf-8')
            if bcrypt.check_password_hash(stored_hash, password):
                session['logged_in'] = True
                session['email'] = email
                session['is_admin'] = user_data[1]
                session['last_activity'] = time.time() # Set initial activity time
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error="Invalid email or password.")
        else:
            return render_template('login.html', error="Invalid email or password.")
    
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
            # Use parameterized query to check if user already exists
            existing_user = conn.execute("SELECT email FROM Users WHERE email = ?", (email,)).fetchone()
            if existing_user:
                conn.close()
                return render_template('register.html', error="Registration failed: This email address is already in use.")

            # Hash the password before storing
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Create new user (non-admin) using parameterized INSERT
            conn.execute("""
                INSERT INTO Users (user_id, email, password, is_admin) 
                VALUES (?, ?, ?, FALSE)
            """, (str(uuid.uuid4()), email, hashed_password))
            conn.close()
            
            # Auto-login the new user
            session['logged_in'] = True
            session['email'] = email
            session['is_admin'] = False
            session['last_activity'] = time.time() # Set initial activity time
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
                # Use parameterized query to check if user already exists
                existing_user = conn.execute("SELECT email FROM Users WHERE email = ?", (email,)).fetchone()
                if existing_user:
                    conn.close()
                    message = f"Error: User {email} already exists."
                else:
                    # Hash the password before storing
                    hashed_password = bcrypt.generate_password_hash(new_user_password).decode('utf-8')
                    
                    # Create new user (non-admin) using parameterized INSERT
                    conn.execute("""
                        INSERT INTO Users (user_id, email, password, is_admin) 
                        VALUES (?, ?, ?, FALSE)
                    """, (str(uuid.uuid4()), email, hashed_password))
                    conn.close()
                    message = f"Success! User {email} created."
            except Exception as e:
                conn.close()
                message = f"Database Error: {e}"

    conn = get_db_connection()
    # Parameterized query is not strictly needed here, but kept consistent
    users = conn.execute("SELECT email, is_admin FROM Users").fetchall()
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
        # Use parameterized INSERT query (safer than f-strings)
        conn.execute("""
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
                uuid(), ?, ?, now(), 
                
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                
                ?, ?, ?, ?, ?, ?, ?, ?,
                
                CAST(? AS JSON), CAST(? AS JSON), CAST(? AS JSON),
                
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, params)
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
    # Query data using non-parameterized query, safe as no user input is involved
    data = conn.execute("SELECT * FROM StatementOfAffairs ORDER BY date_submitted DESC").fetchall()
    conn.close()
    return f"<pre>{data}</pre>"

def initialize_admin_user():
    """Creates the initial admin user if the Users table is empty."""
    conn = get_db_connection()
    count = conn.execute("SELECT count(*) FROM Users").fetchone()[0]
    if count == 0:
        print("--- Creating Initial Admin User ---")
        # Hash the default admin password
        hashed_password = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8')
        
        # Use parameterized INSERT
        conn.execute("""
            INSERT INTO Users (user_id, email, password, is_admin) 
            VALUES (?, ?, ?, TRUE)
        """, (str(uuid.uuid4()), ADMIN_EMAIL, hashed_password))
        conn.close()
        print(f"Admin User created: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
        print("---------------------------------")
    else:
        conn.close()

if __name__ == '__main__':
    # Initialize DB connection and create admin user on startup
    try:
        initialize_admin_user()
    except Exception as e:
        print(f"Database initialization failed: {e}")
    
    # Run the Flask app
    app.run(debug=True)


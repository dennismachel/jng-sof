import os
import duckdb
import secrets # Used for generating secure passwords
from flask import Flask, render_template, request, redirect, url_for, session, abort
import uuid
import json # 

# --- Configuration ---
DATABASE_FILE = 'statement_of_affairs.duckdb'
# IMPORTANT: Use a strong, unique key. Get this from environment variables in production.
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@corporate.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'secure_admin_password_123')

# --- DuckDB Schema Definition ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS StatementOfAffairs (
    submission_id VARCHAR PRIMARY KEY,
    name VARCHAR,
    date_submitted TIMESTAMP,
    -- ASSETS & LIABILITIES (Simplified as JSON for flexibility, based on the file)
    total_assets DOUBLE,
    total_liabilities DOUBLE,
    net_worth DOUBLE,
    -- Detailed Schedules (Stored as JSON/STRUCT for multiple entries)
    motor_vehicles JSON, 
    real_estate JSON,    
    life_insurance JSON, 
    -- INCOME & EXPENSES
    net_employed_income DOUBLE,
    utilities_expense DOUBLE,
    transport_expense DOUBLE,
    other_living_expense DOUBLE,
    total_inflows DOUBLE,
    total_outflows DOUBLE
);

CREATE TABLE IF NOT EXISTS Users (
    user_id VARCHAR PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    -- NOTE: For production, this MUST be stored as a secure hash (e.g., using bcrypt).
    -- We store plain text for this demo ONLY.
    password TEXT NOT NULL, 
    is_admin BOOLEAN DEFAULT FALSE
);
"""

# --- Flask App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_change_me_in_prod') 

#--- Database Connection --- DUCKDB ---
def get_db_connection():
    """Establishes connection to DuckDB and ensures schema exists."""
    conn = duckdb.connect(database=DATABASE_FILE, read_only=False)
    conn.sql(SCHEMA)
    return conn
#--- Authentication Helpers ---
def check_auth(is_admin_required=False):
    """Checks if the user is logged in and redirects if not."""
    if 'logged_in' not in session:
        return False
    if is_admin_required and not session.get('is_admin', False):
        # Logged in but not an admin, deny access
        return False
    return True

#--- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user_data = conn.sql(f"SELECT password, is_admin FROM Users WHERE email = '{email}'").fetchone()
        conn.close()

        if user_data and user_data[0] == password: # UNSAFE CHECK: See SCHEMA notes
            session['logged_in'] = True
            session['email'] = email
            session['is_admin'] = user_data[1]
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials or email format.")

    return render_template('login.html', corporate_domain="@corporate.com")

@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('logged_in', None)
    session.pop('email', None)
    session.pop('is_admin', None)
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
        
        if not email or not email.endswith('@corporate.com'):
            message = "Error: Invalid email format. Must end with @corporate.com."
        else:
            # Generate a secure, one-time password
            new_user_password = secrets.token_hex(8) 
            
            conn = get_db_connection()
            try:
                conn.execute("""
                    INSERT INTO Users (user_id, email, password, is_admin) 
                    VALUES (?, ?, ?, FALSE)
                """, (str(uuid.uuid4()), email, new_user_password)) # UNSAFE: storing plain password
                conn.close()
                message = f"Success! User {email} created."
            except duckdb.ConstraintException:
                conn.close()
                message = f"Error: User {email} already exists."
            except Exception as e:
                conn.close()
                message = f"Database Error: {e}"

    conn = get_db_connection()
    users = conn.sql("SELECT email, is_admin FROM Users").fetchall()
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
        
        # 1. Collect and Type-Convert Simple Fields
        name = data.get('name')
        
        # Use safe float conversion for all numerical fields
        def safe_float(val):
            try:
                return float(str(val).replace('$', '').replace(',', '') or 0.0)
            except ValueError:
                return 0.0

        # Assets/Liabilities/Income/Expenses
        total_assets = safe_float(data.get('total_assets'))
        total_liabilities = safe_float(data.get('total_liabilities'))
        net_employed_income = safe_float(data.get('net_employed_income'))
        utilities_expense = safe_float(data.get('utilities_expense'))
        transport_expense = safe_float(data.get('transport_expense'))
        other_living_expense = safe_float(data.get('other_living_expense'))
        
        # Basic calculations
        net_worth = total_assets - total_liabilities
        total_inflows = net_employed_income
        total_outflows = utilities_expense + transport_expense + other_living_expense

        # 2. Collect Complex JSON Data (Placeholder Logic)
        motor_vehicles_list = [
            {"type": data.get('mv_type_1', 'N/A'), "value": safe_float(data.get('mv_value_1', 0.0))}
        ]
        real_estate_list = [
            {"address": data.get('re_address_1', 'N/A'), "valuation": safe_float(data.get('re_valuation_1', 0.0))}
        ]
        life_insurance_list = [
             {"company": data.get('li_company_1', 'N/A'), "cash_value": safe_float(data.get('li_cash_value_1', 0.0))}
        ]
        
        import json
        motor_vehicles_json = json.dumps(motor_vehicles_list)
        real_estate_json = json.dumps(real_estate_list)
        life_insurance_json = json.dumps(life_insurance_list)
        
        # 3. Insert Data into DuckDB
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO StatementOfAffairs (
                submission_id, name, date_submitted,
                total_assets, total_liabilities, net_worth,
                motor_vehicles, real_estate, life_insurance,
                net_employed_income, utilities_expense, transport_expense,
                other_living_expense, total_inflows, total_outflows
            ) VALUES (
                uuid(), ?, now(), 
                ?, ?, ?,
                CAST(? AS JSON), CAST(? AS JSON), CAST(? AS JSON),
                ?, ?, ?,
                ?, ?, ?
            )
        """, (
            name, 
            total_assets, total_liabilities, net_worth,
            motor_vehicles_json, real_estate_json, life_insurance_json,
            net_employed_income, utilities_expense, transport_expense,
            other_living_expense, total_inflows, total_outflows
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
    data = conn.sql("SELECT * FROM StatementOfAffairs ORDER BY date_submitted DESC").fetchall()
    conn.close()
    return f"<pre>{data}</pre>"

def initialize_admin_user():
    """Creates the initial admin user if the Users table is empty."""
    conn = get_db_connection()
    count = conn.sql("SELECT count(*) FROM Users").fetchone()[0]
    if count == 0:
        print("--- Creating Initial Admin User ---")
        conn.execute("""
            INSERT INTO Users (user_id, email, password, is_admin) 
            VALUES (?, ?, ?, TRUE)
        """, (str(uuid.uuid4()), ADMIN_EMAIL, ADMIN_PASSWORD)) # UNSAFE: plain password
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
"""db_seed.py — ensure an initial admin user exists in the Users table.

This is safe to run repeatedly — it will create the Users table if missing and only insert
an admin user when Users table contains no rows.

It reads connection details and admin credentials from environment variables.
"""
import os
import uuid
import psycopg2
import psycopg2.extras
import json
import bcrypt
import time
from psycopg2 import OperationalError

POSTGRES_HOST = os.environ.get('POSTGRES_HOST') or os.environ.get('DB_HOST') or 'db'
POSTGRES_PORT = os.environ.get('POSTGRES_PORT') or '5432'
POSTGRES_DB = os.environ.get('POSTGRES_DB', 'statement_of_affairs')
POSTGRES_USER = os.environ.get('POSTGRES_USER')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD')

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

SCHEMA = """
CREATE TABLE IF NOT EXISTS Users (
    user_id UUID PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE
);
"""


def main():
    missing = []
    for name, val in (
        ('POSTGRES_USER', POSTGRES_USER),
        ('POSTGRES_PASSWORD', POSTGRES_PASSWORD),
        ('ADMIN_EMAIL', ADMIN_EMAIL),
        ('ADMIN_PASSWORD', ADMIN_PASSWORD),
    ):
        if not val:
            missing.append(name)

    if missing:
        print(
            "Skipping DB seed: missing environment variables: {}.\n"
            "Provide these via your environment, an `.env` file, or docker-compose `env_file`."
            .format(', '.join(missing))
        )
        return

    # If running tests with sqlite, or explicit skip, do not attempt Postgres seeding
    if os.environ.get('USE_SQLITE_TESTING') == '1':
        print('USE_SQLITE_TESTING=1 set; skipping Postgres DB seed.')
        return

    dsn = {
        'host': POSTGRES_HOST,
        'port': POSTGRES_PORT,
        'dbname': POSTGRES_DB,
        'user': POSTGRES_USER,
        'password': POSTGRES_PASSWORD,
    }

    # Wait for database to be ready using retries and exponential backoff
    max_retries = int(os.environ.get('DB_SEED_MAX_RETRIES', '8'))
    initial_delay = float(os.environ.get('DB_SEED_INITIAL_DELAY', '1'))
    delay = initial_delay
    connected = False
    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            print(f"DB seed: attempting to connect to Postgres (attempt {attempt}/{max_retries})...")
            conn = psycopg2.connect(connect_timeout=5, **dsn)
            connected = True
            break
        except OperationalError as oe:
            last_err = oe
            print(f"DB not ready yet: {oe}; retrying in {delay} seconds...")
            time.sleep(delay)
            delay *= 2
        except Exception as e:
            last_err = e
            print(f"Unexpected error while attempting DB connection: {e}")
            time.sleep(delay)
            delay *= 2

    if not connected:
        print(f"Failed to connect to Postgres after {max_retries} attempts: {last_err}")
        return

    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            # Ensure Users table exists
            cur.execute(SCHEMA)
        conn.autocommit = True
        with conn.cursor() as cur:
            # Ensure Users table exists
            cur.execute(SCHEMA)

            # Check if any user exists
            cur.execute("SELECT count(*) FROM Users")
            count = cur.fetchone()[0]

            if count == 0:
                print("No users found — creating initial admin user.")
                hashed = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
                cur.execute(
                    "INSERT INTO Users (user_id, email, password, is_admin) VALUES (%s, %s, %s, TRUE)",
                    (str(uuid.uuid4()), ADMIN_EMAIL, hashed.decode('utf-8'))
                )
                print(f"Created admin user: {ADMIN_EMAIL}")
            else:
                print("Users already exist — skipping admin creation.")

    except Exception as e:
        print(f"DB seed failed: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == '__main__':
    main()

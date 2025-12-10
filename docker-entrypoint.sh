#!/bin/sh
set -e

# Make sure .env (python-dotenv) is loaded by the app code. This script will run db_seed first
# and then exec the final process (gunicorn) so logs show correctly.
python db_seed.py || true

# If PORT not set, default to 8080
PORT=${PORT:-5000}

# Exec gunicorn as the final step so it receives unix signals correctly
exec gunicorn -b :${PORT} --workers 1 --threads 8 --timeout 0 app:app

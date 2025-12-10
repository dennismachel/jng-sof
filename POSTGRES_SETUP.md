# PostgreSQL Setup Instructions for jng-sof

## 1. Install PostgreSQL (if not already installed)
- macOS: `brew install postgresql`
- Ubuntu/Debian: `sudo apt-get install postgresql postgresql-contrib`
- Windows: Download from https://www.postgresql.org/download/

## 2. Start PostgreSQL Service
- macOS: `brew services start postgresql`
- Ubuntu/Debian: `sudo service postgresql start`

## 3. Create Database and User
Open a terminal and run:

```
psql postgres
```

Then, in the psql shell:

```
-- Create database
CREATE DATABASE statement_of_affairs;

-- Create user (replace 'youruser' and 'yourpassword' as needed)
CREATE USER youruser WITH PASSWORD 'yourpassword';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE statement_of_affairs TO youruser;
```

## 4. Set Environment Variables
Set these in your shell, `.env`, or Docker environment:

```
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=statement_of_affairs
export POSTGRES_USER=youruser
export POSTGRES_PASSWORD=yourpassword
```

## 5. Docker Compose (Optional)
If you want to run PostgreSQL in Docker, add this to a `docker-compose.yml`:

```
version: '3.8'
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: statement_of_affairs
      POSTGRES_USER: youruser
      POSTGRES_PASSWORD: yourpassword
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
```

## 6. Run the Flask App
- Ensure environment variables are set.
- Build and run your Docker container, or run locally with `python app.py`.

## 7. First Run
- The app will automatically create tables and the initial admin user if needed.

---
For troubleshooting, check your connection settings and ensure PostgreSQL is running.

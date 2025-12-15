# Use official Python image
FROM python:3.12-slim   

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker caching
COPY requirements.txt ./

# --- CRITICAL FIX: Install libraries for WeasyPrint ---
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libpq-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libglib2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*
# ------------------------------------------------------

RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Cloud Run sets the PORT environment variable
EXPOSE 5000

# Make entrypoint executable
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

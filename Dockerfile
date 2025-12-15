# Use official Python image
FROM python:3.12-slim   

# Set working directory
WORKDIR /app

# Copy requirements (if exists) and install dependencies
COPY requirements.txt ./
# Install system dependencies
RUN apt-get update && apt-get install -y build-essential libffi-dev libpq-dev && rm -rf /var/lib/apt/lists/*


# --- UPDATED LINE BELOW ---
# Install system dependencies (including those for WeasyPrint/PDF generation)
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libpq-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*
# ---------------------------

RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Cloud Run sets the PORT environment variable (default 8080) — expose it so local tooling can match
EXPOSE 5000

# Set environment variables for Flask
#ENV FLASK_APP=app.py
#ENV FLASK_RUN_HOST=0.0.0.0
#ENV FLASK_ENV=production

# Run the Flask app
CMD ["flask", "run", "-h", "0.0.0.0"]
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

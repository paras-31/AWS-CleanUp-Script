# -----------------------
#  Base Python Image
# -----------------------
FROM python:3.11-slim

# Avoid writing .pyc files & enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# -----------------------
# Install system deps
# -----------------------
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# -----------------------
#  Create app directory
# -----------------------
WORKDIR /app

# -----------------------
# Install Python dependencies
# -----------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# -----------------------
# Copy application code
# -----------------------
COPY . .

# -----------------------
# Default command to run cleanup script
# Update main.py to your actual filename
# -----------------------
CMD ["python", "main.py"]

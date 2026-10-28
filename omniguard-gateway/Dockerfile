# OmniGuard Gateway Dockerfile
# Python 3.11-slim with Uvicorn - Hardened
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r omniguard && useradd -r -g omniguard -d /app -s /sbin/nologin omniguard

WORKDIR /app

# Install system dependencies (gcc for any native extensions, then remove)
RUN apt-get update && apt-get install -y --no-install-recommends     gcc     && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt     && apt-get purge -y --auto-remove gcc     && rm -rf /root/.cache/pip

# Copy application code
COPY main.py .
COPY security/ ./security/

# Change ownership to non-root user
RUN chown -R omniguard:omniguard /app

# Switch to non-root user
USER omniguard

# Expose port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=5s     CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

# Read-only filesystem (tmpfs for /tmp if needed)
# Note: Read-only rootfs requires --read-only flag at runtime

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

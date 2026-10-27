# ==============================================================================
# Stage 1: Build virtual environment with python dependencies
# ==============================================================================
FROM python:3.12-slim-bookworm AS builder

# Set build-time environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Copy requirements and install into a standalone virtualenv
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ==============================================================================
# Stage 2: Minimal runtime image with Nmap and unprivileged user
# ==============================================================================
FROM python:3.12-slim-bookworm AS runner

# Labels for OCI image specification
LABEL org.opencontainers.image.title="AEGIS-Recon" \
      org.opencontainers.image.description="Evidence-based reconnaissance and threat intelligence platform" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    DATABASE_PATH=/app/data/aegis_recon.db \
    ALLOWLIST_PATH=/app/config/allowlist.yaml

# Install runtime dependencies: Nmap and curl (for container healthcheck)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        curl \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create unprivileged application user and group (UID/GID 10001)
RUN groupadd -g 10001 aegis && \
    useradd -u 10001 -g aegis -m -s /bin/bash aegis

WORKDIR /app

# Copy virtual environment from builder stage
COPY --from=builder --chown=aegis:aegis /opt/venv /opt/venv

# Create necessary runtime directories with unprivileged permissions
RUN mkdir -p /app/data /app/config /app/logs && \
    chown -R aegis:aegis /app

# Copy application source code
COPY --chown=aegis:aegis app/ /app/app/
COPY --chown=aegis:aegis web/ /app/web/
COPY --chown=aegis:aegis config/ /app/config/
COPY --chown=aegis:aegis scripts/ /app/scripts/

# Switch to unprivileged user (Never run as root!)
USER aegis

# Container exposes the FastAPI web service port
EXPOSE 8000

# Periodic health check verifying API and database responsiveness
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/health || exit 1

# Default execution entrypoint: Uvicorn ASGI server
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


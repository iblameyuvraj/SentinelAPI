# ==============================================================================
# SentinelAPI — AI-Powered OWASP API Security Testing & Pentesting Engine
# Multi-stage / Production Docker Image
# ==============================================================================

FROM python:3.11-slim

# Labels
LABEL maintainer="Yuvraj <yuvrajjsoni17@gmail.com>"
LABEL description="SentinelAPI - Zero-Trust API Vulnerability Scanner"

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TERM=xterm-256color \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8


# Set working directory
WORKDIR /app

# Copy dependency specifications first for Docker layer caching
COPY requirements.txt pyproject.toml ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and relevant data
COPY sentinelapi/ ./sentinelapi/
COPY sentinel ./sentinel
COPY sandbox_openapi.json ./
COPY .env.example ./

# Install sentinelapi in editable mode so 'sentinel' command is available on PATH
RUN pip install --no-cache-dir -e .

# Create output directory for audit reports and PDF logs
RUN mkdir -p /app/markdown

# Set executable permissions on launcher
RUN chmod +x /app/sentinel

# Default entrypoint runs the SentinelAPI engine
ENTRYPOINT ["sentinel"]

# Default command displays help if no arguments are passed, or user can run interactive session with -it
CMD []

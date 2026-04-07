# ═══════════════════════════════════════════════════════════════════════════════
# SecureCodeEnv++ — Production Dockerfile (Step 49)
# ═══════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim AS base

# Metadata
LABEL maintainer="SecureCodeEnv Team"
LABEL description="OpenEnv-compatible security code review environment"
LABEL version="1.0.0"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ── Install dependencies first (layer caching) ─────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Copy application code ──────────────────────────────────────────────────
COPY secure_code_env/ ./secure_code_env/
COPY openenv.yaml ./
COPY pyproject.toml ./
COPY README.md ./

# ── Health check ───────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health').raise_for_status()"

# ── Expose port and run ───────────────────────────────────────────────────
EXPOSE 8000

CMD ["uvicorn", "secure_code_env.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

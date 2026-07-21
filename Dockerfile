# ── Stage 1: builder ──────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps for pyahocorasick (C extension) and onnxruntime
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Non-root user for security
RUN useradd -m -u 1001 guardrail
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=guardrail:guardrail . .

# Pre-download model if available (CI skips this; prod builds include it)
# RUN python -m pipeline.tier2_classifier --download

USER guardrail

EXPOSE 8100

# Uvicorn: 1 worker per container (scale via replicas, not threads)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100", \
     "--workers", "1", "--log-level", "info"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/health')"

# =============================================================================
# Stage 1: builder — install Python deps & build wheels
# =============================================================================
FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pyproject.toml README.md ./
COPY opensast ./opensast
COPY rules ./rules

# Install project dependencies into a virtual-env so we can copy it cleanly
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir .

# =============================================================================
# Stage 2: runtime — minimal image with only what's needed to run
# =============================================================================
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="openSAST" \
      org.opencontainers.image.description="Multi-engine SAST orchestrator for Korea MOIS 49 security weakness items" \
      org.opencontainers.image.source="https://github.com/sungalex/openSAST"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Runtime system dependencies:
#   - openjdk-21-jre-headless: SpotBugs 엔진 실행
#   - libpango/libcairo: WeasyPrint PDF 렌더링
#   - curl: 헬스체크 등 유틸
#   - shared-mime-info: WeasyPrint MIME 타입 감지
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 shared-mime-info \
    openjdk-21-jre-headless \
  && rm -rf /var/lib/apt/lists/*

# Copy the pre-built virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install engines that ship native binaries — safer to install in runtime stage
RUN pip install --no-cache-dir "semgrep>=1.70" "bandit[sarif]>=1.7"

WORKDIR /app

# Copy application code and rules
COPY --from=builder /build/opensast ./opensast
COPY --from=builder /build/rules ./rules
COPY --from=builder /build/pyproject.toml /build/README.md ./
COPY static ./static

# Create non-root user
RUN useradd -r -u 10001 -m opensast \
  && chown -R opensast:opensast /app

USER opensast

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]

CMD ["uvicorn", "opensast.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

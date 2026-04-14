FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libffi-dev shared-mime-info \
    openjdk-21-jre-headless \
  && rm -rf /var/lib/apt/lists/*

# Install Opengrep (Semgrep CE) — primary 1st-pass engine
RUN pip install --no-cache-dir "semgrep>=1.70"

# Install Bandit
RUN pip install --no-cache-dir "bandit[sarif]>=1.7"

WORKDIR /app

COPY pyproject.toml README.md ./
COPY aisast ./aisast
COPY rules ./rules

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "aisast.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

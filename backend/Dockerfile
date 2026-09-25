# Build from the repository root so the bundled datasets are available:
#   docker build -f backend/Dockerfile -t dnsentinel-api .
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DNSENTINEL_DB_PATH=/app/var/dnsentinel.db

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend/ backend/
COPY data/ data/

# Bake reproducible model artifacts into the image (seeded; see train.py),
# then drop root.
RUN python -m backend.train \
    && useradd --create-home --uid 1000 app \
    && mkdir -p /app/var \
    && chown -R app:app /app/var /app/backend/models

USER app
WORKDIR /app/backend
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/health').status==200 else 1)"

# PaaS hosts inject PORT; default to 8001 to match the dev setup.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8001}"]

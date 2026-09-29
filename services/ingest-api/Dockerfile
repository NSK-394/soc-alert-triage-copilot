FROM python:3.11-slim
WORKDIR /app
COPY services/ingest-api/requirements.txt /app/services/ingest-api/requirements.txt
RUN pip install --no-cache-dir -r /app/services/ingest-api/requirements.txt
COPY services/ingest-api /app/services/ingest-api
ENV PYTHONPATH=/app
WORKDIR /app/services/ingest-api
# Non-root: a security audit flagged this container running as root by default,
# which widens the blast radius if the process is ever compromised. The dev bind
# mount (docker-compose.yml's `./services:/app/services`) still works unprivileged
# here on Docker Desktop's shared filesystem.
RUN useradd --create-home --uid 1000 appuser
USER appuser
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

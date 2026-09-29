FROM python:3.11-slim
WORKDIR /app
COPY services/tier2-worker/requirements.txt /app/services/tier2-worker/requirements.txt
RUN pip install --no-cache-dir -r /app/services/tier2-worker/requirements.txt
COPY services/tier2-worker /app/services/tier2-worker
ENV PYTHONPATH=/app
WORKDIR /app/services/tier2-worker
# Non-root, same rationale as services/ingest-api/Dockerfile (security audit
# finding) -- this container holds OPENAI_API_KEY/DATABASE_URL in its environment,
# so limiting its privileges matters even more here.
RUN useradd --create-home --uid 1000 appuser
USER appuser
# The RQ job loop: listens on the same queue services/ingest-api/job_queue.py
# enqueues to, and runs services/pipeline/run_pipeline.py's run_pipeline() for
# each alert (docs/architecture.md §12 Phase C task 3 / Phase D task 2).
CMD ["python", "rq_worker.py"]

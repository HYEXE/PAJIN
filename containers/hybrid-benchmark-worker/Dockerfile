FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY worker_entry.py /app/worker_entry.py

RUN chmod 0555 /app/worker_entry.py

USER 65532:65532
ENTRYPOINT ["python", "/app/worker_entry.py"]

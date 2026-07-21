FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.lock /tmp/pajin-worker-requirements.lock

RUN python -m pip install \
        --require-hashes \
        --only-binary=:all: \
        --target /opt/pajin-vendor \
        -r /tmp/pajin-worker-requirements.lock \
    && rm /tmp/pajin-worker-requirements.lock

COPY worker_entry.py /app/worker_entry.py
COPY mcp_bridge.py /app/mcp_bridge.py
COPY demo_mcp_server.py /app/demo_mcp_server.py

ENV PYTHONPATH=/opt/pajin-vendor

RUN chmod 0555 /app/worker_entry.py /app/mcp_bridge.py /app/demo_mcp_server.py \
    && python -c "import mcp; print('verified bundled MCP SDK')"

USER 65532:65532
ENTRYPOINT ["python", "/app/worker_entry.py"]

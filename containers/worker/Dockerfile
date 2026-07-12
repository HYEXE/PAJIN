FROM python:3.12-slim

WORKDIR /app
COPY vendor/ /opt/pajin-vendor/
COPY worker_entry.py /app/worker_entry.py
COPY mcp_bridge.py /app/mcp_bridge.py
COPY demo_mcp_server.py /app/demo_mcp_server.py

ENV PYTHONPATH=/opt/pajin-vendor

RUN chmod 0555 /app/worker_entry.py /app/mcp_bridge.py /app/demo_mcp_server.py \
    && python -c "import mcp; print('verified bundled MCP SDK')"

USER 65532:65532
ENTRYPOINT ["python", "/app/worker_entry.py"]

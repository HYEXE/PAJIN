# Test controller only: its Docker socket access is never granted to a target Worker.
FROM docker:29.1.3-cli@sha256:4fa0ee1f3a7e4354c4ea34558b6d4ee32859baf4973d4c8ccc8e7fe3dd730c04 AS docker-cli
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src:/app:/app/tests
WORKDIR /app
COPY containers/control-plane/requirements.lock /tmp/runtime.lock
COPY containers/operations/requirements.lock /tmp/probes.lock
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: \
    -r /tmp/runtime.lock -r /tmp/probes.lock
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --chown=10001:10001 src ./src
COPY --chown=10001:10001 tests ./tests
COPY --chown=10001:10001 scripts ./scripts
COPY --chown=10001:10001 examples ./examples
COPY --chown=10001:10001 pyproject.toml uv.lock ./
USER 10001:10001
CMD ["sleep", "infinity"]

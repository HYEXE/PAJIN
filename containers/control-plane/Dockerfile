FROM docker:29.1.3-cli@sha256:4fa0ee1f3a7e4354c4ea34558b6d4ee32859baf4973d4c8ccc8e7fe3dd730c04 AS docker-cli

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system --gid 10001 pajin \
    && useradd --system --uid 10001 --gid pajin --no-create-home pajin \
    && install --directory --owner=10001 --group=10001 --mode=0700 \
        /var/lib/pajin/artifact-staging \
        /var/lib/pajin/artifact-repository

COPY containers/control-plane/requirements.lock /tmp/pajin-requirements.lock

RUN python -m pip install --require-hashes --only-binary=:all: -r /tmp/pajin-requirements.lock \
    && rm /tmp/pajin-requirements.lock

COPY src ./src
COPY containers/control-plane/init_storage.py /app/init_storage.py
COPY containers/control-plane/replay_runtime_preflight.py /app/replay_runtime_preflight.py

ENV PYTHONPATH=/app/src

RUN chmod 0555 /app/init_storage.py /app/replay_runtime_preflight.py

FROM runtime AS control-plane

USER 10001:10001

EXPOSE 8090

CMD ["python", "-m", "pajin.control_plane"]

FROM runtime AS replay-worker

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

USER 10001:10001

CMD ["python", "-m", "pajin.control_plane.replay_worker_main"]

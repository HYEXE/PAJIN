FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

ARG PIP_TRUSTED_HOST

WORKDIR /app

RUN groupadd --system --gid 10001 pajin \
    && useradd --system --uid 10001 --gid pajin --no-create-home pajin

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install ".[control-plane]"

USER 10001:10001

EXPOSE 8090

CMD ["pajin-control-plane"]

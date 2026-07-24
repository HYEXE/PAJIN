FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.lock /tmp/pajin-ai-target-requirements.lock

RUN python -m pip install \
        --require-hashes \
        --only-binary=:all: \
        --target /opt/pajin-target-vendor \
        -r /tmp/pajin-ai-target-requirements.lock \
    && rm /tmp/pajin-ai-target-requirements.lock

COPY target.py /app/target.py

ENV PYTHONPATH=/opt/pajin-target-vendor

RUN chmod 0555 /app/target.py \
    && python -c "import cryptography; print('verified bundled cryptography runtime')"

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --start-period=2s --retries=5 \
  CMD ["python", "-c", "import os,sys,urllib.request; p=os.environ.get('PAJIN_LAB_PROFILE','vulnerable'); c=os.environ.get('PAJIN_PROVIDER_CREDENTIAL','pajin-local-credential-v1'); sys.exit(1) if p not in {'vulnerable','hardened'} or not c or c != c.strip() else None; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=1).close()"]
ENTRYPOINT ["python", "/app/target.py"]

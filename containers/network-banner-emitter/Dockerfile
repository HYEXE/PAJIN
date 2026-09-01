FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY banner_emitter.py /opt/pajin/banner_emitter.py

USER 65532:65532
EXPOSE 18080/tcp

ENTRYPOINT ["python", "/opt/pajin/banner_emitter.py"]

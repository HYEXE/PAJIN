FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY target.py /app/target.py

RUN chmod 0555 /app/target.py

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --start-period=2s --retries=5 \
  CMD ["python", "-c", "import os,sys,urllib.request; p=os.environ.get('PAJIN_CTF_WEB_LAB_PROFILE','vulnerable'); sys.exit(1) if p not in {'vulnerable','hardened'} else None; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=1).close()"]
ENTRYPOINT ["python", "/app/target.py"]

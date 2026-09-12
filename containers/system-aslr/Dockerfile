FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY containers/system-aslr/agent.py /app/agent.py
COPY containers/system-aslr/client.py /app/client.py
RUN chmod 0444 /app/agent.py /app/client.py
USER 65532:65532
ENTRYPOINT ["python", "-I", "/app/client.py"]

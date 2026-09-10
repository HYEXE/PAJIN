FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY src/pajin/application_elf/parser.py /app/parser.py
COPY containers/application-elf/entry.py /app/entry.py
RUN chmod 0444 /app/parser.py /app/entry.py
USER 65532:65532
ENTRYPOINT ["python", "-I", "/app/entry.py"]

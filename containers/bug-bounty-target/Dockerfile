FROM python:3.12-slim

WORKDIR /app
COPY target.py /app/target.py

RUN chmod 0555 /app/target.py

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=1s --timeout=1s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=1)"
ENTRYPOINT ["python", "/app/target.py"]

FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY proxy.py /app/proxy.py

RUN chmod 0555 /app/proxy.py

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --start-period=2s --retries=5 \
  CMD ["python", "-c", "import socket; s=socket.create_connection(('127.0.0.1',8080),1); s.close()"]
ENTRYPOINT ["python", "/app/proxy.py"]

FROM python:3.12-alpine

WORKDIR /app
COPY proxy.py /app/proxy.py

RUN chmod 0555 /app/proxy.py

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=1s --timeout=1s --retries=5 \
  CMD python -c "import socket; s=socket.create_connection(('127.0.0.1',8080),1); s.close()"
ENTRYPOINT ["python", "/app/proxy.py"]

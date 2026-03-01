# fors33-verifier: CLI for CI/CD and URL-only verification. No file uploads.
FROM python:3.11-slim

RUN pip install --no-cache-dir fors33-verifier

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN pip install --no-cache-dir flask
COPY server_url_only.py /app/server_url_only.py

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]

# DigitalOcean App Platform (URL-only API)

Deploy the fors33-verifier image as an App Platform app to expose **URL-only** verification. No file uploads; zero-trust.

## What runs on App Platform

- **Option A — URL-only API:** Run the same Docker image with CMD that starts the minimal HTTP server. It exposes:
  - `POST /verify` with JSON body: `{"url": "https://...", "expected_hash": "..."}` (optional `"start"`, `"end"` for segments).
  - `GET /health` for liveness.
- **Option B — CLI only:** Run the image as a job (no HTTP). Use only if you trigger verification via another system.

The API **never** accepts file uploads. Users send only a presigned URL and expected hash; the container fetches from that URL and verifies. For local files, users must use `pip install fors33-verifier` or the in-browser web terminal (client-side only).

## Web terminal (client-side only)

The in-browser verification experience must remain **static HTML/JS** using the browser **Web Crypto API** (`crypto.subtle.digest`). The file never leaves the user's machine; hashing happens in their RAM. Host the static page on your existing droplet or elsewhere. Do not send file content to the App Platform API.

## Deploying on App Platform

1. Create an App from a container image.
2. **Image:** `ghcr.io/jhartyharr23/fors33-verifier:latest` or `docker.io/fors33/verifier:latest`.
3. **Run command (for URL-only API):** `serve` (or `python /app/server_url_only.py`). Leave default for CLI-only.
4. **Port:** Set `PORT` (e.g. 8080); the server reads `PORT` from env.
5. **Env:** No secrets required for basic verify. Add any keys only if you extend the server.

After deploy, document the App URL (e.g. `https://verifier-xxx.ondigitalocean.app`) in README and LLM_CONTEXT.md for the URL-based verification use case.

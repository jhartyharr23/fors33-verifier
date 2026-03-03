#!/usr/bin/env python3
"""
Minimal HTTP API for URL-only verification. No file uploads.
POST /verify with JSON: {"url": "https://...", "expected_hash": "..."}
or {"url": "https://...", "expected_hash": "...", "start": 0, "end": 1024}.
Returns 200 + {"verified": true/false} or 4xx/5xx.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

def get_app():
    try:
        from flask import Flask, request, jsonify
    except ImportError:
        sys.exit("flask is required for server_url_only.py; pip install flask")

    app = Flask(__name__)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    @app.route("/verify", methods=["POST"])
    def verify():
        try:
            data = request.get_json(force=True) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON"}), 400

        url = data.get("url")
        expected_hash = data.get("expected_hash")
        start = data.get("start")
        end = data.get("end")

        if not url or not expected_hash:
            return jsonify({"error": "url and expected_hash are required"}), 400
        if not url.startswith("https://"):
            return jsonify({"error": "url must be HTTPS"}), 400

        cmd = ["fors33-verifier", "--url", url, "--expected-hash", expected_hash]
        if start is not None:
            cmd.extend(["--start", str(int(start))])
        if end is not None:
            cmd.extend(["--end", str(int(end))])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        verified = result.returncode == 0
        return jsonify({"verified": verified}), 200 if verified else 422

    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    get_app().run(host="0.0.0.0", port=port)

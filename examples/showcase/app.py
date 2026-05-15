"""Trivial Flask app — exists only so the showcase image has a runnable
entrypoint. The whole point of this image is to give the CVE scanner
real findings; the app itself is intentionally dull."""

from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(
        {
            "service": "nebulacr-showcase",
            "purpose": "Demo image for NebulaCR — see /metrics on the registry side.",
        }
    )


@app.get("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

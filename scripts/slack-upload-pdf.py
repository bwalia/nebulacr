#!/usr/bin/env python3
"""Upload a PDF to Slack using the files.getUploadURLExternal flow.

Webhook URLs (incoming-webhooks) cannot attach files — only bot tokens can.
This script expects:

  SLACK_BOT_TOKEN   xoxb-… with files:write scope
  SLACK_CHANNEL_ID  e.g. C0123456789 (channel ID, not name)

Optional:
  SLACK_WEBHOOK_URL fallback — if SLACK_BOT_TOKEN is missing, post a plain
                    text notice via the webhook so the channel still hears
                    about the run. (Webhooks can't carry the PDF itself.)

Exit codes:
  0  uploaded OR intentionally skipped (missing creds, missing file)
  1  credentials present but the API refused the upload
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


SLACK_API = "https://slack.com/api"


def _http(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _slack_get(path: str, token: str, params: dict[str, str]) -> dict:
    q = urllib.parse.urlencode(params)
    code, body = _http(
        "GET",
        f"{SLACK_API}/{path}?{q}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"http_{code}", "raw": body.decode("replace")}


def _slack_post(path: str, token: str, payload: dict) -> dict:
    code, body = _http(
        "POST",
        f"{SLACK_API}/{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        data=json.dumps(payload).encode(),
    )
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"http_{code}", "raw": body.decode("replace")}


def _webhook_fallback(url: str, text: str) -> int:
    code, body = _http(
        "POST",
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps({"text": text}).encode(),
    )
    if 200 <= code < 300:
        print("webhook fallback posted")
        return 0
    print(f"webhook post failed: http {code}: {body!r}", file=sys.stderr)
    return 0  # don't fail the job on notify-path errors


def _upload(token: str, channel: str, pdf_path: str) -> int:
    filename = os.path.basename(pdf_path)
    size = os.path.getsize(pdf_path)

    step1 = _slack_get(
        "files.getUploadURLExternal",
        token,
        {"filename": filename, "length": str(size)},
    )
    if not step1.get("ok"):
        print(f"getUploadURLExternal failed: {step1}", file=sys.stderr)
        return 1

    upload_url = step1["upload_url"]
    file_id = step1["file_id"]

    with open(pdf_path, "rb") as fh:
        pdf_bytes = fh.read()
    code, body = _http(
        "POST",
        upload_url,
        headers={"Content-Type": "application/pdf"},
        data=pdf_bytes,
    )
    if not (200 <= code < 300):
        print(f"PDF PUT failed: http {code}: {body!r}", file=sys.stderr)
        return 1

    title = os.environ.get("SLACK_TITLE") or "NebulaCR nightly CVE scan"
    initial_comment = (
        os.environ.get("SLACK_INITIAL_COMMENT")
        or f":shield: {title} — PDF report attached."
    )
    step3 = _slack_post(
        "files.completeUploadExternal",
        token,
        {
            "files": [{"id": file_id, "title": title}],
            "channel_id": channel,
            "initial_comment": initial_comment,
        },
    )
    if not step3.get("ok"):
        print(f"completeUploadExternal failed: {step3}", file=sys.stderr)
        return 1

    print(f"uploaded {filename} ({size} bytes) to channel {channel}")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: slack-upload-pdf.py <path/to.pdf>", file=sys.stderr)
        return 2
    pdf_path = sys.argv[1]

    if not os.path.isfile(pdf_path):
        print(f"no PDF at {pdf_path} — skipping Slack upload")
        return 0

    token = os.environ.get("SLACK_BOT_TOKEN") or ""
    channel = os.environ.get("SLACK_CHANNEL_ID") or ""
    webhook = os.environ.get("SLACK_WEBHOOK_URL") or ""

    if token and channel:
        return _upload(token, channel, pdf_path)

    if webhook:
        print(
            "SLACK_BOT_TOKEN/SLACK_CHANNEL_ID not set — "
            "posting text notice via webhook instead (no PDF attached).",
            file=sys.stderr,
        )
        return _webhook_fallback(
            webhook,
            ":shield: NebulaCR nightly CVE scan finished. "
            "PDF report is in the workflow artifacts "
            "(set SLACK_BOT_TOKEN + SLACK_CHANNEL_ID to get it attached here).",
        )

    print(
        "no Slack credentials configured — skipping notification",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

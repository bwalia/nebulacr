#!/usr/bin/env bash
# sync-gh-secrets.sh — push local secrets into GitHub repo secrets.
#
# Sources (in order of preference):
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
#     from `aws configure get ... --profile $AWS_PROFILE`
#   KUBECONFIG
#     from $KUBECONFIG_FILE (default ~/.kube/config), base64-encoded
#     to match how the existing deploy-k3s workflow decodes it.
#   SLACK_WEBHOOK_URL
#     from $SLACK_FILE (default /tmp/slack), with trailing newline trimmed.
#   DOCKER_HUB_USERNAME / DOCKER_HUB_PASSWORD
#   NEBULACR_USERNAME / NEBULACR_PASSWORD / NEBULACR_REGISTRY / NEBULACR_MIRROR
#     from environment variables of the same name.
#
# Missing sources are skipped with a short note (never fatal).
# Values are never echoed; only names + byte lengths are logged.
#
# Usage:
#   scripts/sync-gh-secrets.sh                  # push to bwalia/nebulacr
#   REPO=other/repo scripts/sync-gh-secrets.sh  # override repo
#   DRY_RUN=1 scripts/sync-gh-secrets.sh        # show what would happen
set -euo pipefail

REPO="${REPO:-bwalia/nebulacr}"
AWS_PROFILE="${AWS_PROFILE:-kubepilot}"
KUBECONFIG_FILE="${KUBECONFIG_FILE:-$HOME/.kube/config}"
SLACK_FILE="${SLACK_FILE:-/tmp/slack}"
DRY_RUN="${DRY_RUN:-0}"

push() {
  local name="$1" value="$2" source="$3"
  if [ -z "$value" ]; then
    echo "  skip  $name  (empty from $source)"
    return
  fi
  if [ "$DRY_RUN" = "1" ]; then
    echo "  dry   $name  ← $source (${#value} bytes)"
    return
  fi
  if printf '%s' "$value" | gh secret set "$name" --repo "$REPO" >/dev/null; then
    echo "  set   $name  ← $source (${#value} bytes)"
  else
    echo "  FAIL  $name  ← $source" >&2
    return 1
  fi
}

echo "syncing local secrets → GH repo: $REPO  (dry_run=$DRY_RUN)"

# ── AWS profile ────────────────────────────────────────────────────────────
if aws configure get aws_access_key_id --profile "$AWS_PROFILE" >/dev/null 2>&1; then
  push AWS_ACCESS_KEY_ID \
    "$(aws configure get aws_access_key_id --profile "$AWS_PROFILE")" \
    "aws-profile:$AWS_PROFILE"
  push AWS_SECRET_ACCESS_KEY \
    "$(aws configure get aws_secret_access_key --profile "$AWS_PROFILE")" \
    "aws-profile:$AWS_PROFILE"
else
  echo "  skip  AWS_*  (profile '$AWS_PROFILE' not found)"
fi

# ── KUBECONFIG ─────────────────────────────────────────────────────────────
if [ -f "$KUBECONFIG_FILE" ]; then
  push KUBECONFIG "$(base64 -w0 "$KUBECONFIG_FILE")" "$KUBECONFIG_FILE (b64)"
else
  echo "  skip  KUBECONFIG  ($KUBECONFIG_FILE missing)"
fi

# ── Slack ──────────────────────────────────────────────────────────────────
if [ -f "$SLACK_FILE" ]; then
  push SLACK_WEBHOOK_URL "$(tr -d '\n' < "$SLACK_FILE")" "$SLACK_FILE"
else
  echo "  skip  SLACK_WEBHOOK_URL  ($SLACK_FILE missing)"
fi

# ── Env-var passthrough ────────────────────────────────────────────────────
for name in \
  DOCKER_HUB_USERNAME DOCKER_HUB_PASSWORD \
  NEBULACR_USERNAME NEBULACR_PASSWORD \
  NEBULACR_REGISTRY NEBULACR_MIRROR
do
  val="${!name:-}"
  if [ -n "$val" ]; then
    push "$name" "$val" "env:$name"
  else
    echo "  skip  $name  (env unset)"
  fi
done

echo "done."

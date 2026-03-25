#!/usr/bin/env bash
# ============================================================================
# nebulacr-login.sh -- CLI helper for authenticating to NebulaCR
#
# This script provides a unified login experience across different
# environments: interactive developer machines, GitHub Actions, GitLab CI,
# Jenkins, and generic CI systems.
#
# Authentication methods (auto-detected or specified via --method):
#
#   oidc-browser   Interactive OIDC browser flow (for developers)
#                  Opens a browser for SSO login, receives a callback with
#                  an authorization code, exchanges it for a NebulaCR token.
#
#   github-actions GitHub Actions OIDC (auto-detected in GitHub runners)
#                  Uses ACTIONS_ID_TOKEN_REQUEST_URL to mint a GitHub JWT,
#                  then exchanges it for a NebulaCR token.
#
#   gitlab-ci      GitLab CI OIDC (auto-detected in GitLab runners)
#                  Uses the GITLAB_OIDC_TOKEN environment variable (set via
#                  GitLab's id_tokens keyword).
#
#   jenkins        Jenkins OIDC (auto-detected in Jenkins agents)
#                  Uses the JENKINS_OIDC_TOKEN environment variable.
#
#   k8s-sa         Kubernetes ServiceAccount token
#                  Reads the projected SA token from the filesystem.
#
#   token          Direct token (for bootstrap/migration)
#                  Uses a pre-existing NebulaCR token. NOT zero-trust.
#
# Usage:
#   ./nebulacr-login.sh \
#     --registry registry.example.com:5000 \
#     --auth-url https://auth.example.com:5001 \
#     --tenant my-org \
#     --project my-project
#
# Options:
#   --registry URL    NebulaCR registry endpoint (host:port)
#   --auth-url URL    NebulaCR auth API endpoint (https://...)
#   --tenant NAME     NebulaCR tenant name
#   --project NAME    NebulaCR project name
#   --repository NAME Specific image repository to scope the token to
#   --actions LIST    Comma-separated actions (pull,push). Default: pull,push
#   --method METHOD   Force authentication method (see above)
#   --audience AUD    OIDC audience claim. Default: nebulacr
#   --username USER   Username for docker login. Default: auto-detected
#   --no-docker       Skip docker login (just print the token)
#   --json            Output token details as JSON
#   --quiet           Suppress informational output
#   --help            Show this help message
#
# Environment variables (override CLI flags):
#   NEBULACR_REGISTRY    Registry endpoint
#   NEBULACR_AUTH_URL    Auth API endpoint
#   NEBULACR_TENANT      Tenant name
#   NEBULACR_PROJECT     Project name
#   NEBULACR_AUDIENCE    OIDC audience (default: nebulacr)
#   NEBULACR_TOKEN       Pre-existing token (for --method token)
#
# Exit codes:
#   0  Success
#   1  General error
#   2  Invalid arguments
#   3  Authentication failed
#   4  Docker login failed
#   5  Missing dependencies
#
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly DEFAULT_AUDIENCE="nebulacr"
readonly DEFAULT_ACTIONS="pull,push"
readonly DEFAULT_SA_TOKEN_PATH="/var/run/secrets/nebulacr/token"
readonly OIDC_CALLBACK_PORT=8085

# ---------------------------------------------------------------------------
# Defaults (can be overridden by env vars or CLI flags)
# ---------------------------------------------------------------------------
REGISTRY="${NEBULACR_REGISTRY:-}"
AUTH_URL="${NEBULACR_AUTH_URL:-}"
TENANT="${NEBULACR_TENANT:-}"
PROJECT="${NEBULACR_PROJECT:-}"
REPOSITORY=""
ACTIONS="${DEFAULT_ACTIONS}"
METHOD=""
AUDIENCE="${NEBULACR_AUDIENCE:-${DEFAULT_AUDIENCE}}"
USERNAME=""
NO_DOCKER=false
JSON_OUTPUT=false
QUIET=false

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

log() {
    if [ "${QUIET}" = false ]; then
        echo "[${SCRIPT_NAME}] $*" >&2
    fi
}

error() {
    echo "[${SCRIPT_NAME}] ERROR: $*" >&2
}

die() {
    local exit_code="$1"
    shift
    error "$@"
    exit "${exit_code}"
}

# Check that a required command is available
require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" &>/dev/null; then
        die 5 "Required command '${cmd}' not found. Please install it."
    fi
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
show_help() {
    # Extract help from the header comment
    sed -n '/^# Usage:/,/^# ====/p' "$0" | sed 's/^# \?//'
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --registry)
                REGISTRY="$2"; shift 2 ;;
            --registry=*)
                REGISTRY="${1#*=}"; shift ;;
            --auth-url)
                AUTH_URL="$2"; shift 2 ;;
            --auth-url=*)
                AUTH_URL="${1#*=}"; shift ;;
            --tenant)
                TENANT="$2"; shift 2 ;;
            --tenant=*)
                TENANT="${1#*=}"; shift ;;
            --project)
                PROJECT="$2"; shift 2 ;;
            --project=*)
                PROJECT="${1#*=}"; shift ;;
            --repository)
                REPOSITORY="$2"; shift 2 ;;
            --repository=*)
                REPOSITORY="${1#*=}"; shift ;;
            --actions)
                ACTIONS="$2"; shift 2 ;;
            --actions=*)
                ACTIONS="${1#*=}"; shift ;;
            --method)
                METHOD="$2"; shift 2 ;;
            --method=*)
                METHOD="${1#*=}"; shift ;;
            --audience)
                AUDIENCE="$2"; shift 2 ;;
            --audience=*)
                AUDIENCE="${1#*=}"; shift ;;
            --username)
                USERNAME="$2"; shift 2 ;;
            --username=*)
                USERNAME="${1#*=}"; shift ;;
            --no-docker)
                NO_DOCKER=true; shift ;;
            --json)
                JSON_OUTPUT=true; shift ;;
            --quiet|-q)
                QUIET=true; shift ;;
            --help|-h)
                show_help ;;
            --version)
                echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"; exit 0 ;;
            -*)
                die 2 "Unknown option: $1. Use --help for usage." ;;
            *)
                die 2 "Unexpected argument: $1. Use --help for usage." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Validate required parameters
# ---------------------------------------------------------------------------
validate_params() {
    local missing=()

    [ -z "${REGISTRY}" ] && missing+=("--registry")
    [ -z "${AUTH_URL}" ] && missing+=("--auth-url")
    [ -z "${TENANT}" ] && missing+=("--tenant")
    [ -z "${PROJECT}" ] && missing+=("--project")

    if [ ${#missing[@]} -gt 0 ]; then
        die 2 "Missing required parameters: ${missing[*]}"
    fi
}

# ---------------------------------------------------------------------------
# Auto-detect CI environment
# ---------------------------------------------------------------------------
detect_environment() {
    if [ -n "${METHOD}" ]; then
        log "Using specified method: ${METHOD}"
        return
    fi

    # GitHub Actions: ACTIONS_ID_TOKEN_REQUEST_URL is set when id-token: write
    if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
        METHOD="github-actions"
        USERNAME="${USERNAME:-github-actions}"
        log "Detected GitHub Actions environment"
        return
    fi

    # GitLab CI: GITLAB_OIDC_TOKEN is set via id_tokens keyword
    if [ -n "${GITLAB_OIDC_TOKEN:-}" ]; then
        METHOD="gitlab-ci"
        USERNAME="${USERNAME:-gitlab-ci}"
        log "Detected GitLab CI environment"
        return
    fi

    # Jenkins: JENKINS_URL is set in Jenkins agents
    if [ -n "${JENKINS_URL:-}" ]; then
        METHOD="jenkins"
        USERNAME="${USERNAME:-jenkins}"
        log "Detected Jenkins environment"
        return
    fi

    # Kubernetes: check for projected SA token
    if [ -f "${DEFAULT_SA_TOKEN_PATH}" ]; then
        METHOD="k8s-sa"
        USERNAME="${USERNAME:-k8s-sa}"
        log "Detected Kubernetes environment (ServiceAccount token found)"
        return
    fi

    # Generic CI: check for a pre-set token
    if [ -n "${NEBULACR_TOKEN:-}" ]; then
        METHOD="token"
        USERNAME="${USERNAME:-ci}"
        log "Using pre-set NEBULACR_TOKEN"
        return
    fi

    # Interactive: default to browser-based OIDC
    if [ -t 0 ]; then
        METHOD="oidc-browser"
        USERNAME="${USERNAME:-user}"
        log "No CI environment detected, using interactive OIDC browser flow"
    else
        die 3 "Cannot determine authentication method. Use --method to specify one."
    fi
}

# ---------------------------------------------------------------------------
# Authentication: GitHub Actions OIDC
# ---------------------------------------------------------------------------
auth_github_actions() {
    require_cmd curl
    require_cmd jq

    log "Requesting OIDC token from GitHub..."

    local OIDC_TOKEN
    OIDC_TOKEN=$(curl -sSf \
        -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${AUDIENCE}" \
        | jq -r '.value')

    if [ -z "${OIDC_TOKEN}" ] || [ "${OIDC_TOKEN}" = "null" ]; then
        die 3 "Failed to obtain OIDC token from GitHub"
    fi

    log "GitHub OIDC token obtained"
    exchange_token "${OIDC_TOKEN}"
}

# ---------------------------------------------------------------------------
# Authentication: GitLab CI OIDC
# ---------------------------------------------------------------------------
auth_gitlab_ci() {
    require_cmd curl
    require_cmd jq

    if [ -z "${GITLAB_OIDC_TOKEN:-}" ]; then
        die 3 "GITLAB_OIDC_TOKEN is not set. Add 'id_tokens: { GITLAB_OIDC_TOKEN: { aud: ${AUDIENCE} } }' to your .gitlab-ci.yml"
    fi

    log "Using GitLab OIDC token"
    exchange_token "${GITLAB_OIDC_TOKEN}"
}

# ---------------------------------------------------------------------------
# Authentication: Jenkins OIDC
# ---------------------------------------------------------------------------
auth_jenkins() {
    require_cmd curl
    require_cmd jq

    local OIDC_TOKEN="${JENKINS_OIDC_TOKEN:-}"

    if [ -z "${OIDC_TOKEN}" ]; then
        die 3 "JENKINS_OIDC_TOKEN is not set. Configure the Jenkins OIDC Credentials Plugin."
    fi

    log "Using Jenkins OIDC token"
    exchange_token "${OIDC_TOKEN}"
}

# ---------------------------------------------------------------------------
# Authentication: Kubernetes ServiceAccount token
# ---------------------------------------------------------------------------
auth_k8s_sa() {
    require_cmd curl
    require_cmd jq

    local TOKEN_PATH="${K8S_SA_TOKEN_PATH:-${DEFAULT_SA_TOKEN_PATH}}"

    if [ ! -f "${TOKEN_PATH}" ]; then
        die 3 "ServiceAccount token not found at ${TOKEN_PATH}"
    fi

    local SA_TOKEN
    SA_TOKEN=$(cat "${TOKEN_PATH}")

    log "Using Kubernetes ServiceAccount token"
    exchange_token "${SA_TOKEN}"
}

# ---------------------------------------------------------------------------
# Authentication: Direct token
# ---------------------------------------------------------------------------
auth_direct_token() {
    if [ -z "${NEBULACR_TOKEN:-}" ]; then
        die 3 "NEBULACR_TOKEN is not set."
    fi

    log "Using pre-existing NebulaCR token (NOT zero-trust)"
    ACCESS_TOKEN="${NEBULACR_TOKEN}"
    TOKEN_EXPIRES_IN="unknown"
    TOKEN_ID="direct"
}

# ---------------------------------------------------------------------------
# Authentication: OIDC browser flow (interactive)
# ---------------------------------------------------------------------------
auth_oidc_browser() {
    require_cmd curl
    require_cmd jq

    # Check if a browser is available
    local OPEN_CMD=""
    if command -v xdg-open &>/dev/null; then
        OPEN_CMD="xdg-open"
    elif command -v open &>/dev/null; then
        OPEN_CMD="open"
    elif command -v wslview &>/dev/null; then
        OPEN_CMD="wslview"
    fi

    log "Starting OIDC browser authentication flow..."
    log "Auth URL: ${AUTH_URL}"

    # Step 1: Initiate the OIDC flow with the NebulaCR auth service
    # This returns an authorization URL that the user opens in their browser.
    local INIT_RESPONSE
    INIT_RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST \
        "${AUTH_URL}/auth/oidc/authorize" \
        -H "Content-Type: application/json" \
        -d "{
            \"redirect_uri\": \"http://localhost:${OIDC_CALLBACK_PORT}/callback\",
            \"scope\": {
                \"tenant\": \"${TENANT}\",
                \"project\": \"${PROJECT}\",
                \"actions\": $(actions_to_json)
            }
        }")

    local INIT_CODE
    INIT_CODE=$(echo "${INIT_RESPONSE}" | tail -1)
    local INIT_BODY
    INIT_BODY=$(echo "${INIT_RESPONSE}" | sed '$d')

    if [ "${INIT_CODE}" != "200" ]; then
        die 3 "Failed to initiate OIDC flow (HTTP ${INIT_CODE})"
    fi

    local AUTH_REDIRECT
    AUTH_REDIRECT=$(echo "${INIT_BODY}" | jq -r '.authorization_url')
    local STATE
    STATE=$(echo "${INIT_BODY}" | jq -r '.state')

    if [ -z "${AUTH_REDIRECT}" ] || [ "${AUTH_REDIRECT}" = "null" ]; then
        die 3 "Auth service did not return an authorization URL"
    fi

    # Step 2: Open the browser (or print the URL for the user)
    echo ""
    echo "Please open this URL in your browser to authenticate:"
    echo ""
    echo "  ${AUTH_REDIRECT}"
    echo ""

    if [ -n "${OPEN_CMD}" ]; then
        ${OPEN_CMD} "${AUTH_REDIRECT}" 2>/dev/null || true
        echo "(Browser should open automatically)"
    fi

    echo "Waiting for authentication callback on port ${OIDC_CALLBACK_PORT}..."

    # Step 3: Start a temporary HTTP server to receive the callback
    # The callback will contain an authorization code that we exchange for a token.
    local CALLBACK_RESPONSE
    CALLBACK_RESPONSE=$(
        # Use bash's built-in TCP handling or netcat to listen for the callback
        if command -v python3 &>/dev/null; then
            python3 -c "
import http.server, urllib.parse, json, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        code = params.get('code', [''])[0]
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h2>Authentication successful!</h2><p>You can close this tab.</p></body></html>')
        print(code, flush=True)

    def log_message(self, *args):
        pass  # Suppress HTTP logs

server = http.server.HTTPServer(('localhost', ${OIDC_CALLBACK_PORT}), Handler)
server.timeout = 120
server.handle_request()
" 2>/dev/null
        else
            die 5 "python3 is required for the OIDC browser flow callback server"
        fi
    )

    if [ -z "${CALLBACK_RESPONSE}" ]; then
        die 3 "No authorization code received (timeout or user cancelled)"
    fi

    log "Authorization code received, exchanging for token..."

    # Step 4: Exchange the authorization code for a NebulaCR token
    local EXCHANGE_RESPONSE
    EXCHANGE_RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST \
        "${AUTH_URL}/auth/oidc/token" \
        -H "Content-Type: application/json" \
        -d "{
            \"code\": \"${CALLBACK_RESPONSE}\",
            \"state\": \"${STATE}\",
            \"redirect_uri\": \"http://localhost:${OIDC_CALLBACK_PORT}/callback\",
            \"scope\": {
                \"tenant\": \"${TENANT}\",
                \"project\": \"${PROJECT}\",
                \"actions\": $(actions_to_json)
            }
        }")

    local EX_CODE
    EX_CODE=$(echo "${EXCHANGE_RESPONSE}" | tail -1)
    local EX_BODY
    EX_BODY=$(echo "${EXCHANGE_RESPONSE}" | sed '$d')

    if [ "${EX_CODE}" != "200" ]; then
        die 3 "Token exchange failed (HTTP ${EX_CODE})"
    fi

    ACCESS_TOKEN=$(echo "${EX_BODY}" | jq -r '.token')
    TOKEN_EXPIRES_IN=$(echo "${EX_BODY}" | jq -r '.expires_in // "300"')
    TOKEN_ID=$(echo "${EX_BODY}" | jq -r '.token_id // "unknown"')

    if [ -z "${ACCESS_TOKEN}" ] || [ "${ACCESS_TOKEN}" = "null" ]; then
        die 3 "Token exchange returned no token"
    fi

    log "NebulaCR token obtained via OIDC browser flow"
}

# ---------------------------------------------------------------------------
# Token exchange: POST identity token to NebulaCR auth service
# ---------------------------------------------------------------------------
exchange_token() {
    local IDENTITY_TOKEN="$1"

    # Build the scope JSON
    local REPO_FIELD=""
    if [ -n "${REPOSITORY}" ]; then
        REPO_FIELD="\"repository\": \"${REPOSITORY}\","
    fi

    local RESPONSE
    RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST \
        "${AUTH_URL}/auth/github-actions/token" \
        -H "Content-Type: application/json" \
        -H "User-Agent: nebulacr-login-sh/${SCRIPT_VERSION}" \
        -d "{
            \"identity_token\": \"${IDENTITY_TOKEN}\",
            \"scope\": {
                \"tenant\": \"${TENANT}\",
                \"project\": \"${PROJECT}\",
                ${REPO_FIELD}
                \"actions\": $(actions_to_json)
            }
        }")

    local HTTP_CODE
    HTTP_CODE=$(echo "${RESPONSE}" | tail -1)
    local BODY
    BODY=$(echo "${RESPONSE}" | sed '$d')

    if [ "${HTTP_CODE}" != "200" ]; then
        local ERR_TYPE
        ERR_TYPE=$(echo "${BODY}" | jq -r '.error // "unknown"' 2>/dev/null || echo "unknown")
        local ERR_MSG
        ERR_MSG=$(echo "${BODY}" | jq -r '.message // "No details"' 2>/dev/null || echo "No details")
        error "NebulaCR authentication failed (HTTP ${HTTP_CODE}): ${ERR_TYPE} - ${ERR_MSG}"

        case "${HTTP_CODE}" in
            401) error "Hint: Verify the OIDC issuer is trusted by NebulaCR" ;;
            403) error "Hint: Verify the identity subject is authorized in access policies" ;;
            404) error "Hint: Verify AUTH_URL is correct: ${AUTH_URL}" ;;
            422) error "Hint: Verify tenant/project/repository exist" ;;
        esac
        exit 3
    fi

    ACCESS_TOKEN=$(echo "${BODY}" | jq -r '.token')
    TOKEN_EXPIRES_IN=$(echo "${BODY}" | jq -r '.expires_in // "300"')
    TOKEN_ID=$(echo "${BODY}" | jq -r '.token_id // "unknown"')

    if [ -z "${ACCESS_TOKEN}" ] || [ "${ACCESS_TOKEN}" = "null" ]; then
        die 3 "Auth service returned 200 but no token in response"
    fi
}

# ---------------------------------------------------------------------------
# Helper: Convert comma-separated actions to JSON array
# ---------------------------------------------------------------------------
actions_to_json() {
    echo "${ACTIONS}" \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | jq -R . \
        | jq -sc .
}

# ---------------------------------------------------------------------------
# Docker login
# ---------------------------------------------------------------------------
docker_login() {
    if [ "${NO_DOCKER}" = true ]; then
        return
    fi

    require_cmd docker

    log "Logging in to Docker registry: ${REGISTRY}"

    echo "${ACCESS_TOKEN}" | docker login "${REGISTRY}" \
        --username "${USERNAME}" \
        --password-stdin

    log "Docker login successful"
}

# ---------------------------------------------------------------------------
# Output results
# ---------------------------------------------------------------------------
output_results() {
    if [ "${JSON_OUTPUT}" = true ]; then
        jq -n \
            --arg registry "${REGISTRY}" \
            --arg tenant "${TENANT}" \
            --arg project "${PROJECT}" \
            --arg token_id "${TOKEN_ID}" \
            --arg expires_in "${TOKEN_EXPIRES_IN}" \
            --arg method "${METHOD}" \
            '{
                registry: $registry,
                tenant: $tenant,
                project: $project,
                token_id: $token_id,
                expires_in: ($expires_in | tonumber? // $expires_in),
                method: $method,
                status: "authenticated"
            }'
    else
        log "Authentication successful"
        log "  Registry:   ${REGISTRY}"
        log "  Tenant:     ${TENANT}"
        log "  Project:    ${PROJECT}"
        log "  Method:     ${METHOD}"
        log "  Token ID:   ${TOKEN_ID}"
        log "  Expires in: ${TOKEN_EXPIRES_IN}s"
        if [ "${NO_DOCKER}" = false ]; then
            log "  Docker:     logged in"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    validate_params
    detect_environment

    # These are set by the auth functions
    ACCESS_TOKEN=""
    TOKEN_EXPIRES_IN=""
    TOKEN_ID=""

    # Run the appropriate authentication method
    case "${METHOD}" in
        github-actions) auth_github_actions ;;
        gitlab-ci)      auth_gitlab_ci ;;
        jenkins)        auth_jenkins ;;
        k8s-sa)         auth_k8s_sa ;;
        token)          auth_direct_token ;;
        oidc-browser)   auth_oidc_browser ;;
        *)              die 2 "Unknown method: ${METHOD}" ;;
    esac

    # Perform docker login
    docker_login

    # Output results
    output_results
}

main "$@"

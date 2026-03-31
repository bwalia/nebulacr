# Authentication

NebulaCR uses a dedicated auth service (`nebula-auth`, port 5001) that issues short-lived JWT tokens consumed by the registry service (`nebula-registry`, port 5000). Authentication follows the Docker Registry Token Authentication specification.

## Table of Contents

- [Bootstrap Admin (Development Mode)](#bootstrap-admin-development-mode)
- [OIDC Integration](#oidc-integration)
- [Token Lifecycle](#token-lifecycle)
- [Docker CLI Login Flow](#docker-cli-login-flow)
- [CI/CD Integration](#cicd-integration)
- [API Examples](#api-examples)

---

## Bootstrap Admin (Development Mode)

For initial setup and local development, NebulaCR provides a bootstrap admin account that authenticates via HTTP Basic auth. The default credentials are `admin:admin`.

The bootstrap admin is configured through environment variables on the auth service:

```bash
NEBULACR_AUTH__BOOTSTRAP_ADMIN__USERNAME=admin
NEBULACR_AUTH__BOOTSTRAP_ADMIN__PASSWORD_HASH=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
```

The password hash is a SHA-256 hex digest. To generate a hash for a custom password:

```bash
echo -n 'your-password' | sha256sum | cut -d' ' -f1
```

Or in the TOML config file (`/etc/nebulacr/config.toml`):

```toml
[auth.bootstrap_admin]
username = "admin"
password_hash = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
```

**WARNING**: Disable the bootstrap admin in production after configuring OIDC providers and access policies. Remove or comment out the `[auth.bootstrap_admin]` section entirely.

---

## OIDC Integration

NebulaCR supports multiple OIDC identity providers simultaneously. The auth service validates incoming identity tokens against each provider's JWKS endpoint.

### Google Workspace / Cloud Identity

```toml
[[auth.oidc_providers]]
issuer_url = "https://accounts.google.com"
client_id = "your-google-client-id.apps.googleusercontent.com"
client_secret = "your-google-client-secret"
subject_claim = "email"
tenant_claim = "hd"   # Hosted domain claim maps users to tenants
```

Helm values:

```yaml
oidc:
  enabled: true
  issuerUrl: "https://accounts.google.com"
  clientId: "your-google-client-id.apps.googleusercontent.com"
  clientSecret: "your-google-client-secret"
  tenantClaim: "hd"
  scopes:
    - openid
    - profile
    - email
```

### GitHub Actions OIDC

GitHub Actions provides OIDC tokens natively with no client secret required. This is the recommended approach for CI/CD pipelines.

```toml
[[auth.oidc_providers]]
issuer_url = "https://token.actions.githubusercontent.com"
client_id = "nebulacr"
subject_claim = "sub"
# Optional: map repository_owner to tenant
# tenant_claim = "repository_owner"
```

The GitHub OIDC `sub` claim contains the full context, for example:
`repo:myorg/myrepo:ref:refs/heads/main`

### GitLab CI OIDC

```toml
[[auth.oidc_providers]]
issuer_url = "https://gitlab.com"
client_id = "nebulacr"
subject_claim = "sub"
# GitLab sub format: "project_path:group/project:ref_type:branch:ref:main"
```

For self-managed GitLab, replace the issuer URL with your GitLab instance URL.

### Azure AD / Entra ID

```toml
[[auth.oidc_providers]]
issuer_url = "https://login.microsoftonline.com/{tenant-id}/v2.0"
client_id = "your-azure-client-id"
subject_claim = "sub"
tenant_claim = "tid"
```

Replace `{tenant-id}` with your Azure AD tenant ID.

### Multiple Providers

You can configure multiple providers simultaneously. The auth service tries each provider's JWKS in order when validating an incoming token:

```toml
[[auth.oidc_providers]]
issuer_url = "https://accounts.google.com"
client_id = "google-client-id.apps.googleusercontent.com"
client_secret = "google-secret"
subject_claim = "email"
tenant_claim = "hd"

[[auth.oidc_providers]]
issuer_url = "https://token.actions.githubusercontent.com"
client_id = "nebulacr"
subject_claim = "sub"

[[auth.oidc_providers]]
issuer_url = "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"
client_id = "azure-client-id"
subject_claim = "sub"
tenant_claim = "tid"
```

---

## Token Lifecycle

NebulaCR issues short-lived JWT access tokens. The default TTL is 300 seconds (5 minutes).

### Token Structure

Issued tokens contain these claims:

| Claim | Description |
|-------|-------------|
| `iss` | Issuer, matches `auth.issuer` config (default: `nebulacr`) |
| `aud` | Audience, matches `auth.audience` config (default: `nebulacr-registry`) |
| `sub` | Subject identifier (username or OIDC subject) |
| `exp` | Expiration time (Unix timestamp) |
| `iat` | Issued-at time (Unix timestamp) |
| `access` | Array of granted repository access scopes |

### Token TTL Configuration

In config file:

```toml
[auth]
token_ttl_seconds = 300    # 5 minutes (default)
```

Via environment variable:

```bash
NEBULACR_AUTH__TOKEN_TTL_SECONDS=300
```

Per-tenant TTL can be overridden using the TokenPolicy CRD:

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: TokenPolicy
metadata:
  name: acme-token-policy
  namespace: nebulacr
spec:
  tenantRef: acme
  maxTtlSeconds: 600
  defaultTtlSeconds: 300
  allowedIpRanges:
    - "10.0.0.0/8"
  requireMfa: false
```

### Signing Algorithms

NebulaCR supports RS256 (RSA) and EdDSA (Ed25519) for JWT signing:

```toml
[auth]
signing_algorithm = "RS256"             # or "EdDSA"
signing_key_path = "/etc/nebulacr/keys/private.pem"
verification_key_path = "/etc/nebulacr/keys/public.pem"
```

To generate an RSA key pair:

```bash
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
chmod 640 private.pem
chmod 644 public.pem
```

To generate an Ed25519 key pair:

```bash
openssl genpkey -algorithm Ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

---

## Docker CLI Login Flow

Docker CLI authentication follows the standard Docker Registry V2 token auth flow:

1. Docker client calls `GET /v2/` on the registry (port 5000).
2. Registry responds with `401 Unauthorized` and a `Www-Authenticate` header pointing to the auth service.
3. Docker client sends credentials to the auth service token endpoint.
4. Auth service validates credentials and returns a JWT.
5. Docker client retries the original request with the JWT in the `Authorization: Bearer <token>` header.

### Login with Bootstrap Admin

```bash
docker login localhost:5000 -u admin -p admin
```

### Push and Pull

```bash
# Tag an image for the registry (tenant/project/name format)
docker tag myimage:latest localhost:5000/demo/default/myimage:latest

# Push
docker push localhost:5000/demo/default/myimage:latest

# Pull
docker pull localhost:5000/demo/default/myimage:latest
```

### Standard 2-Segment Docker Paths

For compatibility with standard Docker 2-segment paths (e.g., `library/nginx`), NebulaCR uses the default tenant `_`:

```bash
# These are equivalent -- both use the default tenant "_"
docker pull localhost:5000/library/nginx:latest
docker pull localhost:5000/_/library/nginx:latest
```

---

## CI/CD Integration

### GitHub Actions (OIDC Zero-Trust)

No long-lived credentials are needed. GitHub provides an OIDC token to the workflow, which NebulaCR exchanges for a registry token.

```yaml
name: Push Image
on:
  push:
    branches: [main]

permissions:
  id-token: write   # Required for OIDC token
  contents: read

jobs:
  push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Get OIDC token
        id: oidc
        run: |
          OIDC_TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=nebulacr" | jq -r '.value')
          echo "::add-mask::$OIDC_TOKEN"
          echo "token=$OIDC_TOKEN" >> "$GITHUB_OUTPUT"

      - name: Exchange for registry token
        id: registry
        run: |
          REGISTRY_TOKEN=$(curl -s -X POST \
            "https://registry.example.com/auth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
            -d "subject_token=${{ steps.oidc.outputs.token }}" \
            -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
            -d "scope=repository:myorg/myproject/myimage:push,pull" | jq -r '.token')
          echo "::add-mask::$REGISTRY_TOKEN"
          echo "token=$REGISTRY_TOKEN" >> "$GITHUB_OUTPUT"

      - name: Login to NebulaCR
        run: |
          echo "${{ steps.registry.outputs.token }}" | \
            docker login registry.example.com -u oauth2 --password-stdin

      - name: Build and push
        run: |
          docker build -t registry.example.com/myorg/myproject/myimage:${{ github.sha }} .
          docker push registry.example.com/myorg/myproject/myimage:${{ github.sha }}
```

### GitLab CI (OIDC)

```yaml
push_image:
  image: docker:latest
  id_tokens:
    NEBULACR_TOKEN:
      aud: nebulacr
  script:
    - REGISTRY_TOKEN=$(curl -s -X POST
        "https://registry.example.com/auth/token"
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
        -d "subject_token=${NEBULACR_TOKEN}"
        -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt"
        -d "scope=repository:myorg/myproject/myimage:push,pull" | jq -r '.token')
    - echo "$REGISTRY_TOKEN" | docker login registry.example.com -u oauth2 --password-stdin
    - docker build -t registry.example.com/myorg/myproject/myimage:${CI_COMMIT_SHORT_SHA} .
    - docker push registry.example.com/myorg/myproject/myimage:${CI_COMMIT_SHORT_SHA}
```

### Generic CI (Basic Auth)

For CI systems without OIDC support, use basic auth with a service account:

```bash
# Get a token using basic auth
TOKEN=$(curl -s -u "ci-user:ci-password" \
  "https://registry.example.com:5001/auth/token?service=nebulacr-registry&scope=repository:tenant/project/image:push,pull" \
  | jq -r '.token')

# Use the token
docker login registry.example.com -u oauth2 -p "$TOKEN"
```

---

## API Examples

### Request a Token with Basic Auth

```bash
# Request a token for a specific repository scope
curl -s -u admin:admin \
  "http://localhost:5001/auth/token?service=nebulacr-registry&scope=repository:demo/default/myimage:push,pull"
```

Response:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "issued_at": "2025-01-15T10:30:00Z"
}
```

### Use a Token with the Registry API

```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Check API version support
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/v2/

# List tags for a repository
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/v2/demo/default/myimage/tags/list

# Get a manifest
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  http://localhost:5000/v2/demo/default/myimage/manifests/latest
```

### Full Push Workflow with curl

```bash
# Step 1: Get a push token
TOKEN=$(curl -s -u admin:admin \
  "http://localhost:5001/auth/token?service=nebulacr-registry&scope=repository:demo/default/myimage:push,pull" \
  | jq -r '.token')

# Step 2: Start a blob upload
UPLOAD_URL=$(curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/v2/demo/default/myimage/blobs/uploads/" \
  -D - -o /dev/null | grep -i location | tr -d '\r' | awk '{print $2}')

# Step 3: Upload blob data (chunked or monolithic)
curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @layer.tar.gz \
  "${UPLOAD_URL}&digest=sha256:$(sha256sum layer.tar.gz | cut -d' ' -f1)"

# Step 4: Upload the manifest
curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  --data-binary @manifest.json \
  "http://localhost:5000/v2/demo/default/myimage/manifests/v1.0"
```

### Token Rate Limits

Token issuance is rate-limited separately from the registry API:

```bash
NEBULACR_RATE_LIMIT__TOKEN_ISSUE_RPM=60   # 60 tokens per minute per tenant
```

If you hit the rate limit, you will receive a `429 Too Many Requests` response. Wait and retry, or increase the limit for your tenant.

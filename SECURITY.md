# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in NebulaCR, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, send an email to: **security@workstation.co.uk**

Include:

- A description of the vulnerability
- Steps to reproduce or a proof of concept
- The potential impact
- Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment**: Within 48 hours of your report
- **Initial assessment**: Within 5 business days
- **Fix development**: Depends on severity, typically within 30 days
- **Disclosure**: Coordinated with the reporter after a fix is available

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older versions | No |

## Disclosure Policy

- We will not disclose vulnerabilities publicly until a fix is available.
- We will credit reporters in the release notes (unless they prefer anonymity).
- We ask reporters to avoid public disclosure until we have released a fix.

## Security Best Practices

When deploying NebulaCR:

- Run containers as non-root (default in our images)
- Enable TLS for all external traffic
- Use OIDC authentication in production (not bootstrap admin)
- Rotate JWT signing keys periodically
- Enable network policies to restrict pod-to-pod traffic
- Keep images updated to the latest release

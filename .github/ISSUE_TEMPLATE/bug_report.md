---
name: Bug report
about: Report a bug in awesome-lambda-auth
title: '[Bug] '
labels: bug
assignees: ''
---

## Describe the bug

A clear and concise description of the bug.

## Steps to reproduce

1. Deploy with …
2. Call `…` (method and path) with …
3. Observe …

## Expected behaviour

What you expected to happen, and, if you know it, what the reference awesome-node-auth answers.

## Actual behaviour

What actually happens. Include the failing request and response (method, path, status, body), and the relevant log lines from CloudWatch, with every secret and personal data removed.

## Environment

| Field | Value |
|-------|-------|
| `awesome-lambda-auth` commit | |
| Deployed with | `scripts/deploy.sh` / own template / … |
| Region | |
| Store driver | DynamoDB / memory |
| Optional features on | admin / tools / webhook queue / script runner / SSE / CloudFront |
| Client and version | Angular / Flutter / React / other |

## Additional context

Anything else: the relevant part of the configuration document (redacted), screenshots, a minimal reproduction.

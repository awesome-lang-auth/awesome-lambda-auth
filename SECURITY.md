# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| `main` (no tagged release yet) | ✅ |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through a [GitHub Security Advisory](https://github.com/awesome-lang-auth/awesome-lambda-auth/security/advisories/new).

Please include:

- a description of the vulnerability and its impact;
- steps to reproduce, or a proof of concept;
- the commit or version you tested, and the relevant configuration (with every secret removed);
- a suggested fix, if you have one.

## Response timeline

- **Acknowledgement:** within 72 hours.
- **Assessment and triage:** within 5 business days.
- **Fix and advisory:** published once the fix is on `main`.

## Scope

This policy covers this repository: the Lambda functions, the DynamoDB stores, the integrations with AWS services, and the SAM template (IAM grants, public endpoints, what each resource can cost).

A vulnerability in the auth logic itself, such as token issuance, verification or the route handlers, usually belongs to the core. Report it to [awesome-go-auth](https://github.com/awesome-lang-auth/awesome-go-auth/security/advisories/new). A vulnerability in the protocol belongs to the reference, [awesome-node-auth](https://github.com/awesome-lang-auth/awesome-node-auth/security/advisories/new). If you are not sure where it belongs, report it here.

## Operating a deployment safely

- Keep every secret in AWS Secrets Manager, as the template does. Never put one in the configuration document or in an environment variable you write by hand.
- The optional features (admin console, tools, webhook queue, script runner, SSE) are off by default. `docs/config-reference.md` and `docs/cost-model.md` state what each one exposes and what it can cost before you turn it on.

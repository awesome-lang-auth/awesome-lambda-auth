# Contributing to awesome-lambda-auth

Thank you for your interest in contributing to `awesome-lambda-auth`, the serverless (AWS Lambda + DynamoDB) auth server of the awesome-lang-auth family.

## Development setup

You need Docker. Go does not have to be installed on the host: `./scripts/toolchain.sh` runs every Go command in a pinned `golang` container.

```bash
git clone https://github.com/awesome-lang-auth/awesome-lambda-auth
cd awesome-lambda-auth
./scripts/toolchain.sh go vet ./...
./scripts/toolchain.sh go test -race ./...
```

The DynamoDB store tests need DynamoDB Local. The README's "Toolchain" section shows how to start it on a Docker network and point the tests at it. A change is not ready while those tests skip.

## How to contribute

1. **Fork** the repository and create a branch from `main`.
2. Keep the change focused, and follow the style of the file you edit. Comments explain *why*, with citations; this codebase is densely commented on purpose.
3. Add or update tests. Assert on real request and response shapes; a test that would still pass with the feature removed is not a test.
4. Make sure `gofmt -l .` prints nothing, and that `go vet ./...` and `go test -race ./...` pass with DynamoDB Local running.
5. If you change `infra/sam/template.yaml`, `infra/sam/template_test.go` must still pass.
6. Open a **pull request** against `main`. Use [Conventional Commits](https://www.conventionalcommits.org) for the title (`feat:`, `fix:`, `docs:`, …).

## The rules of this project

- **Wire compatibility.** The family's clients must work against a deployed stack with only a base-URL change. Endpoint paths, body fields and status codes follow the reference, [awesome-node-auth](https://github.com/awesome-lang-auth/awesome-node-auth).
- **No fork of the core.** The auth logic lives in [awesome-go-auth](https://github.com/awesome-lang-auth/awesome-go-auth) and is imported, never copied. A fix that belongs in the core goes there first.
- **Deviations are registered.** Every deliberate difference from the reference goes into `cmd/auth/deviations.go`, with a row in `docs/deviations.md`; a test keeps the two in sync.
- **No secrets or account data in the repository.** Never commit a secret, an AWS account id, an ARN, an e-mail address or a real domain. `infra/sam/template_test.go` refuses most of them.

## Reporting bugs and requesting features

Use the [issue templates](.github/ISSUE_TEMPLATE/), and search the existing issues before you open a new one.

## Security issues

Do **not** open a public issue for a security vulnerability. [SECURITY.md](SECURITY.md) describes how to report one privately.

## Code of Conduct

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your work is licensed under the [MIT License](LICENSE) that covers this project.

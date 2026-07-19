# Contributing

Thanks for your interest in contributing to Trace.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/trace.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make changes
5. Run tests: `go test ./... -short -count=1`
6. Run linter: `go vet ./...`
7. Commit and push
8. Open a pull request

## Development Requirements

- Go 1.26+
- No external dependencies beyond Go modules

## Code Style

- Follow standard Go formatting (`gofmt`)
- Run `go vet ./...` before committing
- All exports must have doc comments
- Keep the single-binary philosophy — no external runtime dependencies

## Testing

- Write tests for new functionality
- Existing tests must pass before merging
- Use `-short` for quick local runs
- Full test suite runs in CI

## Pull Request Process

1. Ensure all tests pass
2. Update docs if you change public interfaces
3. Add a changelog entry if your change is user-facing
4. PRs should target the `main` branch

## Code of Conduct

Be respectful. We're all here to build something useful.

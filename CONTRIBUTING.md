# Contributing

Contributions are welcome. By participating, you agree to maintain a respectful and constructive environment.

For coding standards, testing patterns, architecture guidelines, commit conventions, and all
development practices, refer to the **[Development Guide](https://github.com/rios0rios0/guide/wiki)**.

## Prerequisites

- Termux on Android (aarch64)
- [Make](https://www.gnu.org/software/make/)
- clang (`pkg install clang`)

## Development Workflow

1. Fork and clone the repository
2. Create a branch: `git checkout -b feat/my-change`
3. Build:
   ```bash
   make
   ```
4. Make your changes
5. Validate:
   ```bash
   make test
   ```
6. Update `CHANGELOG.md` under `[Unreleased]`
7. Commit following the [commit conventions](https://github.com/rios0rios0/guide/wiki/Git-Flow)
8. Open a pull request against `main`

# Contributing

Pull requests to `otpki/circl` target the `iogo` branch. Keep changes focused and
avoid unrelated formatting, refactoring, or generated-file churn. Discuss
substantial cryptographic or public API changes with maintainers before starting.

Include tests for changed behavior. For cryptographic changes, include relevant
specifications and test vectors. Describe public API and compatibility changes
in the PR, and pass the existing CI checks.

Use the existing Makefile and lint configuration:

```sh
make build
make test
make test NOASM=1
make lint
```

`make bootstrap` installs the linter version used by CI. For CI parity, use a
Go version listed in `.github/workflows/ci-actions.yml`. Follow existing source
style and regenerate affected generated files from their generators.

## Contributing upstream

Prepare upstream contributions on separate branches based on Cloudflare CIRCL's
current `main`. Keep upstream's `github.com/cloudflare/circl` module/import paths
and submit focused changes with tests. OTPKI module renames and fork-specific
documentation or CI changes stay on our downstream branch. Follow
[upstream contribution guidance](https://github.com/cloudflare/circl#contributing).

## Security and licensing

Report suspected vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Preserve the existing BSD licenses, source notices,
and upstream attribution.

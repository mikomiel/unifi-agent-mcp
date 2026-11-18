# UniFi Agent MCP agent instructions

Build a portable UniFi Network MCP under Apache-2.0. Use GitHub pull requests against `main` to integrate changes.

## Checks

Run these checks from the repository root before a public push. They require Python 3.12 and Gitleaks.

```sh
python3 scripts/check_estate_identifiers.py
gitleaks dir --redact=100 --no-banner .
gitleaks git --redact=100 --no-banner --log-opts='--all' .
git log --all --format=%B | gitleaks stdin --redact=100 --no-banner
```

Run the package checks declared in [CI](.github/workflows/ci.yml) when a package manifest is present.

## Project boundaries

Use the UniFi Network Integration API. Read-only mode is the default. Approval mode submits typed proposals for user-defined firewall rules to the broker. Give the trusted executor sole access to the UniFi write credential.

Keep credentials and deployment configuration outside the package. Use synthetic fixtures. Scan the full public commit range for private identifiers and secrets, including messages and generated files.

## Pull requests

Use an isolated branch and attach exact-head CI evidence to the pull request. The [contribution guide](CONTRIBUTING.md) describes which changes need a maintainer merge. Each release needs maintainer authorization for its version and commit.

Use [OpenSpec](openspec/config.yaml) to record intended behavior and acceptance checks. Use the [security policy](SECURITY.md) for vulnerability reports. Report checks as PASS, FAIL, NOT RUN, or UNAVAILABLE and distinguish repository changes from deployment evidence.

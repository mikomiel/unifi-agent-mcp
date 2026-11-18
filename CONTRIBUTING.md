# Contributing

Use GitHub Issues to report a reproducible defect or propose a feature. Include the UniFi Network version and MCP client when relevant. Use synthetic inputs in examples, tests, and command output. Report vulnerabilities through [the private reporting process](SECURITY.md).

Open pull requests against `main`. Use [Conventional Commits](https://www.conventionalcommits.org/) and explain the user-visible behavior and the checks you ran. Follow the public-content checks in [AGENTS.md](AGENTS.md).

The protected branch requires green CI and independent review of the exact pull request head. Merge Guard may merge approved changes in the paths declared in [.github/merge-guard.toml](.github/merge-guard.toml). A maintainer merges changes to workflows, tests, scripts, dependencies, release manifests, and other guarded paths.

Release Please prepares a release pull request from versioned changes. A maintainer approves the exact version and source commit before merging it. The workflow reads the repository secret `RELEASE_PLEASE_TOKEN`.

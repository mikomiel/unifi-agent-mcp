# Contributing

Use GitHub Issues to report a reproducible defect or propose a feature. Include the UniFi Network version and MCP client when relevant. Use synthetic inputs in examples, tests, and command output. Report vulnerabilities through [the private reporting process](SECURITY.md).

Open pull requests against `main`. Use [Conventional Commits](https://www.conventionalcommits.org/) and explain the user-visible behavior and the checks you ran. Follow the public-content checks in [AGENTS.md](AGENTS.md).

The protected branch requires green CI and independent review of the exact pull request head. Merge Guard may merge approved changes in the paths declared in [.github/merge-guard.toml](.github/merge-guard.toml). A maintainer merges changes to workflows, tests, scripts, dependencies, release manifests, and other guarded paths.

Release Please prepares a release pull request from versioned changes. A maintainer approves the exact version and source commit before merging it. The workflow reads the repository secret `RELEASE_PLEASE_TOKEN`.

After the merge, Release Please creates the version tag and a draft GitHub release. Build the wheel from that tag and test it in a clean environment. Upload the approved wheel and its SHA-256 checksum to the draft, then publish it. Publishing makes the assets immutable. [GitHub release management](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)

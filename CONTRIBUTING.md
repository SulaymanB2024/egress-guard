# Contributing

Use Python 3.12 or newer and an isolated environment. Install the local project with its pinned transport dependency, then run:

```sh
python -B -m unittest discover -s tests -v
```

Tests must explicitly create temporary application state. Mock `networksetup`, authorization dialogs, native notifications and provider APIs. The loopback proxy integration test starts only local fixtures, compares the origin TLS certificate and checks that refused requests never reach the origin. It must not alter operating system settings or trust stores.

Keep changes focused. Add regression coverage for a real security or recovery boundary. Do not submit tests that contact a production canary, embed credentials, depend on private machine paths, or modify a real user's proxy.

Before release, run the [release checks](docs/releasing.md). This repository does not use GitHub Actions as a release gate; maintainers run local checks and publish the reviewed artifact.

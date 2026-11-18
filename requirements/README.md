# Reviewed dependency locks

`runtime.lock` pins the transport's complete dependency graph across platform branches. `build.lock` pins the source build backend and its dependencies. Every entry has SHA-256 artifact hashes. The macOS installer uses pip's hash-checking mode, requires prebuilt dependency wheels, installs the local project without dependency resolution or build isolation, then runs `pip check`. A source install includes the locked build helpers; a supplied wheel needs only the runtime lock.

Both tools validate a constrained ASCII exact-pin, marker and SHA-256 format without comments, rejecting pip directives and URLs. The installer gives pip private snapshots of those validated bytes, so later source-file changes cannot alter its dependency inputs. The installer refuses an existing environment. Failed fresh installs remove only the environment they created and preserve application data. These locks improve repeatability and artifact checking; they do not establish that a dependency is free of vulnerabilities. Trust in the downloaded release and the user's Python installation remains necessary.

To review the public package inventory without networking:

```sh
python3 -B scripts/audit-dependencies.py
```

To query OSV explicitly:

```sh
python3 -B scripts/audit-dependencies.py --online
```

Only release package names and versions are sent. Browsing activity, installed software inventory, user configuration and credentials are excluded. All platform branches are checked. Exit status is `0` for a complete query with no known matches, `1` for unresolved advisory matches, and `2` when review could not complete. Offline inventory mode also returns `0` and labels itself `inventory_only`. Results do not determine whether an affected path is reachable in Egress Guard.

## Current upstream boundary — November 18, 2026

The locks contain Tornado 6.5.10 because released mitmproxy 12.3.1 requires `tornado>=6.5.0,<=6.5.10`. OSV reports these four open package advisories:

| Advisory | Upstream fix |
| --- | --- |
| [HTTP folded-header parsing](https://github.com/tornadoweb/tornado/security/advisories/GHSA-pcg2-g6cj-q92c) | Tornado 6.6.0 |
| [Chunked-body CPU/memory use](https://github.com/tornadoweb/tornado/security/advisories/GHSA-r4j5-9xpp-3985) | Tornado 6.6.0 |
| [RedirectHandler redirects](https://github.com/tornadoweb/tornado/security/advisories/GHSA-pw9p-v7r6-gx4p) | Tornado 6.6.0 |
| [Redirect follow-up](https://github.com/tornadoweb/tornado/security/advisories/GHSA-5cjw-f85j-cv6r) | Tornado 6.6.1 |

Source tracing and an isolated import check found no affected path through the shipped commands. Egress Guard selects `DumpMaster` and its h11/mitmproxy HTTP parsing. Its dashboard and outbound clients use the Python standard library. Loading the regular proxy, parser and onboarding app imported zero Tornado modules. The separate `mitmweb` executable starts a Tornado server; it is not Egress Guard's dashboard and is outside this assessment.

The package alerts remain open. The dependency constraint is preserved, and no patched-version or clean-scan claim is made. Re-lock and repeat transport checks when a maintained parent release permits Tornado 6.6.1 or later. [Upstream PR #8566](https://github.com/mitmproxy/mitmproxy/pull/8566) currently permits 6.6.0 only and does not resolve the follow-up advisory.

## Refresh deliberately

Generated with uv 0.11.19. Review version, marker and hash changes before release; updates are never scheduled automatically.

```sh
uv pip compile pyproject.toml --universal --python-version 3.12 --generate-hashes --no-header --no-annotate --no-build --default-index https://pypi.org/simple -o requirements/runtime.lock
uv pip compile requirements/build.in --universal --python-version 3.12 --generate-hashes --no-header --no-annotate --no-build --default-index https://pypi.org/simple -o requirements/build.lock
```

References: [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/), [uv lock generation](https://docs.astral.sh/uv/pip/compile/), [OSV batch API](https://google.github.io/osv.dev/api/post-v1-querybatch/).

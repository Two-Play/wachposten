# Contributing

- Work on a branch and open a pull request into `develop`; `develop` goes into `main` by pull
  request as well.
- `ci-ok` (format, clippy, tests) must be green on both; pull requests into `main` also need
  `vm-ok`, which builds the RPM in Fedora and runs `test/vm.py --rpm` in a VM, and
  `packages-ok`, which builds and installs the RPM, Debian and Arch packages.
- Code, comments and documentation are in English; the window's German texts live in
  `crates/app/translations/de/LC_MESSAGES/wachposten.po`.

Before a pull request:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 test/vm.py          # needs KVM, QEMU and xorriso; no root
```

## Making a release

1. On a branch from `develop`, raise the version in `Cargo.toml`, `packaging/wachposten.spec`
   (`Version`, `Release: 1`) and `packaging/arch/PKGBUILD` (`pkgver`, `pkgrel=1`). Move the
   entries under `[Unreleased]` in `CHANGELOG.md` into a new section `[x.y.z] - date` and
   update the links at the bottom.
2. Pull request into `develop`, then the release pull request `develop` → `main`.
3. Tag the merge commit on `main` and push the tag:

   ```bash
   git checkout main && git pull
   git tag -a v0.1.0 -m "Wachposten 0.1.0"
   git push origin v0.1.0
   ```

4. `release.yml` checks that the tag matches all versions, builds the packages and creates a
   draft release with them, `SHA256SUMS` and the changelog section. Read it on GitHub and
   publish it.

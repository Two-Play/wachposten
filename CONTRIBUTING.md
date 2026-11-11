# Contributing

- Work on a branch and open a pull request into `develop`; `develop` goes into `main` by pull
  request as well.
- `ci-ok` (format, clippy, tests) must be green on both; pull requests into `main` also need
  `vm-ok`, which builds the RPM in Fedora and runs `test/vm.py --rpm` in a VM.
- Code, comments and documentation are in English; the window's German texts live in
  `crates/app/translations/de/LC_MESSAGES/wachposten.po`.

Before a pull request:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 test/vm.py          # needs KVM, QEMU and xorriso; no root
```

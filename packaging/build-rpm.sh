#!/bin/sh
# Builds the RPM from the working tree, with all crates vendored so rpmbuild works offline.
# Output: target/rpm/RPMS/<arch>/wachposten-*.rpm
set -eu
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
top="$PWD/target/rpm"
stage="$top/stage/wachposten-$version"
rm -rf "$top/stage"
mkdir -p "$stage" "$top/SOURCES"
# Tracked and new (not ignored) files, so uncommitted work is packaged too.
git ls-files -co --exclude-standard -z | xargs -0 cp --parents -t "$stage"
(cd "$stage" && mkdir -p .cargo && cargo vendor --locked --quiet vendor > .cargo/config.toml)
tar -C "$top/stage" -czf "$top/SOURCES/wachposten-$version.tar.gz" "wachposten-$version"
# With Rust from rustup instead of the cargo/rust packages, rpmbuild would refuse the
# BuildRequires; the toolchain is there, so skip that check.
nodeps=""
if ! rpm -q cargo >/dev/null 2>&1 && command -v cargo >/dev/null; then
    nodeps="--nodeps"
fi
rpmbuild --define "_topdir $top" $nodeps -bb packaging/wachposten.spec
ls "$top"/RPMS/*/wachposten-*.rpm

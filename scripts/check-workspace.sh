#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo +stable metadata --no-deps --format-version 1 >/dev/null
cargo +stable fmt --all --check
cargo +stable clippy --workspace --all-targets --all-features -- -D warnings
cargo +stable clippy --workspace --all-targets --all-features -- -W clippy::missing_docs_in_private_items
cargo +stable clippy --workspace --lib --bins --examples --all-features -- \
  -D warnings \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic
cargo +stable test --workspace --all-features
cargo +stable test --workspace --doc
RUSTDOCFLAGS="-D warnings" cargo +stable doc --workspace --no-deps
RUSTDOCFLAGS="-D warnings" cargo +stable doc --workspace --no-deps --document-private-items
cargo +stable check --workspace
cargo +stable tree -d
cargo +stable tree -e features

python3 - <<'PY'
import pathlib
import tomllib
import sys

root = pathlib.Path(".")
workspace = tomllib.loads(root.joinpath("Cargo.toml").read_text())
members = [root / member for member in workspace["workspace"]["members"]]

required_docs = ["README.md", "architecture.md", "limitations.md", "designdecisions.md"]
missing = []
for member in members:
    for name in required_docs:
        if not (member / name).exists():
            missing.append(f"{member}/{name}")

if missing:
    print("Missing required crate docs:", file=sys.stderr)
    for path in missing:
        print(f"  {path}", file=sys.stderr)
    sys.exit(1)

def allowed_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if stripped.startswith("//!") or stripped.startswith("///") or stripped.startswith("//"):
        return True
    if stripped.startswith("#!"):
        return True
    if stripped.startswith("#["):
        return True
    if (
        stripped.startswith("mod ")
        or stripped.startswith("pub mod ")
        or stripped.startswith("pub(crate) mod ")
        or stripped.startswith("pub(super) mod ")
        or (stripped.startswith("pub(in ") and " mod " in stripped)
    ):
        return True
    if (
        stripped.startswith("pub use ")
        or stripped.startswith("pub(crate) use ")
        or stripped.startswith("pub(super) use ")
        or (stripped.startswith("pub(in ") and " use " in stripped)
        or stripped.startswith("use ")
    ):
        return True
    return False

offenders = []
for path in sorted(root.glob("**/src/lib.rs")) + sorted(root.glob("**/src/**/mod.rs")):
    rel = path.relative_to(root)
    in_use_block = False
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        stripped = line.strip()
        if in_use_block:
            if stripped.endswith(";"):
                in_use_block = False
            continue
        if not allowed_line(line):
            offenders.append(f"{rel}:{lineno}:{line.strip()}")
            break
        if (stripped.startswith("pub use ") or stripped.startswith("use ")) and not stripped.endswith(";"):
            in_use_block = True

if offenders:
    print("lib.rs/mod.rs module-wiring violations:", file=sys.stderr)
    for offender in offenders:
        print(f"  {offender}", file=sys.stderr)
    sys.exit(1)

main_offenders = []
for path in sorted(root.glob("**/src/main.rs")):
    rel = path.relative_to(root)
    text = path.read_text()
    if any(token in text for token in ["struct ", "enum ", "impl ", "trait ", "mod tests", "#[cfg(test)]"]):
        main_offenders.append(f"{rel}:main.rs should stay bootstrap-only")
        continue
    significant_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and not line.strip().startswith("//")
        and not line.strip().startswith("#!")
        and not line.strip().startswith("#[")
        and not line.strip().startswith("mod ")
        and not line.strip().startswith("use ")
    ]
    if len(significant_lines) > 8:
        main_offenders.append(
            f"{rel}:main.rs has {len(significant_lines)} significant lines and is no longer thin"
        )

if main_offenders:
    print("main.rs bootstrap violations:", file=sys.stderr)
    for offender in main_offenders:
        print(f"  {offender}", file=sys.stderr)
    sys.exit(1)
PY

if rg -n '\bunsafe\b' --glob '!target/**' --glob '*.rs' \
    | rg -v 'forbid\(unsafe_code\)|deny\(unsafe_code\)|// SAFETY:' >/tmp/boomerang-unsafe-check.txt; then
  echo "Unsafe code markers found:" >&2
  cat /tmp/boomerang-unsafe-check.txt >&2
  exit 1
fi

if rg -n '\b(todo!|unimplemented!)\b' --glob '!target/**' --glob '*.rs' >/tmp/boomerang-todo-check.txt; then
  echo "Incomplete implementation markers found:" >&2
  cat /tmp/boomerang-todo-check.txt >&2
  exit 1
fi

if rg -n '/Users/bedlam/Desktop/(getting_rusty|bitceptron)/boomerang' \
  README.md Architecture.md DesignDecisions.md Limitations.md docs poc crates >/tmp/boomerang-doc-path-check.txt; then
  echo "Machine-specific documentation links found:" >&2
  cat /tmp/boomerang-doc-path-check.txt >&2
  exit 1
fi

# Contributing to podpi.sh

Thanks for wanting to help. This project has an unusual constraint that shapes
everything below: **a competent stranger must be able to read `podpi.sh` and
convince themselves it does what it claims.** People may rely on its output in
proceedings where they cannot afford to be wrong.

That makes auditability the primary design goal — ahead of brevity, cleverness and
feature count.

## The bar

Before opening a pull request:

```bash
make check      # bash -n + shellcheck + --self-test
```

All three must pass. CI additionally runs the suite on macOS, under its real
Bash 3.2, and asserts a pinned cross-platform manifest digest.

## House style

**Boring, explicit Bash.** If there is a clever one-liner and a plain five-line
version, use the plain one and comment it.

- `#!/usr/bin/env bash` with `set -euo pipefail`.
- **Never `eval`.** Never construct a command from a filename.
- Quote every pathname. Use arrays for argument lists.
- Must stay ShellCheck-clean. A `# shellcheck disable=` needs a comment saying why.
- **Bash 3.2 compatible** — stock macOS `/bin/bash`. That rules out `mapfile`,
  `readarray`, `declare -A`, `${var^^}`, `|&`, `&>>`, `;;&`, negative array indices
  and `declare -g`. Use `while IFS= read -r -d ''` and sorted files with `comm`.
- **Portable tools only.** No `realpath`, no `sort -z`, no `find -printf`, no GNU
  `stat -c` outside the portability layer. Every platform difference belongs in
  `detect_platform()` and nowhere else.
- Indent four spaces. Functions get a comment saying what they do and what they set.

## Rules that are not negotiable

These are the properties the tool exists to provide. A change that breaks one of
them will not be merged, however convenient it is.

1. **The source tree is read-only.** No modifying, renaming, `chmod`ing,
   normalizing, extracting, following or executing anything under it. Ever.
2. **The canonical manifest stays deterministic.** No time, hostname, username or
   absolute path in `manifest.txt`. If you must change the bytes, bump `FORMAT:`
   and keep old manifests verifiable.
3. **No network except on explicit request.** `tsa_fetch()` is the only function
   permitted to open a connection, and only under `--timestamp`. Adding a call home,
   an update check or telemetry is an automatic rejection.
4. **No signing automation.** No Profil Zaufany, mObywatel, e-dowód, gov.pl or
   qualified-provider integration. The script stops at producing the file to sign.
5. **Never overwrite silently.** Existing packages, attestations and sidecar files
   are refused, not clobbered.
6. **Never overclaim.** Output and docs must not imply the tool establishes file
   creation time, authorship, metadata truthfulness or legal admissibility. If you
   add a claim, add the limitation next to it.

## Tests

Every behavioural change needs a case in `--self-test`. It is one `check` line:

```bash
check "detect altered byte"  1  bash "$self" --verify "$pkg" --source "$ev"
```

`check LABEL EXPECTED_EXIT COMMAND...`. Tests must not touch the network — the RFC
3161 tests generate a throwaway TSA locally and are skipped when `openssl ts` is
unavailable. Everything goes in `mktemp -d` and is cleaned up.

## Scope

`podpi.sh` is intentionally one file that does four things: hash, manifest, attest,
verify. Timestamping is the one addition, and it is opt-in.

Things that will be politely declined: a config file format, plugins, alternative
hash algorithms, archive extraction, content parsing (PDF/EXIF/email), a bundled PDF
engine, a daemon, a GUI, or a rewrite in another language. If you need those, a fork
is a perfectly good outcome — say so in the issue and we will part on good terms.

Good contributions: portability fixes, clearer error messages, better documentation
of the trust model, additional test coverage, and genuine correctness bugs.

## Reporting bugs

Use the issue templates. For anything with security impact, see
[SECURITY.md](SECURITY.md) and report privately instead.

**Never attach real evidence files** to an issue. Reproduce with synthetic data.

## Commits and licensing

Write commit subjects in the imperative mood ("refuse TAB filenames", not "refused").
Explain *why* in the body when it is not obvious.

By contributing you agree that your work is licensed under the [MIT License](LICENSE).

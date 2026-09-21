# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because the manifest is a durable evidentiary artefact, any change to the
**canonical manifest bytes** is a breaking change and bumps the `FORMAT:` number
inside `manifest.txt`. Manifests written by older versions must keep verifying.

## [Unreleased]

## [1.0.0] - 2026-09-21

### Added

- Deterministic SHA-256 manifest (`FORMAT: 1`) with no time, hostname, username
  or absolute path in the canonical bytes, so repeated runs over unchanged files
  reproduce byte-identical output on any supported platform.
- Per-file stability check: `stat` before and after hashing, aborting the run if
  size, inode or mtime changed while the bytes were being read.
- Human-readable `attestation.txt` identifying the manifest by SHA-256, with an
  optional `--name` for the attesting person.
- `--verify`, reporting matching / changed / missing / extra files separately,
  with `--strict` to make unlisted extra files fatal.
- Optional RFC 3161 trusted timestamping, strictly opt-in via `--timestamp`.
  `--tsa URL` fetches a token; `--tsr FILE` attaches one obtained elsewhere,
  keeping the step offline. A token whose imprint does not cover the manifest is
  discarded rather than attached.
- `--attest`, to finish a manifest-only package without re-hashing — the recovery
  path when a timestamp authority is unreachable.
- `--timestamp-file` and `--hash-file`, for the PDF you actually sign.
- `--pdf`, generating a self-contained `attestation.html` with embedded CSS and
  no JavaScript, remote fonts or external resources.
- `--self-test`, covering acquisition, verification, refusals and the full RFC
  3161 path against a throwaway TSA it generates locally, with no network.
- Refusal to represent filenames containing TAB or NEWLINE, rather than escaping
  them ambiguously.
- Refusal to overwrite an existing package, or to place the output inside the
  evidence tree (or vice versa).
- Bash 3.2 compatibility and a single `detect_platform()` portability layer, so
  the script runs on stock macOS `/bin/bash` as well as Linux.

### Security

- The source directory is treated as strictly read-only: nothing is modified,
  renamed, `chmod`ed, normalized, extracted, followed or executed.
- `tsa_fetch()` is the only function that opens a network connection, and it runs
  only on explicit request. It announces the URL before contacting it, and sends
  only a SHA-256 digest and a nonce — never file contents.
- `--tsa` or `--tsr` without `--timestamp` is a hard error, so a partially typed
  command cannot silently produce an untimestamped package.
- No `eval` anywhere; no command is ever constructed from a filename.

[Unreleased]: https://github.com/foobarto/podpi.sh/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/foobarto/podpi.sh/releases/tag/v1.0.0

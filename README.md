# podpi.sh

**Generate a cryptographic preservation record for a directory of files, so you can
electronically sign an attestation that identifies it.**

[![CI](https://github.com/foobarto/podpi.sh/actions/workflows/ci.yml/badge.svg)](https://github.com/foobarto/podpi.sh/actions/workflows/ci.yml)
[![ShellCheck](https://img.shields.io/badge/shellcheck-clean-brightgreen)](https://www.shellcheck.net/)
[![Bash](https://img.shields.io/badge/bash-3.2%2B-blue)](https://www.gnu.org/software/bash/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

`podpi.sh` (from Polish *podpisz*, "sign it") is a single, deliberately boring Bash
script. It hashes a directory of files, writes a deterministic manifest, and produces
a short human-readable attestation that identifies that manifest by its SHA-256
digest — a document you can then sign with a Polish e-signature service
(Profil Zaufany, e-dowód, or a qualified provider).

**The signing happens outside this script.** `podpi.sh` stops at producing the file
you sign. It never automates a login, never talks to a signature provider, and only
touches the network if you explicitly ask it for a timestamp.

---

## The chain

```
hash  ->  manifest  ->  trusted timestamp  ->  attestation  ->  signature  ->  verify
 (1)        (2)               (3)                  (4)            (5)          (6)
```

| Step | Who | Network |
|------|-----|---------|
| 1–2 Hash files, write the canonical manifest | `podpi.sh` | never |
| 3 RFC 3161 trusted timestamp | `podpi.sh --timestamp` only | **only here** |
| 4 Write the attestation identifying the manifest | `podpi.sh` | never |
| 5 Electronically sign it | **you**, in your browser | — |
| 6 Verify the manifest against the files, later | `podpi.sh --verify` | never |

Steps 1, 2, 4 and 6 are fully offline. Step 3 never runs unless you ask for it.

---

## Quick start

```bash
git clone https://github.com/foobarto/podpi.sh.git
cd podpi.sh
./podpi.sh --self-test          # confirm it works on your machine
./podpi.sh evidence/            # create a preservation package
```

That writes `podpi-20260921T191500Z/` containing the manifest, its digest, the
attestation, and a human-readable summary. Sign `attestation.txt` with your chosen
service. Months later:

```bash
./podpi.sh --verify podpi-20260921T191500Z --source evidence/
```

...recomputes every hash and tells you whether the bytes still match.

## Install

There is nothing to build. Copy the one file somewhere on your `PATH`:

```bash
install -m 0755 podpi.sh ~/.local/bin/podpi.sh
```

**Requirements:** Bash 3.2+ and standard POSIX tools. That is it for the core
workflow — no Python, no Node, no jq. Timestamping additionally needs `curl` and an
OpenSSL that provides the `ts` command (see [Platform support](#platform-support)).

---

## Commands

```
podpi.sh DIRECTORY                     create a preservation package
podpi.sh --pdf DIRECTORY               also write a printable attestation.html
podpi.sh --verify PACKAGE [--source D] verify a package against files
podpi.sh --attest PACKAGE              finish a manifest-only package
podpi.sh --timestamp-file FILE --tsa U timestamp any single file
podpi.sh --hash-file FILE              print and record a file's SHA-256
podpi.sh --self-test                   run the built-in test suite
podpi.sh --help                        full trust-model documentation
```

| Option | Meaning |
|--------|---------|
| `--output DIR` | where to write the package (default `podpi-<UTC stamp>`) |
| `--name "NAME"` | name the attesting person in the attestation |
| `--pdf` | also generate `attestation.html` for Print → Save as PDF |
| `--no-open` | with `--pdf`, do not launch a browser |
| `--source DIR` | with `--verify`, the evidence root to check against |
| `--strict` | with `--verify`, treat unlisted extra files as a failure |
| `--timestamp` | request an RFC 3161 timestamp — **the only networked option** |
| `--tsa URL` | timestamp authority endpoint to contact |
| `--tsr FILE` | attach a token obtained elsewhere instead (stays offline) |
| `--tsa-ca FILE` | CA bundle used to cryptographically verify a token |

---

## What it proves

- It creates a SHA-256 manifest identifying **exact file bytes**. Anyone who later
  holds the files can recompute the hashes and see whether they match.
- If you electronically sign the attestation, the signature associates **you** with
  that identified manifest.
- If an RFC 3161 token is attached, and the issuing authority is trustworthy and its
  certificate validates, the token shows the **manifest already existed** by the time
  the authority asserts.

## What it does not prove

It does **not** establish:

- when the original files were created;
- when an email was sent;
- who authored a source file;
- whether metadata is truthful;
- whether statements inside a file are true;
- legal admissibility.

A timestamp proves the *manifest* existed by a certain time. It says nothing about
when the underlying files were created.

Filenames, filesystem timestamps, PDF metadata, image EXIF and email `Date:` headers
are **not** treated as evidence of time or authorship. The tool preserves exact bytes;
it does not interpret content.

An electronic signature is not by itself a qualified trusted timestamp. For eIDAS
purposes a *qualified* timestamp must come from a qualified trust service provider on
the EU Trusted List. `podpi.sh` speaks plain RFC 3161 and does not evaluate, endorse
or check the qualification status of any authority you point it at — **choosing one is
your decision.**

> This is not legal advice. Whether a preservation record helps in a particular
> proceeding is a question for a lawyer in the relevant jurisdiction.

---

## Output

```
podpi-20260921T191500Z/
├── manifest.txt             canonical, deterministic, no volatile data
├── manifest.txt.sha256      digest of the manifest
├── attestation.txt          the document you sign
├── attestation.txt.sha256   digest of the attestation
├── summary.txt              human-readable; written last, marks completion
├── source-path.txt          local convenience only, NOT part of the evidence
├── manifest.txt.tsq         ┐
├── manifest.txt.tsr         ├ only with --timestamp
├── timestamp.txt            ┘
└── attestation.html         only with --pdf
```

### Manifest format

Deliberately trivial: three fixed comment lines, a column header, then one
tab-separated row per file.

```
# PODPI.sh EVIDENCE MANIFEST
# FORMAT: 1
# HASH: SHA-256
SHA256→BYTES→PATH
b6a98d9ce9a2d9149288fa3df42d377c3e42737afdcdaf714e33c0a100b51060→6→a.txt
5da8f23decf397b13f4f55b6fb8a61936238bfe08ed9d901132974f1beccc45c→6→b c.txt
673953e0ad7fc53247f4feadc2c2d4506396840d1f8796526f48d47333ac7652→6→nested/d.bin
```

(`→` is a literal TAB.) Paths are always relative to the evidence root.

### Determinism

The manifest contains **no time, no hostname, no username and no absolute path**.
Hashing the same unchanged directory twice produces byte-identical bytes and therefore
the same SHA-256 — on any machine, on either Linux or macOS. CI asserts this against a
pinned digest on every push.

Ordering is byte-wise under `LC_ALL=C`, gathered NUL-safely, so spaces, Unicode,
quotes, parentheses and shell metacharacters in filenames are all handled.

Filenames containing a **TAB or NEWLINE** are refused outright rather than escaped
ambiguously — the manifest format cannot represent them honestly, and silently
mangling evidence filenames is worse than stopping.

---

## Read-only guarantee

From the script's perspective the source directory is strictly read-only. It never
modifies, renames, `chmod`s, normalizes, extracts, follows, executes or uploads
anything in it. It reads path, exact bytes, size and the minimum metadata needed for
the stability check.

**Stability check.** Each file is `stat`ed before hashing and again afterwards. If
size, inode or mtime changed while the bytes were being read, the run aborts:

```
ERROR: source file changed while being hashed:
nested/dump.bin
```

A manifest is never presented as successful if the evidence shifted underneath it.

---

## Timestamping (opt-in)

Timestamping is **never automatic**. A package created without `--timestamp` has no
token and says so, in the attestation itself.

```bash
# fetch a token from an authority you choose
./podpi.sh --timestamp --tsa https://your.tsa.example/tsa evidence/

# or attach one you obtained by some other route, fully offline
./podpi.sh --attest podpi-20260921T191500Z --timestamp --tsr token.tsr
```

Safeguards:

- `--tsa`/`--tsr` **without** `--timestamp` is a hard error, not a silent skip.
- Preconditions are checked *before* hashing, so a misconfiguration fails in a second
  rather than after an hour.
- A token whose message imprint does not cover the manifest is **discarded**, not
  attached.
- If the authority is unreachable, the hashing work is **kept**. The package is left
  manifest-only and `--attest` finishes it without re-hashing anything.

If you already have a signed attestation and only want to timestamp the manifest
without touching it, use `--timestamp-file PACKAGE/manifest.txt --tsa URL`.

### Endpoints known to work

Verified working with `podpi.sh` against live services. **These are examples, not
endorsements** — `podpi.sh` does not check whether an authority is qualified under
eIDAS, and choosing one remains your decision.

| Endpoint | Policy OID | Verifies against system roots |
|----------|-----------|-------------------------------|
| `http://time.certum.pl` (Certum / Asseco, PL) | `1.2.616.1.113527.2.5.1.11` | yes |
| `http://timestamp.digicert.com` | `2.16.840.1.114412.7.1` | yes |
| `http://timestamp.sectigo.com` | `1.3.6.1.4.1.6449.2.1.1` | yes |
| `https://freetsa.org/tsr` | `tsa_policy1` | no — needs its own CA via `--tsa-ca` |

```bash
# a public authority, verified against your system trust store
./podpi.sh --verify PACKAGE --source evidence/ --tsa-ca /etc/ssl/certs/ca-bundle.crt
```

The freetsa row is worth understanding: the token is perfectly valid, but it is signed
by a root your system does not trust, so verification reports `FAILED` and the run
exits non-zero. That is the intended behaviour — an unverifiable token must never
report `PASS`. Pass that authority's own CA with `--tsa-ca` and it verifies.

---

## Verification

```
$ ./podpi.sh --verify podpi-20260921T191500Z --source evidence/
PODPI.sh VERIFICATION

Manifest:
PASS

Trusted timestamp:
PRESENT
  asserted time:   2026-09-21T17:54:26Z
  imprint matches: YES (token covers this exact manifest)
  signature:       NOT CHECKED (pass --tsa-ca FILE to verify it)

Files checked:
9125

Matching:
9125

Changed:
0

Missing:
0

Extra:
0

RESULT:
PASS
```

Exit code is `0` for PASS and non-zero for FAIL. Changed and missing files are always
failures; extra files are reported but tolerated unless you pass `--strict`.

Timestamp verification reports two **independent** levels and never conflates them:
the *imprint check* needs no CA and proves the token is about this exact manifest; the
*signature check* needs `--tsa-ca` and proves the token is authentic.

---

## The PDF route

Some signature services want a PDF. `--pdf` writes a self-contained `attestation.html`
— embedded CSS, no JavaScript, no remote fonts, no external resources of any kind —
laid out for A4. Open it, Print → Save as PDF, then:

```bash
./podpi.sh --hash-file attestation.pdf
```

> `attestation.txt`, `attestation.html` and the printed `attestation.pdf` are **three
> different digital objects with three different hashes.** Hash the PDF you actually
> sign, after producing it. Never assume the HTML hash equals the PDF hash.

`podpi.sh` deliberately does not bundle a PDF engine; requiring headless Chromium to
preserve evidence would be a poor trade.

---

## What to sign

| You sign | You are bound to |
|----------|------------------|
| `manifest.txt` | the exact manifest bytes, directly |
| `attestation.txt` | a human statement that identifies the manifest by SHA-256 |

Both are useful. For human and legal readability, `attestation.txt` is the default
recommendation.

---

## Platform support

| | Linux | macOS |
|---|---|---|
| Core workflow | ✅ | ✅ |
| Bash | 4.x / 5.x | stock `/bin/bash` 3.2 |
| SHA-256 | `sha256sum` | `shasum -a 256` |
| `stat` | GNU `-c` | BSD `-f` |
| Timestamping | ✅ | needs Homebrew OpenSSL |

Every platform difference is resolved once, in `detect_platform()`; the rest of the
script never tests the platform again. No `realpath`, no `sort -z`, no `find -printf`,
no `mapfile`, no associative arrays — so stock macOS Bash 3.2 works.

macOS ships **LibreSSL**, which has no `openssl ts` command. Core operations are
unaffected; only timestamping needs:

```bash
brew install openssl@3
export PODPI_OPENSSL="$(brew --prefix openssl@3)/bin/openssl"
```

> **Unicode caveat.** Filenames are recorded as exact bytes. HFS+ stores names in NFD
> while Linux typically stores NFC, so evidence copied between the two can legitimately
> produce different manifests. Verify a manifest on the same kind of filesystem that
> produced it. `podpi.sh` does not normalize filenames — that would violate the
> read-only principle.

---

## Limitations

- Only **regular files** are recorded. Symlinks, devices and empty directories are
  counted and reported in `summary.txt`, but not represented in the manifest.
- TAB/NEWLINE filenames are refused, by design.
- `source-path.txt` is local convenience metadata and is explicitly **not** part of
  the evidence identity. `--source` is the portable way to point at the files.
- No TSA is integrated or endorsed; you supply the URL.
- The script does not interpret file contents at all.

---

## Development

```bash
make check      # bash -n + shellcheck + --self-test
make test       # --self-test only
make lint       # shellcheck only
```

The self-test builds a temporary tree (spaces, Unicode, nested binary), creates a
package, verifies it, flips a byte, deletes a file, adds an extra, and checks that
each is caught — then exercises the full RFC 3161 path against a **throwaway TSA it
generates locally**, with no network. It cleans up after itself.

CI runs on Ubuntu and macOS, including under macOS's real Bash 3.2, and asserts the
pinned cross-platform manifest digest. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
house style — the short version is *boring, explicit, ShellCheck-clean, no `eval`.*

## License

[MIT](LICENSE) © Bartosz Ptaszyński (foobarto)

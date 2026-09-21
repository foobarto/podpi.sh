# Security Policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub's private vulnerability
reporting:

**<https://github.com/foobarto/podpi.sh/security/advisories/new>**

Do not open a public issue for a vulnerability. Please allow a reasonable period for
a fix before public disclosure.

When reporting, include the `podpi.sh` version or commit, your platform and Bash
version (`bash --version`), and the smallest reproduction you can manage.

**Do not attach real evidence files.** Reproduce with synthetic data.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

## Threat model

`podpi.sh` is a preservation-record generator. It is worth being precise about what
is and is not a security boundary.

### In scope

Reports are wanted for anything that would let an attacker:

- cause the manifest to record a digest that does not match the bytes actually read;
- cause verification to report `PASS` for files that no longer match the manifest;
- cause a timestamp token to be accepted when it does not cover the manifest, or to
  be reported as signature-verified when it is not;
- achieve command execution, or escape quoting, via a crafted **filename**, package
  path, TSA URL or manifest row;
- cause the tool to write outside its output directory, or to modify, delete or
  otherwise alter files in the source evidence tree;
- cause the tool to transmit data over the network during any operation other than
  an explicitly requested `--timestamp` / `--timestamp-file`.

### Explicitly out of scope

These are documented design properties, not vulnerabilities:

- **A manifest proves bytes, not truth.** It does not establish when files were
  created, who wrote them, or whether their contents or metadata are truthful.
- **`podpi.sh` does not vet timestamp authorities.** You supply the URL. It does not
  check whether an authority is qualified under eIDAS or on the EU Trusted List.
- **A token's signature is only checked when you pass `--tsa-ca`.** Without it,
  verification reports `signature: NOT CHECKED` — by design, and stated in the output.
  Trusting an unverified token is a user decision, not a tool defect.
- **`source-path.txt` is untrusted local metadata**, not part of the evidence
  identity. Prefer `--source`.
- **Someone who can modify the whole package** (manifest, its digest, and the
  attestation together) can produce an internally consistent but false package. That
  is precisely what the electronic signature and the trusted timestamp are for; the
  manifest alone was never meant to resist its own author.
- **Filenames with TAB or NEWLINE are refused**, not escaped. Intentional.
- **Unicode normalization differences** between filesystems (HFS+ NFD vs Linux NFC)
  can legitimately produce different manifests. `podpi.sh` does not normalize, because
  that would violate the read-only principle.

## What leaves your machine

Nothing, unless you pass `--timestamp` or use `--timestamp-file`.

In that case the tool POSTs an RFC 3161 request to the single URL you named. That
request contains a **SHA-256 digest and a random nonce** — not filenames, not file
contents, not directory structure. TLS certificate verification is left at its secure
default and is never disabled.

## What does this change?

<!-- One or two sentences. Link the issue if there is one. -->

## Why?

<!-- What problem does it solve? If it is a bug, how does it currently fail? -->

## Checklist

- [ ] `make check` passes (`bash -n`, `shellcheck`, `--self-test`)
- [ ] A case was added to `--self-test` covering this change
- [ ] Code stays Bash 3.2 compatible (no `mapfile`, `declare -A`, `${var^^}`, `|&`)
- [ ] No new `eval`, and no command built from a filename
- [ ] Any new platform difference lives in `detect_platform()`

### Invariants

Confirm this change does **not**:

- [ ] modify, rename, `chmod`, normalize, extract or execute anything in the source tree
- [ ] put time, hostname, username or an absolute path into `manifest.txt`
- [ ] open a network connection outside `--timestamp` / `--timestamp-file`
- [ ] automate any electronic-signature service
- [ ] overwrite an existing package, attestation or sidecar file
- [ ] overclaim what the tool proves

<!-- If a canonical manifest byte changes, bump FORMAT: and say so here. -->

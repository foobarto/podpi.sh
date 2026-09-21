#!/usr/bin/env bash
#
# podpi.sh -- evidence preservation record generator ("podpisz" = "sign it")
#
# The chain this tool supports:
#
#     hash -> manifest -> trusted timestamp -> attestation -> signature -> verify
#      (1)      (2)             (3)                (4)           (5)        (6)
#
#   (1),(2)  always, offline
#   (3)      ONLY when you explicitly ask with --timestamp; this is the only
#            step that ever touches the network, and only the TSA URL you name
#   (4)      a short human statement identifying the manifest (and the
#            timestamp token, when one exists) by SHA-256
#   (5)      performed by YOU, outside this script, with your chosen
#            electronic-signature service
#   (6)      --verify, offline
#
# The source directory is READ ONLY from this script's perspective: nothing is
# renamed, chmod'ed, normalized, extracted or executed.
#
# Portability: Bash 3.2+ (so stock macOS /bin/bash works), GNU or BSD
# coreutils. See detect_platform() for every platform-dependent decision.
#
set -euo pipefail

# Byte-wise collation and predictable output everywhere. This is what makes
# the manifest ordering reproducible across machines.
export LC_ALL=C

readonly PROG="podpi.sh"
readonly MANIFEST_MAGIC="# PODPI.sh EVIDENCE MANIFEST"
readonly MANIFEST_COLUMNS=$'SHA256\tBYTES\tPATH'

# ==========================================================================
# Portability layer
# ==========================================================================
# Every platform difference is resolved once, here, and recorded in a
# variable. The rest of the script never tests the platform again.

HASH_KIND=""       # sha256sum | shasum | openssl
STAT_KIND=""       # gnu | bsd
STAT_FINGERPRINT_FMT=""
OPENER=""          # xdg-open | open | (empty)
OPENSSL_BIN="${PODPI_OPENSSL:-openssl}"

detect_platform() {
    # --- SHA-256 -----------------------------------------------------------
    # Linux has sha256sum; macOS has shasum; openssl dgst is the last resort.
    if command -v sha256sum >/dev/null 2>&1; then
        HASH_KIND="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        HASH_KIND="shasum"
    elif command -v "$OPENSSL_BIN" >/dev/null 2>&1; then
        HASH_KIND="openssl"
    else
        die "ERROR: no SHA-256 tool found (need sha256sum, shasum or openssl)."
    fi

    # --- stat --------------------------------------------------------------
    # GNU uses -c '%s', BSD (macOS) uses -f '%z'. For the stability check we
    # want size, inode and the highest-resolution mtime the platform offers,
    # so we probe for fractional-second support and fall back to whole seconds.
    if stat -c '%s' . >/dev/null 2>&1; then
        STAT_KIND="gnu"
        STAT_FINGERPRINT_FMT='%s %i %y'          # %y = mtime with nanoseconds
    elif stat -f '%z' . >/dev/null 2>&1; then
        STAT_KIND="bsd"
        if stat -f '%z %i %Fm' . >/dev/null 2>&1; then
            STAT_FINGERPRINT_FMT='%z %i %Fm'     # %Fm = mtime as float
        else
            STAT_FINGERPRINT_FMT='%z %i %m'      # whole seconds only
        fi
    else
        die "ERROR: unsupported stat(1); neither GNU -c nor BSD -f works."
    fi

    # --- desktop opener ----------------------------------------------------
    if command -v xdg-open >/dev/null 2>&1; then
        OPENER="xdg-open"
    elif command -v open >/dev/null 2>&1; then
        OPENER="open"
    fi
}

# sha256_of_file FILE -> 64 hex characters.
# The file is fed on stdin so no hashing tool ever has to interpret a
# filename (GNU sha256sum escapes odd filenames in its output; reading stdin
# sidesteps that entirely). All three backends print the digest first.
sha256_of_file() {
    case "$HASH_KIND" in
        sha256sum) sha256sum            < "$1" | awk '{print $1; exit}' ;;
        shasum)    shasum -a 256        < "$1" | awk '{print $1; exit}' ;;
        openssl)   "$OPENSSL_BIN" dgst -sha256 -r < "$1" | awk '{print $1; exit}' ;;
    esac
}

# size_of_file FILE -> byte count
size_of_file() {
    if [ "$STAT_KIND" = "gnu" ]; then
        stat -c '%s' "$1"
    else
        stat -f '%z' "$1"
    fi
}

# stat_fingerprint FILE -> "size inode mtime"
# Compared before and after hashing to detect a file changing under us.
stat_fingerprint() {
    if [ "$STAT_KIND" = "gnu" ]; then
        stat -c "$STAT_FINGERPRINT_FMT" "$1"
    else
        stat -f "$STAT_FINGERPRINT_FMT" "$1"
    fi
}

# abs_path PATH -> absolute, symlink-resolved path.
# realpath(1) is not on stock macOS and BSD realpath has no -m, so this is
# built from `cd` + `pwd -P`, which is portable everywhere. For a path that
# does not exist yet, the parent is resolved and the basename appended.
abs_path() {
    local p="$1" parent base
    if [ -d "$p" ]; then
        (cd "$p" && pwd -P)
        return 0
    fi
    parent="$(dirname "$p")"
    base="$(basename "$p")"
    [ -d "$parent" ] || die "ERROR: parent directory does not exist: $parent"
    parent="$(cd "$parent" && pwd -P)"
    case "$parent" in
        */) printf '%s%s\n' "$parent" "$base" ;;
        *)  printf '%s/%s\n' "$parent" "$base" ;;
    esac
}

# ==========================================================================
# Small helpers
# ==========================================================================

die() {
    printf '%s\n' "$@" >&2
    exit 1
}

note() {
    printf '%s\n' "$@" >&2
}

# mib BYTES -> MiB with two decimals (display only, never canonical)
mib() {
    awk -v n="$1" 'BEGIN { printf "%.2f", n / 1048576 }'
}

# path_is_inside CHILD PARENT -> true when CHILD is PARENT or lies beneath it.
# Both arguments must already be absolute, resolved paths.
path_is_inside() {
    local child="$1" parent="$2"
    [ "$child" = "$parent" ] && return 0
    case "$child/" in
        "$parent"/*) return 0 ;;
        *) return 1 ;;
    esac
}

# has_control_chars PATH -> true when the path holds a TAB or NEWLINE, i.e.
# the two characters that would make the simple TSV manifest ambiguous.
# (NUL cannot occur in a Unix filename, so these are the only two.)
has_control_chars() {
    case "$1" in
        *$'\t'* | *$'\n'*) return 0 ;;
        *) return 1 ;;
    esac
}

# html_escape: escape &, < and > on stdin. Nothing lands in an attribute, so
# no other escaping is required.
html_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# require_openssl_ts: the RFC 3161 code paths need `openssl ts`, which
# LibreSSL (shipped as /usr/bin/openssl on macOS) does not provide.
require_openssl_ts() {
    command -v "$OPENSSL_BIN" >/dev/null 2>&1 || \
        die "ERROR: openssl not found; required for timestamping." \
            "Set PODPI_OPENSSL=/path/to/openssl if it is installed elsewhere."
    "$OPENSSL_BIN" ts -help >/dev/null 2>&1 || \
        die "ERROR: this openssl has no 'ts' command (LibreSSL does not ship it)." \
            "On macOS:  brew install openssl@3" \
            "then:      export PODPI_OPENSSL=\"\$(brew --prefix openssl@3)/bin/openssl\"" \
            "Timestamping is optional; every other $PROG operation works without it."
}

# The output directory is created by us and by us alone (we abort if it
# already exists), so on failure we remove it again rather than leave a
# partial, misleading package behind. Cleared once the manifest is safely on
# disk -- from that point a failure leaves a recoverable manifest-only package.
PARTIAL_OUTPUT=""

cleanup_partial() {
    if [ -n "$PARTIAL_OUTPUT" ] && [ -d "$PARTIAL_OUTPUT" ]; then
        rm -rf "$PARTIAL_OUTPUT"
        note "Removed incomplete package: $PARTIAL_OUTPUT"
    fi
}

# Once the manifest exists, any later failure (typically an unreachable TSA)
# must not look like a lost run: the expensive hashing is already on disk and
# --attest can finish the job. die() exits outright, so this hint is emitted
# from an EXIT trap rather than from a return-value check.
RECOVER_PKG=""

recovery_hint() {
    local rc=$?
    if [ "$rc" -ne 0 ] && [ -n "$RECOVER_PKG" ] \
       && [ -f "$RECOVER_PKG/manifest.txt" ] && [ ! -f "$RECOVER_PKG/attestation.txt" ]; then
        note "" \
             "The manifest was written and is intact:" \
             "  $RECOVER_PKG/manifest.txt" \
             "" \
             "No attestation was produced, so the package is manifest-only." \
             "Nothing needs re-hashing. Finish it with:" \
             "  $PROG --attest $RECOVER_PKG [--timestamp --tsa URL] [--name \"...\"]"
    fi
    return "$rc"
}

# ==========================================================================
# Help / trust model
# ==========================================================================

usage() {
    cat <<'EOF'
podpi.sh -- evidence preservation record generator

THE CHAIN

    hash -> manifest -> trusted timestamp -> attestation -> signature -> verify

    Steps 1, 2, 4 and 6 are offline and automatic.
    Step 3 happens ONLY if you ask for it with --timestamp.
    Step 5 is performed by you, outside this script.

USAGE
    podpi.sh DIRECTORY                     create a preservation package
    podpi.sh --pdf DIRECTORY               also write attestation.html
    podpi.sh --verify PACKAGE [--source D] verify a package against files
    podpi.sh --attest PACKAGE              finish a manifest-only package
    podpi.sh --timestamp-file FILE --tsa U timestamp any single file
    podpi.sh --hash-file FILE              print and record a file's SHA-256
    podpi.sh --self-test                   run built-in tests
    podpi.sh --help                        this text

OPTIONS
    --output DIR      write the package to DIR (default: podpi-<UTC stamp>)
    --name "NAME"     name the attesting person in attestation.txt
    --pdf             also generate a printable attestation.html
    --no-open         with --pdf, do not launch a browser
    --source DIR      with --verify, the evidence root to check against
    --strict          with --verify, treat unlisted extra files as a failure
    --timestamp       request an RFC 3161 timestamp (see NETWORK below)
    --tsa URL         timestamp authority endpoint to contact
    --tsr FILE        attach an already-obtained token instead (no network)
    --tsa-ca FILE     CA/anchor bundle used to cryptographically verify a token
    --hash-signed F   alias of --hash-file

NETWORK

    podpi.sh contacts the network in exactly one case: when you pass
    --timestamp (or use --timestamp-file), and then only the single URL you
    named with --tsa. Creating a manifest, writing an attestation and
    verifying a package never open a socket.

    Timestamping is never automatic. A package created without --timestamp
    simply has no token, and says so.

    --tsr lets you attach a token obtained by some other route, so the
    timestamp step can also be done fully offline.

OUTPUT
    manifest.txt            canonical, deterministic, no volatile data
    manifest.txt.sha256     digest of the manifest
    attestation.txt         short human statement identifying the manifest
    attestation.txt.sha256  digest of the attestation
    summary.txt             human-readable; written last, marks completion
    source-path.txt         local convenience only, NOT part of the evidence
    manifest.txt.tsq        timestamp request      \ only with
    manifest.txt.tsr        timestamp token        | --timestamp
    timestamp.txt           decoded token, readable/
    attestation.html        only with --pdf

WHAT PODPI.sh PROVES

    It creates a SHA-256 manifest identifying exact file bytes.

    If someone later possesses the files, they can recompute the hashes and
    determine whether those bytes match the manifest.

    If the attestation is electronically signed, the signature can associate
    the signer with the identified manifest.

    If an RFC 3161 token is attached, and the issuing authority is trustworthy
    and its certificate validates, the token establishes that the manifest
    already existed at the time the authority asserts.

WHAT PODPI.sh DOES NOT PROVE

    It does not by itself prove:

      - when the original files were created;
      - when an email was sent;
      - who authored a source file;
      - whether metadata is truthful;
      - whether statements in a file are true;
      - legal admissibility.

    A timestamp proves the MANIFEST existed by a certain time. It says
    nothing about when the underlying files were created.

    Filenames, filesystem timestamps, PDF metadata, image EXIF and email Date
    headers are NOT treated as evidence of time or authorship by this tool.
    It preserves exact bytes; it does not interpret content.

    An electronic signature is not by itself a qualified trusted timestamp.
    For eIDAS purposes a QUALIFIED timestamp must come from a qualified trust
    service provider on the EU Trusted List. podpi.sh speaks plain RFC 3161
    and does not evaluate, endorse or check the qualification status of any
    authority you point it at -- choosing one is your decision.

WHAT TO SIGN

    Signing manifest.txt directly binds the signature to the exact manifest.

    Signing attestation.txt instead binds the signer to a statement that
    explicitly identifies the manifest by SHA-256 -- and the timestamp token
    too, when one is present.

    Both are useful. For human and legal readability, attestation.txt is the
    default recommendation.

    attestation.txt, attestation.html and a printed attestation.pdf are THREE
    different digital objects with three different hashes. Hash the PDF you
    actually sign, after producing it.

LIMITATIONS

    - Only regular files are recorded. Symlinks, devices and empty
      directories are counted and reported, but not represented.
    - Filenames containing TAB or NEWLINE are refused rather than ambiguously
      escaped, because manifest.txt is an intentionally simple TSV.
    - Unicode filenames are recorded as exact bytes. macOS HFS+ stores names
      in NFD while Linux typically stores NFC, so evidence copied between the
      two can legitimately produce different manifests. Verify a manifest on
      the same kind of filesystem that produced it.
    - Requires Bash 3.2+ (stock macOS /bin/bash is fine). Timestamping
      additionally needs OpenSSL with the `ts` command and curl; macOS ships
      LibreSSL, which lacks `ts` -- see PODPI_OPENSSL above.
EOF
}

# ==========================================================================
# Traversal: collect relative paths, deterministically ordered
# ==========================================================================

REL_PATHS=()
NON_REGULAR_COUNT=0

# collect_paths SRC_ABS
# Fills REL_PATHS with byte-sorted relative paths and sets NON_REGULAR_COUNT.
# Aborts if any path contains TAB or NEWLINE.
#
# Order of operations matters: paths are gathered NUL-safely, then screened
# for TAB/NEWLINE, and only then sorted. Because the screen has already
# guaranteed no path contains a newline, an ordinary line-based `sort` is
# safe -- which avoids `sort -z`, a GNU extension missing from older BSD sort.
collect_paths() {
    local src="$1" p
    REL_PATHS=()
    NON_REGULAR_COUNT=0

    # 1. gather. Running find from inside the source directory yields
    #    "./relative" paths, so no absolute path can reach the manifest.
    #    -type f excludes symlinks, so nothing is ever followed.
    while IFS= read -r -d '' p; do
        REL_PATHS+=("${p#./}")
    done < <(cd "$src" && find . -type f -print0)

    # 2. screen for characters the manifest format cannot represent.
    for p in ${REL_PATHS[@]+"${REL_PATHS[@]}"}; do
        if has_control_chars "$p"; then
            die "ERROR:" \
                "This evidence tree contains filenames with TAB or NEWLINE" \
                "characters." \
                "" \
                "$PROG intentionally refuses to encode these ambiguously in" \
                "its simple text manifest." \
                "" \
                "Rename/copy the evidence through an appropriate forensic" \
                "procedure or use a more capable binary manifest tool." \
                "" \
                "First offending path (control characters shown escaped):" \
                "$(printf '%q' "$p")"
        fi
    done

    # 3. sort (safe now: no path contains a newline).
    if [ ${#REL_PATHS[@]} -gt 0 ]; then
        local sorted
        sorted=()
        while IFS= read -r p; do
            sorted+=("$p")
        done < <(printf '%s\n' "${REL_PATHS[@]}" | sort)
        REL_PATHS=(${sorted[@]+"${sorted[@]}"})
    fi

    # 4. count what was NOT represented, so the operator is told.
    #    (`find -printf` is GNU-only, so entries are counted here instead.)
    while IFS= read -r -d '' p; do
        NON_REGULAR_COUNT=$(( NON_REGULAR_COUNT + 1 ))
    done < <(cd "$src" && find . ! -type d ! -type f -print0)
}

# ==========================================================================
# Acquisition: hash every file, with a before/after stability check
# ==========================================================================

TOTAL_BYTES=0

# hash_tree SRC_ABS MANIFEST_FILE
# Appends one "SHA256<TAB>BYTES<TAB>PATH" row per file, sets TOTAL_BYTES.
hash_tree() {
    local src="$1" body="$2"
    local rel abs before after hash size
    local done_n=0
    local total=${#REL_PATHS[@]}

    TOTAL_BYTES=0

    for rel in ${REL_PATHS[@]+"${REL_PATHS[@]}"}; do
        abs="$src/$rel"

        # 1. fingerprint before hashing (size, inode, highest-resolution mtime)
        before="$(stat_fingerprint "$abs")" || die "ERROR: cannot stat source file:" "$rel"

        # 2. read the exact bytes
        hash="$(sha256_of_file "$abs")" || die "ERROR: cannot read source file:" "$rel"

        # 3. fingerprint again and compare
        after="$(stat_fingerprint "$abs")" || die "ERROR: source file vanished while hashing:" "$rel"

        if [ "$before" != "$after" ]; then
            die "ERROR: source file changed while being hashed:" "$rel"
        fi

        size="${before%% *}"
        TOTAL_BYTES=$(( TOTAL_BYTES + size ))

        printf '%s\t%s\t%s\n' "$hash" "$size" "$rel" >> "$body"

        done_n=$(( done_n + 1 ))
        if [ -t 2 ] && [ $(( done_n % 100 )) -eq 0 ]; then
            printf '\r  hashed %d/%d files' "$done_n" "$total" >&2
        fi
    done

    if [ -t 2 ] && [ "$total" -gt 0 ]; then
        printf '\r  hashed %d/%d files\n' "$done_n" "$total" >&2
    fi
    return 0
}

# manifest_stats MANIFEST -> sets MANIFEST_COUNT and MANIFEST_TOTAL by
# re-reading the finished manifest. Used by both create and --attest so the
# attestation's numbers always come from the manifest itself.
MANIFEST_COUNT=0
MANIFEST_TOTAL=0

manifest_stats() {
    local manifest="$1" line hash size path
    MANIFEST_COUNT=0
    MANIFEST_TOTAL=0
    while IFS= read -r line; do
        case "$line" in
            '#'* | "$MANIFEST_COLUMNS" | '') continue ;;
        esac
        IFS=$'\t' read -r hash size path <<< "$line"
        [ -n "$path" ] || die "ERROR: malformed manifest row: $line"
        MANIFEST_COUNT=$(( MANIFEST_COUNT + 1 ))
        MANIFEST_TOTAL=$(( MANIFEST_TOTAL + size ))
    done < "$manifest"
}

# ==========================================================================
# Step 3: RFC 3161 trusted timestamp -- explicit opt-in only
# ==========================================================================
# Nothing in this section runs unless the operator passed --timestamp or
# --timestamp-file. tsa_fetch() is the ONLY function in the whole script that
# opens a network connection.

TS_PRESENT=0      # 1 once a token is attached
TS_TIME=""        # ISO-8601 UTC, or the authority's raw string
TS_TIME_RAW=""
TS_POLICY=""
TS_SERIAL=""
TS_IMPRINT=""     # message imprint carried inside the token
TS_TOKEN_SHA=""   # SHA-256 of the token file itself
TS_SOURCE=""      # the URL contacted, or "attached token (no network)"

# tsa_query FILE TSQ_OUT
# Builds an RFC 3161 request over FILE's SHA-256. -cert asks the authority to
# embed its signing certificate so the token can be verified later; openssl
# includes a random nonce, which binds the reply to this specific request.
tsa_query() {
    "$OPENSSL_BIN" ts -query -data "$1" -sha256 -cert -out "$2" >/dev/null 2>&1 \
        || die "ERROR: could not build timestamp request for: $1"
}

# tsa_fetch TSQ TSR_OUT URL   <-- the only network call in this script
tsa_fetch() {
    local tsq="$1" tsr="$2" url="$3"

    command -v curl >/dev/null 2>&1 || \
        die "ERROR: curl is required to contact a timestamp authority."

    note "" "Contacting timestamp authority (the only network access $PROG performs):" \
         "  $url" ""

    # -f  : fail loudly on an HTTP error instead of saving an error page
    # -sS : quiet, but still print real errors
    # TLS verification is deliberately left at its secure default.
    curl -fsS --max-time 60 \
         -H "Content-Type: application/timestamp-query" \
         -H "Accept: application/timestamp-reply" \
         --data-binary "@$tsq" \
         -o "$tsr" \
         "$url" \
        || die "ERROR: timestamp authority request failed: $url" \
               "Nothing was sent anywhere else. The manifest is unaffected."
}

# tsr_decode TSR -> populates the TS_* variables; fails if the token is not
# a granted RFC 3161 reply. Works on a bare token too (-token_in).
tsr_decode() {
    local tsr="$1" txt status hexline

    txt="$("$OPENSSL_BIN" ts -reply -in "$tsr" -text 2>/dev/null)" || txt=""
    if [ -z "$txt" ]; then
        txt="$("$OPENSSL_BIN" ts -reply -in "$tsr" -token_in -text 2>/dev/null)" || txt=""
    fi
    [ -n "$txt" ] || die "ERROR: not a readable RFC 3161 timestamp token: $tsr"

    # A reply carries a status; a bare token does not, so an absent status is
    # acceptable but a present, non-granted one is fatal.
    status="$(printf '%s\n' "$txt" | sed -n 's/^Status: *//p')"
    case "$status" in
        ""|"Granted."|"Granted with modifications.") : ;;
        *) die "ERROR: timestamp authority did not grant the request: $status" ;;
    esac

    TS_TIME_RAW="$(printf '%s\n' "$txt" | sed -n 's/^Time stamp: *//p')"
    TS_POLICY="$(printf '%s\n' "$txt"  | sed -n 's/^Policy OID: *//p')"
    TS_SERIAL="$(printf '%s\n' "$txt"  | sed -n 's/^Serial number: *//p')"

    # The message imprint is printed as an openssl hex dump; pull the hex
    # bytes out of it. Lines look like:
    #     0000 - 13 98 ff 91 2f 24 85 51-08 2b 2d f9 ...   ..../$.Q.+-...
    hexline="$(printf '%s\n' "$txt" \
        | awk '/^Message data:/ {g=1; next}
               g && /^ *[0-9a-f]+ - / {print; next}
               g {exit}' \
        | sed -e 's/^ *[0-9a-f]* - //' -e 's/   .*$//' -e 's/[ -]//g')"
    TS_IMPRINT="$(printf '%s' "$hexline" | tr -d '\n')"
    [ -n "$TS_IMPRINT" ] || die "ERROR: could not read the message imprint from: $tsr"

    # Normalise the authority's time to ISO-8601 UTC when the local date(1)
    # can parse it (GNU -d, BSD -j -f); otherwise keep the raw string.
    TS_TIME="$(date -u -d "$TS_TIME_RAW" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -j -f '%b %d %H:%M:%S %Y %Z' "$TS_TIME_RAW" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || printf '%s' "$TS_TIME_RAW")"

    TS_TOKEN_SHA="$(sha256_of_file "$tsr")"
}

# tsr_check_imprint TSR DATA_FILE -> 0 when the token's imprint equals the
# file's SHA-256. Needs no CA and no network: it proves the token is ABOUT
# this file, though not that the token is authentic.
tsr_check_imprint() {
    local expect
    expect="$(sha256_of_file "$2")"
    tsr_decode "$1"
    [ "$TS_IMPRINT" = "$expect" ]
}

# write_timestamp_txt OUT
write_timestamp_txt() {
    cat > "$1" <<EOF
PODPI.sh TRUSTED TIMESTAMP (RFC 3161)

Token file:
manifest.txt.tsr

Token SHA-256:
$TS_TOKEN_SHA

Timestamped object:
manifest.txt

Message imprint in token (SHA-256):
$TS_IMPRINT

Authority asserted time:
$TS_TIME

Authority asserted time (as printed by the token):
$TS_TIME_RAW

Policy OID:
$TS_POLICY

Serial number:
$TS_SERIAL

Obtained from:
$TS_SOURCE

IMPORTANT:
This token asserts that the manifest digest above was presented to
that authority at that time. It therefore shows the manifest
already existed by then.

It does NOT show when the underlying source files were created.

The assertion is only as good as the authority. To check the
token's signature cryptographically you need that authority's
certificate chain:

    $PROG --verify PACKAGE --source DIR --tsa-ca /path/to/ca.pem
EOF
}

# ==========================================================================
# Step 4: attestation
# ==========================================================================

# write_attestation OUT HASH MANIFEST_BYTES COUNT TOTAL_BYTES [NAME]
# Reads the TS_* globals to decide whether a timestamp block is included.
write_attestation() {
    local out="$1" mhash="$2" mbytes="$3" count="$4" total="$5" name="${6-}"

    {
        printf '%s\n\n' "EVIDENCE PRESERVATION ATTESTATION"
        if [ -n "$name" ]; then
            printf '%s\n%s\n\n' "Attesting person:" "$name"
        fi
        printf '%s\n%s\n\n' "Canonical manifest:" "manifest.txt"
        printf '%s\n%s\n\n' "Manifest SHA-256:" "$mhash"
        printf '%s\n%s bytes\n\n' "Manifest size:" "$mbytes"
        printf '%s\n%s\n\n' "Files represented:" "$count"
        printf '%s\n%s\n\n' "Total evidence bytes represented:" "$total"

        if [ "$TS_PRESENT" -eq 1 ]; then
            printf '%s\n%s\n\n' "Trusted timestamp token:" "manifest.txt.tsr"
            printf '%s\n%s\n\n' "Timestamp token SHA-256:" "$TS_TOKEN_SHA"
            printf '%s\n%s\n\n' "Message imprint inside the token:" "$TS_IMPRINT"
            printf '%s\n%s\n\n' "Authority asserted time:" "$TS_TIME"
            printf '%s\n%s\n\n' "Timestamp policy OID:" "$TS_POLICY"
        else
            printf '%s\n%s\n\n' "Trusted timestamp token:" "none (not requested)"
        fi

        cat <<'EOF'
STATEMENT

I attest that I generated the evidence manifest identified
above from files in my possession using the accompanying
preservation procedure.

The SHA-256 digest above identifies the exact bytes of the
canonical manifest to which this statement refers.

The manifest records SHA-256 cryptographic digests and sizes
of the source files represented in it.

My electronic signature on this attestation associates me
with the identified manifest.
EOF

        if [ "$TS_PRESENT" -eq 1 ]; then
            cat <<'EOF'

The accompanying RFC 3161 timestamp token records that the
manifest digest identified above was presented to the timestamp
authority named in that token. If that authority is trustworthy
and its certificate validates, the token establishes that the
manifest already existed at the time the token asserts.

The timestamp does not establish when the underlying source
files were created.
EOF
        else
            cat <<'EOF'

No trusted timestamp accompanies this attestation. The time at
which this manifest was generated therefore rests only on local
records, which are not independently trusted.
EOF
        fi

        cat <<'EOF'

This attestation does not independently establish:

- the truth of statements contained in the underlying files;
- the accuracy of metadata contained in those files;
- the original creation time of any file;
- the actual sender, author or creator of a file;
- the truth of external events described by the evidence.
EOF

        # Only suggest timestamping when there is in fact no token; with one
        # attached the suggestion would contradict the block above.
        if [ "$TS_PRESENT" -eq 0 ]; then
            cat <<'EOF'

Independent trusted timestamping may be used separately.
EOF
        fi
    } > "$out"
}

# write_html OUT ATTESTATION_TXT HASH MANIFEST_BYTES COUNT TOTAL_BYTES
# The body is the verbatim text of attestation.txt, so the printable page can
# never drift from the document that was hashed. No JS, no remote fonts, no
# external resources of any kind.
write_html() {
    local out="$1" att="$2" mhash="$3" mbytes="$4" count="$5" total="$6"

    {
        cat <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Evidence Preservation Attestation</title>
<style>
  @page { size: A4; margin: 20mm; }
  body { font-family: serif; font-size: 11pt; line-height: 1.45;
         color: #000; background: #fff; margin: 20mm; max-width: 170mm; }
  h1 { font-size: 15pt; margin: 0 0 1em 0; }
  .facts { border: 1pt solid #000; padding: 8pt; margin-bottom: 1.2em; }
  .facts dt { font-weight: bold; font-size: 9.5pt; }
  .facts dd { margin: 0 0 6pt 0; font-family: monospace; word-break: break-all; }
  .digest { font-size: 12pt; font-weight: bold; }
  pre { font-family: monospace; font-size: 10pt; white-space: pre-wrap;
        word-break: break-word; margin: 0; }
  .warn { border-top: 1pt solid #000; margin-top: 1.5em; padding-top: 8pt;
          font-size: 9.5pt; }
  @media print { body { margin: 0; } }
</style>
</head>
<body>
<h1>Evidence Preservation Attestation</h1>
<dl class="facts">
EOF
        printf '<dt>Manifest SHA-256</dt><dd class="digest">%s</dd>\n' \
            "$(printf '%s' "$mhash" | html_escape)"
        printf '<dt>Manifest size</dt><dd>%s bytes</dd>\n' \
            "$(printf '%s' "$mbytes" | html_escape)"
        printf '<dt>Files represented</dt><dd>%s</dd>\n' \
            "$(printf '%s' "$count" | html_escape)"
        printf '<dt>Total evidence bytes represented</dt><dd>%s</dd>\n' \
            "$(printf '%s' "$total" | html_escape)"
        if [ "$TS_PRESENT" -eq 1 ]; then
            printf '<dt>Trusted timestamp (RFC 3161)</dt><dd class="digest">%s</dd>\n' \
                "$(printf '%s' "$TS_TIME" | html_escape)"
            printf '<dt>Timestamp token SHA-256</dt><dd>%s</dd>\n' \
                "$(printf '%s' "$TS_TOKEN_SHA" | html_escape)"
        else
            printf '<dt>Trusted timestamp (RFC 3161)</dt><dd>none (not requested)</dd>\n'
        fi
        printf '</dl>\n<pre>'
        html_escape < "$att"
        cat <<'EOF'
</pre>
<div class="warn">
<p><strong>IMPORTANT:</strong><br>
If you print this page to PDF, the PDF becomes a NEW digital
object with different bytes.</p>
<p>Hash and sign the resulting PDF itself.</p>
<p>Do not assume the HTML hash equals the PDF hash.</p>
</div>
</body>
</html>
EOF
    } > "$out"
}

# ==========================================================================
# Shared tail of create/attest: timestamp -> attestation -> summary
# ==========================================================================

# finish_package OUT SRC_LABEL NAME WANT_HTML WANT_OPEN WANT_TS TSA_URL TSR_IN
# Assumes OUT/manifest.txt and OUT/manifest.txt.sha256 already exist and are
# consistent. Writes summary.txt LAST: its presence marks a complete package.
finish_package() {
    local out="$1" src_label="$2" name="$3"
    local want_html="$4" want_open="$5"
    local want_ts="$6" tsa_url="$7" tsr_in="$8"
    local manifest="$out/manifest.txt"
    local mhash mbytes

    mhash="$(sha256_of_file "$manifest")"
    mbytes="$(size_of_file "$manifest")"
    manifest_stats "$manifest"

    # ---- step 3: trusted timestamp (only when explicitly requested) -------
    TS_PRESENT=0
    if [ "$want_ts" -eq 1 ]; then
        require_openssl_ts
        if [ -n "$tsr_in" ]; then
            # Offline: attach a token the operator obtained elsewhere.
            [ -f "$tsr_in" ] || die "ERROR: no such timestamp token: $tsr_in"
            cp "$tsr_in" "$out/manifest.txt.tsr"
            TS_SOURCE="attached token (no network): $tsr_in"
        else
            [ -n "$tsa_url" ] || die "ERROR: --timestamp needs --tsa URL (or --tsr FILE)."
            tsa_query "$manifest" "$out/manifest.txt.tsq"
            tsa_fetch "$out/manifest.txt.tsq" "$out/manifest.txt.tsr" "$tsa_url"
            TS_SOURCE="$tsa_url"
        fi

        # A token that does not cover THIS manifest is worse than none.
        if ! tsr_check_imprint "$out/manifest.txt.tsr" "$manifest"; then
            rm -f "$out/manifest.txt.tsr" "$out/manifest.txt.tsq"
            die "ERROR: the timestamp token does not cover this manifest." \
                "  token imprint:   $TS_IMPRINT" \
                "  manifest SHA-256: $mhash" \
                "The token was discarded. The manifest is unaffected."
        fi
        TS_PRESENT=1
        printf '%s  %s\n' "$TS_TOKEN_SHA" "manifest.txt.tsr" > "$out/manifest.txt.tsr.sha256"
        write_timestamp_txt "$out/timestamp.txt"
        note "Timestamp attached: $TS_TIME"
    fi

    # ---- step 4: attestation ---------------------------------------------
    write_attestation "$out/attestation.txt" "$mhash" "$mbytes" \
        "$MANIFEST_COUNT" "$MANIFEST_TOTAL" "$name"
    printf '%s  %s\n' "$(sha256_of_file "$out/attestation.txt")" "attestation.txt" \
        > "$out/attestation.txt.sha256"

    if [ "$want_html" -eq 1 ]; then
        write_html "$out/attestation.html" "$out/attestation.txt" \
            "$mhash" "$mbytes" "$MANIFEST_COUNT" "$MANIFEST_TOTAL"
    fi

    # ---- summary: written last, so its presence means "complete" ---------
    {
        printf '%s\n\n' "PODPI.sh PRESERVATION SUMMARY"
        printf '%s\n%s\n\n' "Source directory:" "$src_label"
        printf '%s\n%s\n\n' "Manifest:" "manifest.txt"
        printf '%s\n%s\n\n' "Manifest SHA-256:" "$mhash"
        printf '%s\n%s\n\n' "Manifest bytes:" "$mbytes"
        printf '%s\n%s\n\n' "Files represented:" "$MANIFEST_COUNT"
        printf '%s\n%s bytes\n%s MiB\n\n' "Total evidence bytes:" \
            "$MANIFEST_TOTAL" "$(mib "$MANIFEST_TOTAL")"
        printf '%s\n%s\n\n' "Non-regular entries skipped (symlinks, devices, ...):" \
            "$NON_REGULAR_COUNT"
        if [ "$TS_PRESENT" -eq 1 ]; then
            printf '%s\n%s\n\n' "Trusted timestamp:" "PRESENT"
            printf '%s\n%s\n\n' "Authority asserted time:" "$TS_TIME"
            printf '%s\n%s\n\n' "Obtained from:" "$TS_SOURCE"
        else
            printf '%s\n%s\n\n' "Trusted timestamp:" "ABSENT (not requested)"
        fi
        printf '%s\n%s\n\n' "Generation time (local clock):" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        cat <<'EOF'
IMPORTANT:
The generation time above is recorded by this local computer.
It is NOT an independently trusted timestamp.

EOF
        printf '%s\n%s\n\n' "Source files changed during hashing:" "0"
        printf '%s\n%s\n' "Package status:" "COMPLETE"
    } > "$out/summary.txt"

    print_next_steps "$out" "$mhash" "$want_html" "$want_open"
}

print_next_steps() {
    local out="$1" mhash="$2" want_html="$3" want_open="$4"

    cat <<EOF

==================================================
PRESERVATION PACKAGE CREATED
==================================================

Manifest:
$out/manifest.txt

Manifest SHA-256:
$mhash

Attestation:
$out/attestation.txt

EOF
    if [ "$TS_PRESENT" -eq 1 ]; then
        printf '%s\n%s\n\n' "Trusted timestamp (RFC 3161) asserted time:" "$TS_TIME"
    else
        cat <<EOF
Trusted timestamp:
none -- not requested.

To add one (this is the only step that uses the network):

   $PROG --attest $out --timestamp --tsa https://YOUR.TSA/endpoint

EOF
    fi
    cat <<EOF
Next steps:

1. Review attestation.txt.

2. Confirm that the SHA-256 printed in the attestation exactly
   matches manifest.txt.sha256.

3. Sign attestation.txt using your chosen electronic signature
   service.

OR:

4. If you prefer PDF:

   open attestation.html
   Print -> Save as PDF
   hash the resulting PDF with: $PROG --hash-file attestation.pdf
   sign THAT PDF.

5. Preserve together:

   manifest.txt
   manifest.txt.sha256
   attestation.txt
   signed attestation
   summary.txt
   manifest.txt.tsr   (if you obtained a timestamp)

6. Verify at any later time, offline:

   $PROG --verify $out --source YOUR_EVIDENCE_DIR

==================================================
EOF

    if [ "$want_html" -eq 1 ]; then
        printf '\n%s\n%s\n\n' \
            "Open attestation.html in a browser and use Print -> Save as PDF:" \
            "$out/attestation.html"
        if [ "$want_open" -eq 1 ] && [ -n "$OPENER" ]; then
            # Convenience only; a failure to launch a browser is never fatal.
            "$OPENER" "$out/attestation.html" >/dev/null 2>&1 || \
                note "(could not launch a browser; open the file manually)"
        fi
    fi
}

# ==========================================================================
# Mode: create a preservation package  (steps 1-2, then the shared tail)
# ==========================================================================

do_create() {
    local src_in="$1" out_in="$2" name="$3"
    local want_html="$4" want_open="$5"
    local want_ts="$6" tsa_url="$7" tsr_in="$8"
    local src out

    [ -d "$src_in" ] || die "ERROR: not a directory: $src_in"
    src="$(abs_path "$src_in")"
    out="$(abs_path "$out_in")"

    # Never overwrite an existing preservation package.
    [ -e "$out" ] && die "ERROR: output already exists, refusing to overwrite:" "$out"

    # Refuse layouts in which the package could end up hashing itself.
    if [ "$src" = "$out" ]; then
        die "ERROR: source and output directory are the same path."
    fi
    if path_is_inside "$out" "$src"; then
        die "ERROR: output directory lies inside the source directory:" \
            "  source: $src" "  output: $out" \
            "Choose an output path outside the evidence tree."
    fi
    if path_is_inside "$src" "$out"; then
        die "ERROR: source directory lies inside the output directory:" \
            "  source: $src" "  output: $out"
    fi

    # Fail before doing hours of hashing if the timestamp step cannot work.
    if [ "$want_ts" -eq 1 ]; then
        require_openssl_ts
        [ -n "$tsa_url" ] || [ -n "$tsr_in" ] || \
            die "ERROR: --timestamp needs --tsa URL (or --tsr FILE)."
    fi

    note "Scanning: $src"
    collect_paths "$src"
    local count=${#REL_PATHS[@]}
    [ "$count" -gt 0 ] || die "ERROR: no regular files found under: $src"
    note "Hashing $count files ..."

    mkdir "$out"
    PARTIAL_OUTPUT="$out"
    trap cleanup_partial EXIT INT TERM

    # ---- step 2: the canonical manifest ----------------------------------
    # Fixed header: no time, no host, no user, no absolute path -- so
    # re-running over unchanged bytes reproduces byte-identical output.
    local manifest="$out/manifest.txt"
    {
        printf '%s\n' "$MANIFEST_MAGIC"
        printf '%s\n' "# FORMAT: 1"
        printf '%s\n' "# HASH: SHA-256"
        printf '%s\n' "$MANIFEST_COLUMNS"
    } > "$manifest"

    hash_tree "$src" "$manifest"

    printf '%s  %s\n' "$(sha256_of_file "$manifest")" "manifest.txt" \
        > "$out/manifest.txt.sha256"

    # Local convenience only -- explicitly outside the evidence identity.
    {
        printf '%s\n' "$src"
        printf '%s\n' "# This file records where the evidence lived on this computer."
        printf '%s\n' "# It is local convenience metadata and is NOT part of the"
        printf '%s\n' "# canonical evidence identity. Nothing in manifest.txt depends on it."
    } > "$out/source-path.txt"

    # The expensive, irreplaceable work is now safely on disk. From here a
    # failure (typically an unreachable TSA) must NOT throw it away: the
    # package is left as manifest-only and --attest can finish it.
    PARTIAL_OUTPUT=""
    RECOVER_PKG="$out"
    trap recovery_hint EXIT INT TERM

    finish_package "$out" "$src_in" "$name" \
        "$want_html" "$want_open" "$want_ts" "$tsa_url" "$tsr_in"

    RECOVER_PKG=""
    trap - EXIT INT TERM
}

# ==========================================================================
# Mode: finish a manifest-only package (recovery, or add a timestamp later)
# ==========================================================================

do_attest() {
    local pkg_in="$1" name="$2" want_html="$3" want_open="$4"
    local want_ts="$5" tsa_url="$6" tsr_in="$7"
    local pkg manifest recorded observed src_label

    [ -d "$pkg_in" ] || die "ERROR: not a directory: $pkg_in"
    pkg="$(abs_path "$pkg_in")"
    manifest="$pkg/manifest.txt"
    [ -f "$manifest" ] || die "ERROR: no manifest.txt in package: $pkg"

    # Never overwrite an attestation that already exists; it may be signed.
    [ -e "$pkg/attestation.txt" ] && \
        die "ERROR: attestation.txt already exists in: $pkg" \
            "Refusing to overwrite it -- it may already be signed." \
            "To timestamp this manifest without touching the attestation:" \
            "  $PROG --timestamp-file $manifest --tsa URL"

    # Only attest a manifest that still matches its recorded digest.
    [ -f "$pkg/manifest.txt.sha256" ] || die "ERROR: missing manifest.txt.sha256 in: $pkg"
    recorded="$(cut -d' ' -f1 < "$pkg/manifest.txt.sha256")"
    observed="$(sha256_of_file "$manifest")"
    [ "$recorded" = "$observed" ] || \
        die "ERROR: manifest.txt does not match manifest.txt.sha256." \
            "Refusing to attest an altered manifest."

    src_label="(unrecorded)"
    if [ -f "$pkg/source-path.txt" ]; then
        src_label="$(head -n 1 < "$pkg/source-path.txt")"
    fi

    RECOVER_PKG="$pkg"
    trap recovery_hint EXIT INT TERM

    finish_package "$pkg" "$src_label" "$name" \
        "$want_html" "$want_open" "$want_ts" "$tsa_url" "$tsr_in"

    RECOVER_PKG=""
    trap - EXIT INT TERM
}

# ==========================================================================
# Mode: timestamp any single file (e.g. the PDF you are about to sign)
# ==========================================================================

do_timestamp_file() {
    local f="$1" tsa_url="$2" tsr_in="$3"

    [ -f "$f" ] || die "ERROR: not a regular file: $f"
    require_openssl_ts

    if [ -n "$tsr_in" ]; then
        [ -f "$tsr_in" ] || die "ERROR: no such timestamp token: $tsr_in"
        [ -e "$f.tsr" ] && die "ERROR: $f.tsr already exists; refusing to overwrite."
        cp "$tsr_in" "$f.tsr"
        TS_SOURCE="attached token (no network): $tsr_in"
    else
        [ -n "$tsa_url" ] || die "ERROR: --timestamp-file needs --tsa URL (or --tsr FILE)."
        [ -e "$f.tsq" ] && die "ERROR: $f.tsq already exists; refusing to overwrite."
        [ -e "$f.tsr" ] && die "ERROR: $f.tsr already exists; refusing to overwrite."
        tsa_query "$f" "$f.tsq"
        tsa_fetch "$f.tsq" "$f.tsr" "$tsa_url"
        TS_SOURCE="$tsa_url"
    fi

    if ! tsr_check_imprint "$f.tsr" "$f"; then
        rm -f "$f.tsr" "$f.tsq"
        die "ERROR: the timestamp token does not cover this file." \
            "  token imprint: $TS_IMPRINT" \
            "  file SHA-256:  $(sha256_of_file "$f")" \
            "The token was discarded."
    fi

    printf '%s  %s\n' "$TS_TOKEN_SHA" "$(basename "$f").tsr" > "$f.tsr.sha256"

    printf '%s\n' "File:"                        "$f"
    printf '%s\n' "SHA-256:"                     "$(sha256_of_file "$f")"
    printf '%s\n' "Timestamp token:"             "$f.tsr"
    printf '%s\n' "Token SHA-256:"               "$TS_TOKEN_SHA"
    printf '%s\n' "Authority asserted time:"     "$TS_TIME"
    printf '%s\n' "Obtained from:"               "$TS_SOURCE"
}

# ==========================================================================
# Step 6: verification  (entirely offline)
# ==========================================================================

# verify_timestamp PKG MANIFEST CA_FILE -> prints a report, returns non-zero
# on a real failure. Two independent levels:
#   (a) imprint check  -- no CA needed; proves the token is about THIS manifest
#   (b) signature check -- needs --tsa-ca; proves the token is authentic
verify_timestamp() {
    local pkg="$1" manifest="$2" ca="$3"
    local tsr="$pkg/manifest.txt.tsr"

    if [ ! -f "$tsr" ]; then
        printf '%s\n%s\n\n' "Trusted timestamp:" "ABSENT (none was requested)"
        return 0
    fi
    if ! command -v "$OPENSSL_BIN" >/dev/null 2>&1 || ! "$OPENSSL_BIN" ts -help >/dev/null 2>&1; then
        printf '%s\n%s\n\n' "Trusted timestamp:" \
            "PRESENT but NOT CHECKED (no openssl with 'ts' available)"
        return 0
    fi

    if ! tsr_check_imprint "$tsr" "$manifest"; then
        printf '%s\n%s\n' "Trusted timestamp:" "FAIL (token does not cover this manifest)"
        printf '  token imprint:    %s\n' "$TS_IMPRINT"
        printf '  manifest SHA-256: %s\n\n' "$(sha256_of_file "$manifest")"
        return 1
    fi

    printf '%s\n%s\n' "Trusted timestamp:" "PRESENT"
    printf '  asserted time:   %s\n' "$TS_TIME"
    printf '  token SHA-256:   %s\n' "$TS_TOKEN_SHA"
    printf '  imprint matches: YES (token covers this exact manifest)\n'

    if [ -n "$ca" ]; then
        if "$OPENSSL_BIN" ts -verify -data "$manifest" -in "$tsr" \
                -CAfile "$ca" -untrusted "$ca" >/dev/null 2>&1; then
            printf '  signature:       VERIFIED against %s\n\n' "$ca"
        else
            printf '  signature:       FAILED to verify against %s\n\n' "$ca"
            return 1
        fi
    else
        printf '  signature:       NOT CHECKED (pass --tsa-ca FILE to verify it)\n\n'
    fi
    return 0
}

do_verify() {
    local pkg_in="$1" src_in="$2" strict="$3" ca="$4"
    local pkg src manifest tmp

    [ -d "$pkg_in" ] || die "ERROR: not a directory: $pkg_in"
    pkg="$(abs_path "$pkg_in")"
    manifest="$pkg/manifest.txt"
    [ -f "$manifest" ] || die "ERROR: no manifest.txt in package: $pkg"

    # Evidence root: --source wins, source-path.txt is a fallback.
    if [ -n "$src_in" ]; then
        src="$src_in"
    elif [ -f "$pkg/source-path.txt" ]; then
        src="$(head -n 1 < "$pkg/source-path.txt")"
        note "Using evidence root recorded in source-path.txt (local metadata only):" "  $src"
    else
        die "ERROR: no evidence root. Pass --source DIRECTORY."
    fi
    [ -d "$src" ] || die "ERROR: evidence root is not a directory: $src"
    src="$(abs_path "$src")"

    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064  # expand $tmp now, on purpose
    trap "rm -rf '$tmp'" EXIT INT TERM

    printf '%s\n\n' "PODPI.sh VERIFICATION"

    if [ ! -f "$pkg/summary.txt" ] || [ ! -f "$pkg/attestation.txt" ]; then
        printf '%s\n%s\n\n' "Package status:" \
            "INCOMPLETE (manifest present, attestation missing -- see --attest)"
    fi

    # ---- 1. manifest integrity -------------------------------------------
    local manifest_status="PASS" recorded observed
    if [ -f "$pkg/manifest.txt.sha256" ]; then
        recorded="$(cut -d' ' -f1 < "$pkg/manifest.txt.sha256")"
        observed="$(sha256_of_file "$manifest")"
        [ "$recorded" = "$observed" ] || manifest_status="FAIL"
    else
        manifest_status="ABSENT"
    fi
    printf '%s\n%s\n\n' "Manifest:" "$manifest_status"
    if [ "$manifest_status" = "FAIL" ]; then
        printf '%s\n%s\n' "RESULT:" "FAIL"
        printf '%s\n' "manifest.txt does not match manifest.txt.sha256; the manifest itself is altered."
        return 1
    fi

    head -n 1 < "$manifest" | grep -qxF "$MANIFEST_MAGIC" || \
        die "ERROR: not a $PROG manifest: $manifest"

    # ---- 2. trusted timestamp (offline) ----------------------------------
    local ts_ok=0
    verify_timestamp "$pkg" "$manifest" "$ca" || ts_ok=1

    # ---- 3. every manifest row against the evidence tree ------------------
    local checked=0 matching=0 changed=0 missing=0 extra=0
    : > "$tmp/listed"
    : > "$tmp/ondisk"
    local changed_report missing_report extra_report
    changed_report=(); missing_report=(); extra_report=()
    local line hash size path abs obs_hash obs_size

    while IFS= read -r line; do
        case "$line" in
            '#'* | "$MANIFEST_COLUMNS" | '') continue ;;
        esac
        IFS=$'\t' read -r hash size path <<< "$line"
        [ -n "$path" ] || die "ERROR: malformed manifest row: $line"

        checked=$(( checked + 1 ))
        printf '%s\n' "$path" >> "$tmp/listed"   # for the extras set-difference
        abs="$src/$path"

        if [ ! -f "$abs" ]; then
            missing=$(( missing + 1 ))
            missing_report+=("$path")
            continue
        fi

        obs_size="$(size_of_file "$abs")"
        if [ "$obs_size" != "$size" ]; then
            changed=$(( changed + 1 ))
            changed_report+=("$path" "expected: $size bytes" "observed: $obs_size bytes")
            continue
        fi

        obs_hash="$(sha256_of_file "$abs")"
        if [ "$obs_hash" != "$hash" ]; then
            changed=$(( changed + 1 ))
            changed_report+=("$path" "expected: $hash" "observed: $obs_hash")
            continue
        fi

        matching=$(( matching + 1 ))
    done < "$manifest"

    # ---- 4. files on disk that the manifest does not list -----------------
    # Set difference via sorted files + comm: portable, and O(n log n) rather
    # than the O(n^2) a pure-Bash membership test would cost on a large tree.
    # A path containing TAB/NEWLINE can never be in the manifest (creation
    # refuses such trees), so it is reported directly as an extra instead of
    # being fed to the line-based comparison.
    local rel
    while IFS= read -r -d '' rel; do
        rel="${rel#./}"
        if has_control_chars "$rel"; then
            extra=$(( extra + 1 ))
            extra_report+=("$(printf '%q' "$rel")")
        else
            printf '%s\n' "$rel" >> "$tmp/ondisk"
        fi
    done < <(cd "$src" && find . -type f -print0)

    sort "$tmp/listed" > "$tmp/listed.s"
    sort "$tmp/ondisk" > "$tmp/ondisk.s"
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        extra=$(( extra + 1 ))
        extra_report+=("$rel")
    done < <(comm -13 "$tmp/listed.s" "$tmp/ondisk.s")

    printf '%s\n%s\n\n' "Files checked:" "$checked"
    printf '%s\n%s\n\n' "Matching:" "$matching"
    printf '%s\n%s\n\n' "Changed:" "$changed"
    printf '%s\n%s\n\n' "Missing:" "$missing"
    printf '%s\n%s\n\n' "Extra:" "$extra"

    if [ "$changed" -gt 0 ]; then
        printf '%s\n' "CHANGED:"
        printf '%s\n' "${changed_report[@]}"
        printf '\n'
    fi
    if [ "$missing" -gt 0 ]; then
        printf '%s\n' "MISSING:"
        printf '%s\n' "${missing_report[@]}"
        printf '\n'
    fi
    if [ "$extra" -gt 0 ]; then
        printf '%s\n' "EXTRA (not listed in the manifest):"
        printf '%s\n' "${extra_report[@]}"
        printf '\n'
    fi

    # Extra files are informational unless --strict was requested.
    if [ "$changed" -gt 0 ] || [ "$missing" -gt 0 ]; then
        printf '%s\n%s\n' "RESULT:" "FAIL"
        return 1
    fi
    if [ "$ts_ok" -ne 0 ]; then
        printf '%s\n%s\n' "RESULT:" "FAIL (timestamp)"
        return 1
    fi
    if [ "$strict" -eq 1 ] && [ "$extra" -gt 0 ]; then
        printf '%s\n%s\n' "RESULT:" "FAIL (--strict: unlisted files present)"
        return 1
    fi
    printf '%s\n%s\n' "RESULT:" "PASS"
    return 0
}

# ==========================================================================
# Mode: hash a single file (e.g. the PDF you are about to sign)
# ==========================================================================

do_hash_file() {
    local f="$1" bytes hash sidecar
    [ -f "$f" ] || die "ERROR: not a regular file: $f"

    bytes="$(size_of_file "$f")"
    hash="$(sha256_of_file "$f")"
    printf '%s\n%s\n%s\n' "$f" "$bytes" "$hash"

    sidecar="$f.sha256"
    if [ -e "$sidecar" ]; then
        note "(not writing $sidecar: it already exists)"
    else
        printf '%s  %s\n' "$hash" "$(basename "$f")" > "$sidecar"
        note "wrote $sidecar"
    fi
}

# ==========================================================================
# Mode: self-test  (no network; the TSA below is generated locally)
# ==========================================================================

do_self_test() {
    local self tmp ev pkg fails=0
    self="$(abs_path "${BASH_SOURCE[0]}")"
    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064  # expand $tmp now, on purpose
    trap "rm -rf '$tmp'" EXIT INT TERM

    ev="$tmp/evidence"
    mkdir -p "$ev/nested"
    printf 'hello\n'                  > "$ev/file.txt"
    printf 'spaces here\n'            > "$ev/file with spaces.txt"
    printf 'zazolc gesla jazn\n'      > "$ev/zażółć.txt"
    printf 'bin\001\002\003\n'        > "$ev/nested/file.bin"

    check() { # check LABEL EXPECTED_RC COMMAND...
        local label="$1" want="$2"; shift 2
        local got=0
        "$@" >"$tmp/out" 2>&1 || got=$?
        if [ "$got" -eq "$want" ]; then
            printf 'ok    %s\n' "$label"
        else
            printf 'FAIL  %s (expected exit %s, got %s)\n' "$label" "$want" "$got"
            sed 's/^/        /' < "$tmp/out"
            fails=$(( fails + 1 ))
        fi
    }

    printf '%s\n' "PODPI.sh SELF-TEST"
    printf 'bash %s / hash=%s / stat=%s\n\n' \
        "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}" "$HASH_KIND" "$STAT_KIND"

    pkg="$tmp/pkg"
    check "create package"                 0 bash "$self" --output "$pkg" "$ev"
    check "verify clean tree"              0 bash "$self" --verify "$pkg" --source "$ev"

    # Determinism: a second package over unchanged bytes must be identical.
    check "create second package"          0 bash "$self" --output "$tmp/pkg2" "$ev"
    check "manifests are byte-identical"   0 cmp -s "$pkg/manifest.txt" "$tmp/pkg2/manifest.txt"

    check "refuse to overwrite package"    1 bash "$self" --output "$pkg" "$ev"
    check "refuse output inside source"    1 bash "$self" --output "$ev/inside" "$ev"

    # Alter one byte -> verification must fail.
    printf 'hellp\n' > "$ev/file.txt"
    check "detect altered byte"            1 bash "$self" --verify "$pkg" --source "$ev"
    printf 'hello\n' > "$ev/file.txt"
    check "verify after restore"           0 bash "$self" --verify "$pkg" --source "$ev"

    # Delete a file -> verification must fail.
    rm "$ev/nested/file.bin"
    check "detect missing file"            1 bash "$self" --verify "$pkg" --source "$ev"
    printf 'bin\001\002\003\n' > "$ev/nested/file.bin"
    check "verify after recreate"          0 bash "$self" --verify "$pkg" --source "$ev"

    # Extra file -> informational by default, fatal under --strict.
    printf 'later\n' > "$ev/extra.txt"
    check "extra file tolerated"           0 bash "$self" --verify "$pkg" --source "$ev"
    check "extra file fails --strict"      1 bash "$self" --verify "$pkg" --source "$ev" --strict
    rm "$ev/extra.txt"

    # A newline in a filename must be refused, not silently escaped.
    printf 'bad\n' > "$ev/new"$'\n'"line.txt"
    check "refuse NEWLINE filename"        1 bash "$self" --output "$tmp/pkg3" "$ev"
    rm "$ev/new"$'\n'"line.txt"

    check "--pdf writes html"              0 bash "$self" --pdf --no-open --output "$tmp/pkg4" "$ev"
    check "attestation.html exists"        0 test -f "$tmp/pkg4/attestation.html"
    check "--hash-file"                    0 bash "$self" --hash-file "$pkg/manifest.txt"

    # Timestamping must never be automatic.
    check "no token without --timestamp"   1 test -f "$pkg/manifest.txt.tsr"
    check "--timestamp needs --tsa"        1 bash "$self" --output "$tmp/pkg5" --timestamp "$ev"
    check "refuse re-attesting a package"  1 bash "$self" --attest "$pkg"

    # ---- RFC 3161, exercised against a throwaway local TSA, no network ----
    if command -v "$OPENSSL_BIN" >/dev/null 2>&1 && "$OPENSSL_BIN" ts -help >/dev/null 2>&1; then
        local t="$tmp/tsa"
        mkdir -p "$t"
        cat > "$t/tsa.cnf" <<'EOF'
[ tsa_cfg ]
serial            = SERIALFILE
crypto_device     = builtin
signer_cert       = CERTFILE
certs             = CERTFILE
signer_key        = KEYFILE
signer_digest     = sha256
default_policy    = 1.2.3.4.1
digests           = sha256,sha512
accuracy          = secs:1
ordering          = yes
tsa_name          = yes
ess_cert_id_chain = no
ess_cert_id_alg   = sha256
EOF
        sed -i.bak -e "s#SERIALFILE#$t/serial#" -e "s#CERTFILE#$t/tsa.crt#" \
                   -e "s#KEYFILE#$t/tsa.key#" "$t/tsa.cnf"
        echo 01 > "$t/serial"
        "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -keyout "$t/tsa.key" -out "$t/tsa.crt" \
            -days 2 -nodes -subj "/CN=podpi local test TSA" \
            -addext "basicConstraints=critical,CA:FALSE" \
            -addext "keyUsage=critical,digitalSignature" \
            -addext "extendedKeyUsage=critical,timeStamping" >/dev/null 2>&1

        # A manifest-only package, as --attest expects to find.
        cp -R "$tmp/pkg2" "$tmp/pkgts"
        rm -f "$tmp/pkgts/attestation.txt" "$tmp/pkgts/attestation.txt.sha256" \
              "$tmp/pkgts/summary.txt"

        "$OPENSSL_BIN" ts -query -data "$tmp/pkgts/manifest.txt" -sha256 -cert \
            -out "$t/good.tsq" >/dev/null 2>&1
        "$OPENSSL_BIN" ts -reply -config "$t/tsa.cnf" -section tsa_cfg \
            -queryfile "$t/good.tsq" -out "$t/good.tsr" >/dev/null 2>&1

        # A token over unrelated data, to prove a wrong token is rejected.
        printf 'unrelated\n' > "$t/other.dat"
        "$OPENSSL_BIN" ts -query -data "$t/other.dat" -sha256 -cert \
            -out "$t/bad.tsq" >/dev/null 2>&1
        "$OPENSSL_BIN" ts -reply -config "$t/tsa.cnf" -section tsa_cfg \
            -queryfile "$t/bad.tsq" -out "$t/bad.tsr" >/dev/null 2>&1

        check "reject token for other data" 1 bash "$self" --attest "$tmp/pkgts" \
            --timestamp --tsr "$t/bad.tsr"
        check "attach token offline"        0 bash "$self" --attest "$tmp/pkgts" \
            --timestamp --tsr "$t/good.tsr" --name "Jan Kowalski"
        check "token file present"          0 test -f "$tmp/pkgts/manifest.txt.tsr"
        check "verify with timestamp"       0 bash "$self" --verify "$tmp/pkgts" --source "$ev"
        check "verify token signature"      0 bash "$self" --verify "$tmp/pkgts" \
            --source "$ev" --tsa-ca "$t/tsa.crt"
        check "attestation cites the token" 0 grep -q "Trusted timestamp token:" \
            "$tmp/pkgts/attestation.txt"

        # Swapping in a foreign token must be caught at verify time.
        cp "$t/bad.tsr" "$tmp/pkgts/manifest.txt.tsr"
        check "detect swapped token"        1 bash "$self" --verify "$tmp/pkgts" --source "$ev"
    else
        printf 'skip  RFC 3161 tests (no openssl with a ts command)\n'
    fi

    printf '\n'
    if [ "$fails" -eq 0 ]; then
        printf '%s\n' "SELF-TEST RESULT: PASS"
        return 0
    fi
    printf '%s\n' "SELF-TEST RESULT: FAIL ($fails)"
    return 1
}

# ==========================================================================
# Argument parsing
# ==========================================================================

main() {
    local mode="create"
    local src="" pkg="" hash_target="" ts_target="" out="" name="" tsa_url="" tsr_in="" ca=""
    local want_html=0 want_open=1 strict=0 want_ts=0

    [ $# -gt 0 ] || { usage; exit 1; }

    while [ $# -gt 0 ]; do
        case "$1" in
            --help | -h)     usage; exit 0 ;;
            --self-test)     mode="self-test"; shift ;;
            --pdf)           want_html=1; shift ;;
            --no-open)       want_open=0; shift ;;
            --strict)        strict=1; shift ;;
            --timestamp)     want_ts=1; shift ;;
            --verify)
                mode="verify"
                [ $# -ge 2 ] || die "ERROR: --verify requires a package directory"
                pkg="$2"; shift 2 ;;
            --attest)
                mode="attest"
                [ $# -ge 2 ] || die "ERROR: --attest requires a package directory"
                pkg="$2"; shift 2 ;;
            --timestamp-file)
                mode="timestamp-file"; want_ts=1
                [ $# -ge 2 ] || die "ERROR: --timestamp-file requires a file"
                ts_target="$2"; shift 2 ;;
            --hash-file | --hash-signed)
                mode="hash-file"
                [ $# -ge 2 ] || die "ERROR: $1 requires a file"
                hash_target="$2"; shift 2 ;;
            --source)
                [ $# -ge 2 ] || die "ERROR: --source requires a directory"
                src="$2"; shift 2 ;;
            --output)
                [ $# -ge 2 ] || die "ERROR: --output requires a directory"
                out="$2"; shift 2 ;;
            --name)
                [ $# -ge 2 ] || die "ERROR: --name requires a value"
                name="$2"; shift 2 ;;
            --tsa)
                [ $# -ge 2 ] || die "ERROR: --tsa requires a URL"
                tsa_url="$2"; shift 2 ;;
            --tsr)
                [ $# -ge 2 ] || die "ERROR: --tsr requires a file"
                tsr_in="$2"; shift 2 ;;
            --tsa-ca)
                [ $# -ge 2 ] || die "ERROR: --tsa-ca requires a file"
                ca="$2"; shift 2 ;;
            --)              shift; break ;;
            -*)              die "ERROR: unknown option: $1" "Try: $PROG --help" ;;
            *)
                [ -z "$src" ] || die "ERROR: more than one directory given: $src and $1"
                src="$1"; shift ;;
        esac
    done
    if [ $# -gt 0 ]; then
        [ -z "$src" ] || die "ERROR: more than one directory given"
        src="$1"
    fi

    # A TSA URL without --timestamp is almost certainly a mistake; refuse it
    # rather than silently skipping the step the operator clearly wanted.
    if [ "$want_ts" -eq 0 ] && { [ -n "$tsa_url" ] || [ -n "$tsr_in" ]; }; then
        die "ERROR: --tsa/--tsr given without --timestamp." \
            "Timestamping is never automatic; add --timestamp to request it."
    fi

    case "$mode" in
        self-test)      do_self_test ;;
        hash-file)      do_hash_file "$hash_target" ;;
        timestamp-file) do_timestamp_file "$ts_target" "$tsa_url" "$tsr_in" ;;
        verify)         do_verify "$pkg" "$src" "$strict" "$ca" ;;
        attest)         do_attest "$pkg" "$name" "$want_html" "$want_open" \
                                  "$want_ts" "$tsa_url" "$tsr_in" ;;
        create)
            [ -n "$src" ] || die "ERROR: no directory given." "Try: $PROG --help"
            [ -n "$out" ] || out="podpi-$(date -u +%Y%m%dT%H%M%SZ)"
            do_create "$src" "$out" "$name" "$want_html" "$want_open" \
                      "$want_ts" "$tsa_url" "$tsr_in"
            ;;
    esac
}

detect_platform
main "$@"

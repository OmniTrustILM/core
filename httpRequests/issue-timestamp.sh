#!/usr/bin/env bash
set -euo pipefail

# Defaults
# The TSP endpoint is POST {ILM_HOST}/api/v1/protocols/tsp/{TSP_PROFILE} (single path segment, no /sign suffix).
# Setting URL directly overrides the ILM_HOST + TSP_PROFILE composition below.
ILM_HOST="http://localhost:8080"
TSP_PROFILE="tsp-non-qualified"
URL=""
# HTTP Basic credentials accepted by the TSP profile (defaults match timestamping-setup.sh).
# Set BASIC_USER to an empty string to send no Authorization header (e.g. when using mTLS client-cert auth).
BASIC_USER="f.jednicka"
BASIC_PASS="your-strong-password"
FILE=""
DIGEST="sha256"
TLS_CA_CERT=""
CA_CERT=""
TSA_CERT=""
CLIENT_CERT=""
CLIENT_KEY=""
POLICY_OID="1.2.3.4.1"
NONCE=true
OUTPUT_DIR="./tmp/tsa-test"
VERBOSE=false

usage() {
    cat <<'EOF'
Usage: test-tsa.sh [OPTIONS]

Test an RFC 3161 TSA endpoint using openssl ts and curl.

The endpoint is composed as {ILM_HOST}/api/v1/protocols/tsp/{TSP_PROFILE} unless -u
overrides it with a full URL. Authenticates with HTTP Basic by default; the credentials
default to the ones provisioned by timestamping-setup.sh.

Options:
  -H ILM_HOST     ILM API origin (default: http://localhost:8080)
  -P TSP_PROFILE  TSP profile name path segment (default: tsp-qualified)
  -u URL          Full TSA URL; overrides -H/-P composition
  -U USERNAME     HTTP Basic username (default: f.jednicka; empty to disable Basic auth)
  -W PASSWORD     HTTP Basic password (default: your-strong-password)
  -f FILE         File to timestamp (default: creates temp file with "Hello TSA")
  -d DIGEST       sha256 | sha384 | sha512 (default: sha256)
  -T TLS_CA       CA certificate for TLS server verification (curl --cacert)
  -c CA_CERT      CA certificate for timestamp token verification
  -t TSA_CERT     TSA signer cert for verification chain (optional)
  -C CLIENT_CERT  Client certificate for mTLS
  -K CLIENT_KEY   Client key for mTLS
  -p POLICY_OID   Request specific policy OID
  -n              Omit nonce
  -o OUTPUT_DIR   Output directory (default: /tmp/tsa-test)
  -v              Verbose
  -h              Show this help
EOF
    exit 0
}

while getopts "H:P:u:U:W:f:d:T:c:t:C:K:p:no:vh" opt; do
    case $opt in
        H) ILM_HOST="$OPTARG" ;;
        P) TSP_PROFILE="$OPTARG" ;;
        u) URL="$OPTARG" ;;
        U) BASIC_USER="$OPTARG" ;;
        W) BASIC_PASS="$OPTARG" ;;
        f) FILE="$OPTARG" ;;
        d) DIGEST="$OPTARG" ;;
        T) TLS_CA_CERT="$OPTARG" ;;
        c) CA_CERT="$OPTARG" ;;
        t) TSA_CERT="$OPTARG" ;;
        C) CLIENT_CERT="$OPTARG" ;;
        K) CLIENT_KEY="$OPTARG" ;;
        p) POLICY_OID="$OPTARG" ;;
        n) NONCE=false ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Compose the endpoint URL from host + profile unless an explicit URL was given.
if [[ -z "$URL" ]]; then
    URL="${ILM_HOST%/}/api/v1/protocols/tsp/${TSP_PROFILE}"
fi

log() {
    if [[ "$VERBOSE" == true ]]; then
        echo "[INFO] $*"
    fi
}

err() {
    echo "[ERROR] $*" >&2
}

diagnose_signature() {
    local tsr="$1"
    local outdir="$2"

    echo "=== Signature Diagnostics ==="

    # Extract the CMS token from the TSP response
    if ! openssl ts -reply -in "$tsr" -token_out -out "$outdir/token_content.der" 2>/dev/null; then
        err "Could not extract token from TSP response"
        echo "==========================="
        return 1
    fi

    # Extract signer certificate using openssl cms
    local cert_pem="$outdir/signer_cert.pem"
    if ! openssl pkcs7 -inform DER -in "$outdir/token_content.der" \
            -print_certs -out "$cert_pem" 2>/dev/null \
       || [[ ! -s "$cert_pem" ]]; then
        err "Could not extract signer certificate from CMS token"
        echo "==========================="
        return 1
    fi

    echo "--- Signer certificate ---"
    openssl x509 -in "$cert_pem" -noout -subject -issuer -serial 2>/dev/null
    echo ""

    # Extract public key
    openssl x509 -in "$cert_pem" -noout -pubkey > "$outdir/signer_pubkey.pem" 2>/dev/null

    # Extract the raw signature bytes using Python
    # The signature is the last BIT STRING in the SignerInfo
    local sig_hex
    sig_hex=$(python3 -c "
import sys
data = open('$tsr', 'rb').read()

# Find the last BIT STRING in the outer structure — this is the signature
# in SignerInfo. We parse minimally: find SignerInfo's encryptedDigest.
# The signature is the final OCTET STRING / BIT STRING value in SignerInfo.
from subprocess import run, PIPE
r = run(['openssl', 'asn1parse', '-in', '$tsr', '-inform', 'DER'],
        capture_output=True, text=True)
lines = r.stdout.strip().split('\n')

# Find the signature: last OCTET STRING at SignerInfo depth
sig_offset = None
sig_length = None
for line in reversed(lines):
    if 'OCTET STRING' in line:
        parts = line.strip().split(':')
        sig_offset = int(parts[0].strip())
        # Parse header length: offset points to tag, we need to skip tag+length
        hl = int([p for p in parts if p.strip().startswith('hl=')][0].split('=')[1].strip().split()[0])
        sig_length = int([p for p in parts if p.strip().startswith('l=')][0].split('=')[1].strip().split()[0])
        break

if sig_offset is not None:
    raw = data[sig_offset + hl : sig_offset + hl + sig_length]
    sys.stdout.write(raw.hex())
else:
    sys.exit(1)
" 2>/dev/null) || {
        err "Could not extract signature bytes"
        echo "==========================="
        return 1
    }

    # Write raw signature to file
    python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('$sig_hex'))" \
        > "$outdir/signature.bin" 2>/dev/null

    # RSA-decrypt the signature to reveal DigestInfo
    echo "--- DigestInfo (RSA-decrypted signature) ---"
    if openssl rsautl -verify -inkey "$outdir/signer_pubkey.pem" -pubin \
        -in "$outdir/signature.bin" -out "$outdir/digestinfo.der" 2>/dev/null; then

        echo "Hex:"
        xxd -p "$outdir/digestinfo.der" | tr -d '\n'
        echo ""
        echo ""
        echo "ASN.1 parse:"
        openssl asn1parse -in "$outdir/digestinfo.der" -inform DER 2>/dev/null
        echo ""

        # Check for NULL parameters in the AlgorithmIdentifier
        local has_null
        has_null=$(openssl asn1parse -in "$outdir/digestinfo.der" -inform DER 2>/dev/null \
            | grep -c "NULL" || true)
        if [[ "$has_null" -gt 0 ]]; then
            echo "AlgorithmIdentifier NULL parameters: PRESENT"
        else
            echo "AlgorithmIdentifier NULL parameters: ABSENT (may cause verification failure)"
        fi

        # Show expected DigestInfo prefix for the hash algorithm
        echo ""
        echo "--- Expected DigestInfo prefixes (DER, with NULL) ---"
        echo "SHA-256: 3031300d060960864801650304020105000420"
        echo "SHA-384: 3041300d060960864801650304020205000430"
        echo "SHA-512: 3051300d060960864801650304020305000440"

        # Compare actual prefix
        local actual_hex
        actual_hex=$(xxd -p "$outdir/digestinfo.der" | tr -d '\n')
        local prefix_len
        case "$DIGEST" in
            sha256) prefix_len=38; expected="3031300d060960864801650304020105000420" ;;  # 19 bytes = 38 hex chars
            sha384) prefix_len=38; expected="3041300d060960864801650304020205000430" ;;
            sha512) prefix_len=38; expected="3051300d060960864801650304020305000440" ;;
        esac
        local actual_prefix="${actual_hex:0:$prefix_len}"
        if [[ "$actual_prefix" == "$expected" ]]; then
            echo "Actual prefix matches expected for $DIGEST: OK"
        else
            echo "MISMATCH — actual prefix: $actual_prefix"
            echo "           expected:       $expected"
        fi
    else
        err "RSA decrypt failed (key may not be RSA, or signature extraction failed)"
    fi

    # Try CMS verify as an alternative code path
    echo ""
    echo "--- CMS verify (bypasses openssl-ts code path) ---"
    if [[ -f "$outdir/token_content.der" ]]; then
        local cms_result
        cms_result=$(openssl cms -verify -in "$outdir/token_content.der" -inform DER \
            -CAfile "$CA_CERT" -purpose any -binary 2>&1) || true
        echo "$cms_result" | head -3
    else
        err "Could not extract token for CMS verify"
    fi

    echo "==========================="
}

# Validate digest
case "$DIGEST" in
    sha256|sha384|sha512) ;;
    *) err "Unsupported digest: $DIGEST (use sha256, sha384, sha512)"; exit 1 ;;
esac

# Check dependencies
for cmd in openssl curl; do
    if ! command -v "$cmd" &>/dev/null; then
        err "Required command not found: $cmd"
        exit 1
    fi
done

# Setup output directory
mkdir -p "$OUTPUT_DIR"
log "Output directory: $OUTPUT_DIR"

QUERY_FILE="$OUTPUT_DIR/query.tsq"
RESPONSE_FILE="$OUTPUT_DIR/response.tsr"

# Create input file if not provided
if [[ -z "$FILE" ]]; then
    FILE="$OUTPUT_DIR/input.txt"
    echo "Hello TSA" > "$FILE"
    log "Created test file: $FILE"
fi

if [[ ! -f "$FILE" ]]; then
    err "File not found: $FILE"
    exit 1
fi

# Step 1: Create timestamp query
log "Creating timestamp query (digest: $DIGEST)..."
QUERY_ARGS=(-query -data "$FILE" "-$DIGEST" -cert -out "$QUERY_FILE")
if [[ "$NONCE" == false ]]; then
    QUERY_ARGS+=(-no_nonce)
fi
if [[ -n "$POLICY_OID" ]]; then
    QUERY_ARGS+=(-tspolicy "$POLICY_OID")
fi

openssl ts "${QUERY_ARGS[@]}"
log "Query written to: $QUERY_FILE"

if [[ "$VERBOSE" == true ]]; then
    echo "--- Query details ---"
    openssl ts -query -in "$QUERY_FILE" -text
    echo "---------------------"
fi

# Generate request ID (Docker-style adjective_noun)
ADJECTIVES=(brave calm clever eager fierce gentle happy keen lively noble quick sharp swift wise bold bright cool daring fair grand)
NOUNS=(tesla fermat newton darwin euler gauss planck curie faraday turing bohr pascal kepler lovelace hopper maxwell boltzmann fourier lagrange noether)
ADJ=${ADJECTIVES[$((RANDOM % ${#ADJECTIVES[@]}))]}
NOUN=${NOUNS[$((RANDOM % ${#NOUNS[@]}))]}
REQUEST_ID="${ADJ}_${NOUN}"
log "Request ID: $REQUEST_ID"

# Step 2: Send query to TSA via curl
log "Sending query to $URL ..."
CURL_ARGS=(--silent --fail-with-body -o "$RESPONSE_FILE"
    -w "%{http_code}"
    -H "Content-Type: application/timestamp-query"
    -H "X-Request-ID: $REQUEST_ID"
    --data-binary "@$QUERY_FILE")
if [[ -n "$BASIC_USER" ]]; then
    CURL_ARGS+=(--user "${BASIC_USER}:${BASIC_PASS}")
fi
if [[ -n "$CLIENT_CERT" ]]; then
    CURL_ARGS+=(--cert "$CLIENT_CERT")
fi
if [[ -n "$CLIENT_KEY" ]]; then
    CURL_ARGS+=(--key "$CLIENT_KEY")
fi
if [[ -n "$TLS_CA_CERT" ]]; then
    CURL_ARGS+=(--cacert "$TLS_CA_CERT")
fi

rm -f "$RESPONSE_FILE"
CURL_STDERR=$(mktemp)
HTTP_CODE=$(curl "${CURL_ARGS[@]}" "$URL" 2>"$CURL_STDERR") || {
    CURL_EXIT=$?
    echo ""
    err "Request to $URL failed (curl exit code: $CURL_EXIT, HTTP status: $HTTP_CODE)"
    # Show curl's own error message (e.g. SSL errors, connection refused)
    if [[ -s "$CURL_STDERR" ]]; then
        err "curl: $(cat "$CURL_STDERR")"
    fi
    # Show response body only if the server actually replied
    if [[ "$HTTP_CODE" != "000" && -f "$RESPONSE_FILE" && -s "$RESPONSE_FILE" ]]; then
        err "Response body:"
        if file -b "$RESPONSE_FILE" | grep -qi text; then
            cat "$RESPONSE_FILE" >&2
        else
            xxd "$RESPONSE_FILE" | head -20 >&2
        fi
    fi
    rm -f "$CURL_STDERR"
    exit 1
}
rm -f "$CURL_STDERR"
log "Response written to: $RESPONSE_FILE (HTTP $HTTP_CODE)"

# Step 3: Inspect response
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== Timestamp Response ==="
python3 "$SCRIPT_DIR/asn1-dump.py" "$RESPONSE_FILE"
echo "=========================="

# Step 4: Verify (optional)
if [[ -n "$CA_CERT" ]]; then
    log "Verifying response..."
    VERIFY_ARGS=(-verify -queryfile "$QUERY_FILE" -in "$RESPONSE_FILE" -CAfile "$CA_CERT")
    if [[ -n "$TSA_CERT" ]]; then
        VERIFY_ARGS+=(-untrusted "$TSA_CERT")
    fi

    if openssl ts "${VERIFY_ARGS[@]}"; then
        echo "Verification: OK"
        if [[ "$VERBOSE" == true ]]; then
            diagnose_signature "$RESPONSE_FILE" "$OUTPUT_DIR"
        fi
    else
        err "Verification failed"
        diagnose_signature "$RESPONSE_FILE" "$OUTPUT_DIR"
        exit 1
    fi
else
    log "Skipping verification (no CA cert provided, use -c to enable)"
fi

echo "Done. Output files in: $OUTPUT_DIR"

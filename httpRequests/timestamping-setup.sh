#!/usr/bin/env bash
# timestamping-setup.sh
#
# Automates the ILM timestamping environment setup:
#   1. Creates five connectors (credential-provider v1, EJBCA, crypto-provider, signature-formatter,
#      and a credential-provider v2 registration used as the vault via its `secret` interface)
#   2. Creates a SoftKeyStore credential from a PKCS12 bundle
#   3. Creates an EJBCA authority instance
#   4. Creates a soft token
#   5. Creates a token profile
#   6. Creates a Time Quality configuration (used by the qualified signing profile)
#   7. Discovers the vault instance (by name) and creates a vault profile under it
#      (the vault profile backs the TSP profiles' Basic credentials)
#   8. Creates the dedicated mapped user the Basic credentials authenticate as,
#      and grants it the TSP timestamping right (role with resource 'tspProfiles' / action 'timestamp')
#   For each of two sets (non-qualified / qualified):
#       9. Creates an RSA 2048 key pair
#      10. Creates an RA profile (resolving EJBCA profile IDs dynamically)
#      11. Issues a TSA certificate with the requested DN suffix
#      12. Polls for certificate issuance completion
#      13. Trusts the certificate chain (marks root CA as trusted, triggers validation)
#      14. Creates and enables a TSP profile (clientCertificate + basicPassword, linked to the vault profile)
#      15. Creates and enables a Signing Profile
#          (qualified profile links to the Time Quality configuration)
#      16. Links the Signing Profile to the TSP Profile bidirectionally
#      17. Creates a Basic (username/password) credential on the TSP profile, mapped to the user
#  18. Grants object-scoped timestamping permissions to the role (applied after both sets exist)
#
# Requires: curl, jq, base64

set -euo pipefail

# --- Defaults -----------------------------------------------------------------
ILM_HOST="http://localhost:8080"

# Authentication mode:
#   header - send the admin certificate in the ssl-client-cert header (local instances).
#   mtls   - present an admin PKCS12 as a real TLS client certificate (remote HTTPS instances).
AUTH_MODE="header"
CLIENT_CERT_PEM=""          # header mode: admin client certificate PEM
CLIENT_P12_BUNDLE=""        # mtls mode:   admin client PKCS12 bundle
CLIENT_P12_PASSPHRASE=""
INSECURE_TLS="false"        # mtls mode:   skip server TLS verification (curl -k)

CONNECTOR_HOST="localhost"
PORT_CRED_PROVIDER="8200"
PORT_EJBCA="8210"
PORT_CRYPTO_PROVIDER="8230"
PORT_FORMATTER="8270"

PKCS12_BUNDLE=""
PKCS12_PASSWORD="00000000"
TOKEN_PASSWORD=""          # defaults to PKCS12_PASSWORD when empty
CERTIFICATE_DN=""          # used as prefix; -non-qualified / -qualified are appended

EJBCA_URL="https://ejbca.3key.company/ejbca/ejbcaws/ejbcaws?wsdl"
EJBCA_EE_PROFILE="DemoTSAEndEntityProfile"
EJBCA_CERT_PROFILE="DemoTSAEECertificateProfile"
EJBCA_CERT_PROFILE_QUALIFIED="DemoTSAQCEECertificateProfile"
EJBCA_CA_NAME="DemoRootCA_2307RSA"

CREDENTIAL_NAME="ejbca.3key.company"
AUTHORITY_NAME="ejbca.3key.company"
TOKEN_NAME="tsa"
TOKEN_PROFILE_NAME="tsa"
KEY_NAME_BASE="tsa-rsa"           # -non-qualified / -qualified appended
RA_PROFILE_NAME_BASE="tsa"        # -non-qualified / -qualified appended
TSP_PROFILE_NAME_BASE="tsp"       # -non-qualified / -qualified appended
SIGNING_PROFILE_NAME_BASE="tsa"   # -non-qualified / -qualified appended
FORMATTER_CONNECTOR_NAME="signature-formatter"

# Vault backing for TSP Basic credentials.
# The common-credential-provider, when registered as a v2 connector, exposes the `secret`
# interface and acts as the vault provider -- no separate vault service is needed. This v2
# registration runs at the same URL/port as the v1 credential-provider (PORT_CRED_PROVIDER).
VAULT_CONNECTOR_NAME="common-credential-provider-v2"
VAULT_INSTANCE_NAME="vault"
VAULT_PROFILE_NAME="timestamping"
# The common-credential-provider vault requires no data attributes at either the instance or the
# profile level (its listVaultAttributes / listVaultProfileAttributes both return an empty list),
# so both creation requests send an empty attributes array. Hardcoded here; not parametrized.

# Mapped user the TSP Basic credentials authenticate as (created if absent; no certificate).
MAPPED_USER_USERNAME="f.jednicka"
MAPPED_USER_FIRST_NAME="Franta Pepa"
MAPPED_USER_LAST_NAME="Jednicka"
MAPPED_USER_EMAIL="franta.pepa.jednicka@example.com"

# Role granting the mapped user the TSP timestamping right (resource 'tspProfiles', action 'timestamp').
# Without it, every TSP request is rejected by the OPA authorization check in TsaServiceImpl.
MAPPED_USER_ROLE_NAME="timestamping"

# TSP Basic credential (created on both TSP profiles).
TSP_CREDENTIAL_USERNAME="f.jednicka"
TSP_CREDENTIAL_PASSWORD="tsp-test-changeme"

# Policy OIDs (hardcoded; can be overridden via CLI)
POLICY_ID_NON_QUALIFIED="1.2.3.4.5.6"
POLICY_ID_QUALIFIED="1.2.3.4.5.7"

# Time Quality configuration (used by the qualified signing profile)
TIME_QUALITY_CONFIG_NAME="time-quality"
TIME_QUALITY_NTP_SERVERS="ntp"       # comma-separated list, e.g. "pool.ntp.org,time.cloudflare.com"
TIME_QUALITY_ACCURACY="PT1S"
TIME_QUALITY_NTP_CHECK_INTERVAL="PT0.5S"
TIME_QUALITY_NTP_CHECK_TIMEOUT="PT0.3S"
TIME_QUALITY_NTP_SAMPLES_PER_SERVER=3
TIME_QUALITY_NTP_SERVERS_MIN_REACHABLE=1
TIME_QUALITY_MAX_CLOCK_DRIFT="PT0.8S"
TIME_QUALITY_LEAP_SECOND_GUARD=true

CERT_POLL_ATTEMPTS=20  # max poll attempts for certificate issuance
CERT_POLL_INTERVAL=1   # seconds between poll attempts

# --- Result variables (populated by setup functions) --------------------------
CLIENT_CERT_HEADER_VAL=""
CURL_AUTH_ARGS=()           # curl auth arguments, built by configure_authentication
MTLS_CERT_PEM=""            # mtls mode: temp file holding client cert extracted from PKCS12 (OpenSSL curl only)
MTLS_KEY_PEM=""             # mtls mode: temp file holding client key extracted from PKCS12 (OpenSSL curl only)
CRED_CONN_UUID=""
EJBCA_CONN_UUID=""
CRYPTO_CONN_UUID=""
FORMATTER_CONN_UUID=""
VAULT_CONN_UUID=""
CRED_UUID=""
AUTH_UUID=""
TOKEN_UUID=""
TOKEN_PROFILE_UUID=""
VAULT_INSTANCE_UUID=""
VAULT_PROFILE_UUID=""
MAPPED_USER_UUID=""
MAPPED_USER_ROLE_UUID=""

# Time Quality configuration
TIME_QUALITY_UUID=""

# Non-qualified set
KEY_UUID_NQ=""
PRIVATE_KEY_ITEM_UUID_NQ=""
RA_PROFILE_UUID_NQ=""
ISSUED_CERT_UUID_NQ=""
TSP_PROFILE_UUID_NQ=""
SIGNING_PROFILE_UUID_NQ=""

# Qualified set
KEY_UUID_Q=""
PRIVATE_KEY_ITEM_UUID_Q=""
RA_PROFILE_UUID_Q=""
ISSUED_CERT_UUID_Q=""
TSP_PROFILE_UUID_Q=""
SIGNING_PROFILE_UUID_Q=""

# --- Usage --------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Required:
  --pkcs12-bundle FILE        Path to PKCS12 bundle with EJBCA client credentials
  --certificate-dn PREFIX     DN prefix for TSA certificates.
                              Actual CNs will be <PREFIX>-non-qualified and <PREFIX>-qualified.
  Plus the admin credential for the chosen --auth-mode (see "ILM API auth").

Connector options (defaults: localhost, ports 8200/8210/8230/8270):
  --connector-host HOST       Hostname for connectors as seen from ILM server
  --port-cred-provider PORT   common-credential-provider port     (default: 8200)
  --port-ejbca PORT           ejbca-ng-connector port             (default: 8210)
  --port-crypto-provider PORT software-cryptography-provider port (default: 8230)
  --port-formatter PORT       signature-formatter-connector port  (default: 8270)
  --formatter-connector-name NAME
                              Signature Formatter Connector name  (default: signature-formatter)
  --vault-connector-name NAME credential-provider v2 connector used as vault
                              (default: common-credential-provider-v2; runs on --port-cred-provider)

Vault / Basic credential options:
  --vault-instance-name NAME  Vault instance name (created if absent; default: vault)
  --vault-profile-name NAME   Vault profile name (created if absent; default: timestamping)
  --mapped-user-username NAME Username of the mapped user for Basic credentials (default: f.jednicka)
  --tsp-credential-username NAME  Basic credential username (default: f.jednicka)
  --tsp-credential-password PASS  Basic credential password (default: tsp-test-changeme)

Credential/token options:
  --pkcs12-password PASS      PKCS12 bundle password     (default: 00000000)
  --token-password PASS       Soft token PIN             (default: same as pkcs12-password)

ILM API auth:
  --ilm-host HOST             URL of ILM API                (default: http://localhost:8080)
                              For a remote instance use the API origin, e.g.
                              https://semik7.3key.company (NOT the /administrator/ FE path).
  --auth-mode MODE            header | mtls                 (default: header)
  --client-cert-pem FILE      Admin client certificate PEM  (required for --auth-mode header)
  --client-p12-bundle FILE    Admin client PKCS12 bundle    (required for --auth-mode mtls)
  --client-p12-password PASS  Admin PKCS12 password
  --insecure-tls              Skip server TLS verification  (mtls only; for untrusted/demo certs)

EJBCA options:
  --ejbca-url URL             EJBCA WSDL URL                     (default https://ejbca.3key.company/ejbca/ejbcaws/ejbcaws?wsdl)
  --ejbca-ca NAME             Issuing CA name                    (default: DemoRootCA_2307RSA)
  --ejbca-ee-profile NAME     End entity profile (both sets)     (default: DemoTSAEndEntityProfile)
  --ejbca-cert-profile NAME   Certificate profile (non-qualified)(default: DemoTSAEECertificateProfile)
  --ejbca-cert-profile-qualified NAME
                              Certificate profile (qualified)    (default: DemoTSAQCEECertificateProfile)

Object name bases (suffixes -non-qualified / -qualified are appended automatically):
  --credential-name NAME      (default: ejbca.3key.company)
  --authority-name NAME       (default: ejbca.3key.company)
  --token-name NAME           (default: tsa)
  --token-profile-name NAME   (default: tsa)
  --key-name NAME             base for key names          (default: tsa-rsa)
  --ra-profile-name NAME      base for RA profile names   (default: tsa)
  --tsp-profile-name NAME     base for TSP profile names  (default: tsp)
  --signing-profile-name NAME base for Signing Profile names (default: tsa)

Certificate polling:
  --cert-poll-attempts N      Max poll attempts for certificate issuance (default: 20)
  --cert-poll-interval N      Seconds between poll attempts              (default: 1)

Time Quality configuration (used by the qualified signing profile):
  --time-quality-name NAME                    (default: time-quality)
  --time-quality-ntp-servers SERVERS          Comma-separated NTP server list (default: ntp)
  --time-quality-accuracy DURATION            ISO-8601 duration (default: PT1S)
  --time-quality-ntp-check-interval DURATION  ISO-8601 duration (default: PT0.5S)
  --time-quality-ntp-check-timeout DURATION   ISO-8601 duration (default: PT0.3S)
  --time-quality-ntp-samples-per-server N     (default: 3)
  --time-quality-ntp-servers-min-reachable N  (default: 1)
  --time-quality-max-clock-drift DURATION     ISO-8601 duration (default: PT0.8S)
  --time-quality-leap-second-guard BOOL       true|false (default: true)
EOF
  exit 1
}

# --- Helpers ------------------------------------------------------------------

log() { echo "==> $*" >&2; }
ok()  { echo "    OK: $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ilm_curl METHOD PATH [-d BODY]
# Fails with a clear message on non-2xx HTTP status.
ilm_curl() {
  local method="$1"; shift
  local path="$1"; shift
  local tmp err http_code response curl_err
  tmp=$(mktemp); err=$(mktemp)
  # Why `|| true`? On a connection/TLS failure curl exits non-zero and `set -e` would abort before the status check below.
  # Swallow curl's exit so the http_code check (000 on connection failure) produces the shaped error message instead.
  http_code=$(curl -s --show-error -o "$tmp" -w "%{http_code}" -X "$method" \
    "${CURL_AUTH_ARGS[@]}" \
    -H "content-type: application/json" \
    "${ILM_HOST}/api${path}" \
    "$@" 2>"$err" || true)
  response=$(<"$tmp"); curl_err=$(<"$err"); rm -f "$tmp" "$err"
  if [[ "$http_code" == "000" ]]; then
    die "Could not reach ILM at ${ILM_HOST} (${method} /api${path}): ${curl_err:-connection failed}"
  fi
  if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
    die "HTTP ${http_code} on ${method} /api${path}: ${response}"
  fi
  echo "$response"
}

# require_uuid RESPONSE CONTEXT -- extracts .uuid from JSON; exits if missing or null
require_uuid() {
  local uuid
  uuid=$(echo "$1" | jq -r '.uuid // empty')
  [[ -z "$uuid" ]] && die "No UUID returned for $2. Response: $1"
  echo "$uuid"
}

# attr_uuid ATTRS_JSON EXPECTED_NAME EXPECTED_CONTENT_TYPE
# Looks up the uuid of an attribute by name + contentType (the stable contract).
# On mismatch, prints each received attribute so the script can be updated.
attr_uuid() {
  local attrs="$1" name="$2" content_type="$3"
  local uuid
  uuid=$(echo "$attrs" | jq -r \
    --arg n "$name" --arg ct "$content_type" \
    'first(.[] | select(.name==$n and .contentType==$ct) | .uuid) // empty')
  if [[ -z "$uuid" ]]; then
    echo "ERROR: Expected attribute  name='${name}'  contentType='${content_type}' -- not found." >&2
    echo "       Received attributes:" >&2
    echo "$attrs" | jq -r \
      '.[] | "         name=\(.name)  contentType=\(.contentType // "(none)")  type=\(.type)"' >&2
    exit 1
  fi
  echo "$uuid"
}

# group_uuid ATTRS_JSON EXPECTED_NAME
# Like attr_uuid but for group-type attributes, which carry no contentType.
group_uuid() {
  local attrs="$1" name="$2"
  local uuid
  uuid=$(echo "$attrs" | jq -r \
    --arg n "$name" \
    'first(.[] | select(.name==$n and .type=="group") | .uuid) // empty')
  if [[ -z "$uuid" ]]; then
    echo "ERROR: Expected group attribute  name='${name}' -- not found." >&2
    echo "       Received attributes:" >&2
    echo "$attrs" | jq -r \
      '.[] | "         name=\(.name)  contentType=\(.contentType // "(none)")  type=\(.type)"' >&2
    exit 1
  fi
  echo "$uuid"
}

# --- Idempotent reuse helpers -------------------------------------------------
# find_named_item <json_array> <name> -> compact JSON of the first element whose .name equals <name>, or empty.
find_named_item() {
  echo "$1" | jq -c --arg n "$2" 'first(.[] | select(.name==$n)) // empty'
}

# uuid_of_named <list_json> <name> -> the item's uuid, or empty if not found.
uuid_of_named() {
  local match; match=$(find_named_item "$1" "$2")
  [[ -n "$match" ]] && echo "$match" | jq -r '.uuid // empty'
}

# list_paginated <path> -> JSON array of .items for POST .../list endpoints
list_paginated() {
  ilm_curl POST "$1" -d '{"itemsPerPage":1000,"pageNumber":1,"filters":[]}' | jq '.items // []'
}

# --- Argument parsing ---------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      --pkcs12-bundle)                          PKCS12_BUNDLE="$2";                          shift 2 ;;
      --pkcs12-password)                        PKCS12_PASSWORD="$2";                        shift 2 ;;
      --token-password)                         TOKEN_PASSWORD="$2";                         shift 2 ;;
      --certificate-dn)                         CERTIFICATE_DN="$2";                         shift 2 ;;
      --ejbca-url)                              EJBCA_URL="$2";                              shift 2 ;;
      --connector-host)                         CONNECTOR_HOST="$2";                         shift 2 ;;
      --port-cred-provider)                     PORT_CRED_PROVIDER="$2";                     shift 2 ;;
      --port-ejbca)                             PORT_EJBCA="$2";                             shift 2 ;;
      --port-crypto-provider)                   PORT_CRYPTO_PROVIDER="$2";                   shift 2 ;;
      --port-formatter)                         PORT_FORMATTER="$2";                         shift 2 ;;
      --formatter-connector-name)               FORMATTER_CONNECTOR_NAME="$2";               shift 2 ;;
      --vault-connector-name)                   VAULT_CONNECTOR_NAME="$2";                   shift 2 ;;
      --vault-instance-name)                    VAULT_INSTANCE_NAME="$2";                    shift 2 ;;
      --vault-profile-name)                     VAULT_PROFILE_NAME="$2";                     shift 2 ;;
      --mapped-user-username)                   MAPPED_USER_USERNAME="$2";                   shift 2 ;;
      --tsp-credential-username)                TSP_CREDENTIAL_USERNAME="$2";                shift 2 ;;
      --tsp-credential-password)                TSP_CREDENTIAL_PASSWORD="$2";                shift 2 ;;
      --ilm-host)                               ILM_HOST="$2";                               shift 2 ;;
      --auth-mode)                              AUTH_MODE="$2";                              shift 2 ;;
      --client-cert-pem)                        CLIENT_CERT_PEM="$2";                        shift 2 ;;
      --client-p12-bundle)                      CLIENT_P12_BUNDLE="$2";                      shift 2 ;;
      --client-p12-password)                    CLIENT_P12_PASSPHRASE="$2";                  shift 2 ;;
      --insecure-tls)                           INSECURE_TLS="true";                         shift   ;;
      --ejbca-ee-profile)                       EJBCA_EE_PROFILE="$2";                       shift 2 ;;
      --ejbca-cert-profile)                     EJBCA_CERT_PROFILE="$2";                     shift 2 ;;
      --ejbca-cert-profile-qualified)           EJBCA_CERT_PROFILE_QUALIFIED="$2";           shift 2 ;;
      --ejbca-ca)                               EJBCA_CA_NAME="$2";                          shift 2 ;;
      --credential-name)                        CREDENTIAL_NAME="$2";                        shift 2 ;;
      --authority-name)                         AUTHORITY_NAME="$2";                         shift 2 ;;
      --token-name)                             TOKEN_NAME="$2";                             shift 2 ;;
      --token-profile-name)                     TOKEN_PROFILE_NAME="$2";                     shift 2 ;;
      --key-name)                               KEY_NAME_BASE="$2";                          shift 2 ;;
      --ra-profile-name)                        RA_PROFILE_NAME_BASE="$2";                   shift 2 ;;
      --tsp-profile-name)                       TSP_PROFILE_NAME_BASE="$2";                  shift 2 ;;
      --signing-profile-name)                   SIGNING_PROFILE_NAME_BASE="$2";              shift 2 ;;
      --cert-poll-attempts)                     CERT_POLL_ATTEMPTS="$2";                     shift 2 ;;
      --cert-poll-interval)                     CERT_POLL_INTERVAL="$2";                     shift 2 ;;
      --time-quality-name)                      TIME_QUALITY_CONFIG_NAME="$2";               shift 2 ;;
      --time-quality-ntp-servers)               TIME_QUALITY_NTP_SERVERS="$2";               shift 2 ;;
      --time-quality-accuracy)                  TIME_QUALITY_ACCURACY="$2";                  shift 2 ;;
      --time-quality-ntp-check-interval)        TIME_QUALITY_NTP_CHECK_INTERVAL="$2";        shift 2 ;;
      --time-quality-ntp-check-timeout)         TIME_QUALITY_NTP_CHECK_TIMEOUT="$2";         shift 2 ;;
      --time-quality-ntp-samples-per-server)    TIME_QUALITY_NTP_SAMPLES_PER_SERVER="$2";    shift 2 ;;
      --time-quality-ntp-servers-min-reachable) TIME_QUALITY_NTP_SERVERS_MIN_REACHABLE="$2"; shift 2 ;;
      --time-quality-max-clock-drift)           TIME_QUALITY_MAX_CLOCK_DRIFT="$2";           shift 2 ;;
      --time-quality-leap-second-guard)         TIME_QUALITY_LEAP_SECOND_GUARD="$2";         shift 2 ;;
      --help|-h)                     usage ;;
      *) echo "Unknown option: $1"; usage ;;
    esac
  done
}

# --- Validation ---------------------------------------------------------------
validate() {
  local errors=0
  [[ -z "$PKCS12_BUNDLE" ]]    && { echo "ERROR: --pkcs12-bundle is required";    errors=$((errors+1)); }
  [[ -z "$CERTIFICATE_DN" ]]   && { echo "ERROR: --certificate-dn is required";   errors=$((errors+1)); }
  case "$AUTH_MODE" in
    header) [[ -z "$CLIENT_CERT_PEM" ]]   && { echo "ERROR: --client-cert-pem is required for --auth-mode header"; errors=$((errors+1)); } ;;
    mtls)   [[ -z "$CLIENT_P12_BUNDLE" ]] && { echo "ERROR: --client-p12-bundle is required for --auth-mode mtls"; errors=$((errors+1)); } ;;
    *)      echo "ERROR: --auth-mode must be 'header' or 'mtls' (got '$AUTH_MODE')";                               errors=$((errors+1)) ;;
  esac
  [[ $errors -gt 0 ]] && usage

  [[ ! -f "$PKCS12_BUNDLE" ]]   && { echo "ERROR: PKCS12 bundle not found: $PKCS12_BUNDLE"; exit 1; }

  command -v jq     &>/dev/null || { echo "ERROR: jq is required but not installed";     exit 1; }
  command -v curl   &>/dev/null || { echo "ERROR: curl is required but not installed";   exit 1; }
  command -v base64 &>/dev/null || { echo "ERROR: base64 is required but not installed"; exit 1; }

  [[ -z "$TOKEN_PASSWORD" ]] && TOKEN_PASSWORD="$PKCS12_PASSWORD"

  configure_authentication
}

# Populates CURL_AUTH_ARGS according to AUTH_MODE.
configure_authentication() {
  if [[ "$AUTH_MODE" == "header" ]]; then
    [[ ! -f "$CLIENT_CERT_PEM" ]] && { echo "ERROR: Client cert PEM not found: $CLIENT_CERT_PEM"; exit 1; }
    # Extract only the base64 body between BEGIN/END CERTIFICATE markers, then URL-encode it.
    local _cert_b64
    _cert_b64=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$CLIENT_CERT_PEM" \
      | grep -v "^-----" | tr -d '\n\r')
    CLIENT_CERT_HEADER_VAL=$(printf '%s' "$_cert_b64" | sed 's/+/%2B/g; s|/|%2F|g; s/=/%3D/g')
    CURL_AUTH_ARGS=(-H "ssl-client-cert: ${CLIENT_CERT_HEADER_VAL}")
    return
  fi

  # mtls: present the admin PKCS12 as a real TLS client certificate.
  [[ ! -f "$CLIENT_P12_BUNDLE" ]] && { echo "ERROR: Admin PKCS12 not found: $CLIENT_P12_BUNDLE"; exit 1; }
  command -v openssl &>/dev/null || { echo "ERROR: openssl is required for --auth-mode mtls"; exit 1; }

  if curl -V | grep -qi "securetransport"; then
    # SecureTransport curl ignores PEM client certs - it needs a modern PKCS12 bundle (non-legacy PBE).
    if openssl pkcs12 -in "$CLIENT_P12_BUNDLE" -passin "pass:${CLIENT_P12_PASSPHRASE}" \
         -nokeys -clcerts -out /dev/null 2>/dev/null; then
      CURL_AUTH_ARGS=(--cert-type P12 --cert "$CLIENT_P12_BUNDLE" --pass "$CLIENT_P12_PASSPHRASE")
    elif openssl pkcs12 -legacy -in "$CLIENT_P12_BUNDLE" -passin "pass:${CLIENT_P12_PASSPHRASE}" \
         -nokeys -clcerts -out /dev/null 2>/dev/null; then
      die_unsupported_pkcs12 "$CLIENT_P12_BUNDLE"
    else
      die "Cannot read admin PKCS12 ${CLIENT_P12_BUNDLE} (wrong --client-p12-password or corrupt bundle?)"
    fi
  else
    # OpenSSL-backed curl loads PEM client certs directly: extract cert + key from the bundle.
    MTLS_CERT_PEM=$(mktemp)
    MTLS_KEY_PEM=$(mktemp)
    chmod 600 "$MTLS_CERT_PEM" "$MTLS_KEY_PEM"
    trap 'rm -f "$MTLS_CERT_PEM" "$MTLS_KEY_PEM"' EXIT
    extract_p12_pem "$CLIENT_P12_BUNDLE" "$CLIENT_P12_PASSPHRASE" "$MTLS_CERT_PEM" "$MTLS_KEY_PEM"
    CURL_AUTH_ARGS=(--cert "$MTLS_CERT_PEM" --key "$MTLS_KEY_PEM")
  fi
  [[ "$INSECURE_TLS" == "true" ]] && CURL_AUTH_ARGS+=(--insecure)
}

# The admin PKCS12 uses a legacy PBE that SecureTransport curl cannot load.
die_unsupported_pkcs12() {
  local p12="$1" modern="${1%.p12}-modern.p12"
  cat >&2 <<EOF
ERROR: Admin PKCS12 '${p12}' uses a legacy encryption format that SecureTransport curl cannot load.

Convert it once to a modern PKCS12, then re-run with the converted bundle:

  read -rs P12_PASS                     # type the --client-p12-password, then press Enter
  openssl pkcs12 -legacy -in '${p12}' -passin "pass:\$P12_PASS" -nodes -out /tmp/admin-mtls.pem
  openssl pkcs12 -export -in /tmp/admin-mtls.pem -passout "pass:\$P12_PASS" -out '${modern}'
  rm -f /tmp/admin-mtls.pem; unset P12_PASS

Then re-run with:  --client-p12-bundle '${modern}'  (keep the same --client-p12-password)
EOF
  exit 1
}

# Keeps only the PEM blocks from stdin, dropping OpenSSL's "Bag Attributes" dump lines.
pem_only() { sed -n '/-----BEGIN /,/-----END /p'; }

# extract_p12_pem <p12> <password> <out_cert_pem> <out_key_pem>
# Splits a PKCS12 into a client-cert PEM and an unencrypted key PEM. Retries with
# -legacy for bundles using legacy PBE algorithms unsupported by OpenSSL 3 defaults.
extract_p12_pem() {
  local p12="$1" pass="$2" out_cert="$3" out_key="$4" legacy=""
  if ! openssl pkcs12 -in "$p12" -passin "pass:${pass}" -clcerts -nokeys 2>/dev/null | pem_only > "$out_cert"; then
    legacy="-legacy"
    openssl pkcs12 $legacy -in "$p12" -passin "pass:${pass}" -clcerts -nokeys 2>/dev/null | pem_only > "$out_cert" \
      || die "Failed to extract client certificate from ${p12} (wrong password or unsupported format?)"
  fi
  openssl pkcs12 $legacy -in "$p12" -passin "pass:${pass}" -nocerts -nodes 2>/dev/null | pem_only > "$out_key" \
    || die "Failed to extract private key from ${p12} (wrong password or unsupported format?)"
}

# --- Step 1: Connectors -------------------------------------------------------
# On a fresh local instance the connectors don't exist yet and are created.
# On a pre-provisioned instance they're already registered, in WAITING_FOR_APPROVAL status.
# v1 connectors are matched by function group + kind;
# v2 connectors are matched by provided interface and feature flag.
CONNECTORS_V1_JSON=""
CONNECTORS_V2_JSON=""

load_existing_connectors() {
  log "Listing existing connectors..."
  CONNECTORS_V1_JSON=$(ilm_curl GET /v1/connectors)
  CONNECTORS_V2_JSON=$(ilm_curl POST /v2/connectors/list -d \
    '{"itemsPerPage":1000,"pageNumber":1,"filters":[]}' | jq '.items // []')
}

# find_connector <connectors_json> <select_filter>
# Prints "<uuid> <statusCode>" for the first matching connector, or nothing.
find_connector() {
  echo "$1" | jq -r "first(.[] | select($2)) // empty | \"\(.uuid) \(.status)\""
}

# approve_connector <uuid> -- approves a WAITING_FOR_APPROVAL connector and waits until it reaches CONNECTED.
approve_connector() {
  local uuid="$1" attempt status details
  log "  Approving connector ${uuid}..."
  ilm_curl PATCH "/v2/connectors/${uuid}/approve" >/dev/null
  for (( attempt=1; attempt<=20; attempt++ )); do
    details=$(ilm_curl GET "/v1/connectors/${uuid}")
    status=$(echo "$details" | jq -r '.status // empty')
    [[ "$status" == "connected" ]] && { ok "  connector ${uuid} connected"; return 0; }
    sleep 0.5
  done
  die "Connector ${uuid} did not reach 'connected' after approval (last status: '${status}')"
}

# discover_or_create_connector <out_var> <desc> <connectors_json> <filter> <create_fn>
discover_or_create_connector() {
  local out_var="$1" desc="$2" connectors_json="$3" filter="$4" create_fn="$5"
  local match uuid status
  match=$(find_connector "$connectors_json" "$filter")
  if [[ -n "$match" ]]; then
    uuid="${match%% *}"; status="${match##* }"
    log "Found pre-registered ${desc} connector ${uuid} (status=${status})"
    [[ "$status" == "waitingForApproval" ]] && approve_connector "$uuid"
  else
    log "No pre-registered ${desc} connector found; creating it..."
    uuid=$("$create_fn")
  fi
  printf -v "$out_var" '%s' "$uuid"
}

setup_connectors() {
  load_existing_connectors

  discover_or_create_connector CRED_CONN_UUID "credential-provider" "$CONNECTORS_V1_JSON" \
    '(.functionGroups // []) | any(.functionGroupCode=="credentialProvider" and ((.kinds // []) | index("SoftKeyStore")))' \
    create_cred_connector
  ok "common-credential-provider  $CRED_CONN_UUID"

  discover_or_create_connector EJBCA_CONN_UUID "authority (EJBCA)" "$CONNECTORS_V1_JSON" \
    '(.functionGroups // []) | any(.functionGroupCode=="authorityProvider" and ((.kinds // []) | index("EJBCA")))' \
    create_ejbca_connector
  ok "ejbca-ng-connector           $EJBCA_CONN_UUID"

  discover_or_create_connector CRYPTO_CONN_UUID "cryptography-provider" "$CONNECTORS_V1_JSON" \
    '(.functionGroups // []) | any(.functionGroupCode=="cryptographyProvider" and ((.kinds // []) | index("SOFT")))' \
    create_crypto_connector
  ok "software-cryptography-provider  $CRYPTO_CONN_UUID"

  discover_or_create_connector FORMATTER_CONN_UUID "signature-formatter" "$CONNECTORS_V2_JSON" \
    '(.interfaces // []) | any(.code=="signatureFormatting" and ((.features // []) | index("timestamping")))' \
    create_formatter_connector
  ok "signature-formatter  $FORMATTER_CONN_UUID"

  discover_or_create_connector VAULT_CONN_UUID "vault (credential-provider v2)" "$CONNECTORS_V2_JSON" \
    '(.interfaces // []) | any(.code=="secret")' \
    create_vault_connector
  ok "$VAULT_CONNECTOR_NAME  $VAULT_CONN_UUID"
}

create_cred_connector() {
  local _resp
  log "Creating credential-provider connector (port ${PORT_CRED_PROVIDER})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"common-credential-provider\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_CRED_PROVIDER}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v1\"}")
  require_uuid "$_resp" "common-credential-provider connector"
}

create_ejbca_connector() {
  local _resp
  log "Creating ejbca-ng connector (port ${PORT_EJBCA})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"ejbca-ng-connector\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_EJBCA}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v1\"}")
  require_uuid "$_resp" "ejbca-ng-connector connector"
}

create_crypto_connector() {
  local _resp
  log "Creating software-cryptography-provider connector (port ${PORT_CRYPTO_PROVIDER})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"software-cryptography-provider\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_CRYPTO_PROVIDER}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v1\"}")
  require_uuid "$_resp" "software-cryptography-provider connector"
}

create_formatter_connector() {
  local _resp
  log "Creating signature-formatter connector (port ${PORT_FORMATTER})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"${FORMATTER_CONNECTOR_NAME}\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_FORMATTER}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v2\"}")
  require_uuid "$_resp" "signature-formatter connector"
}

create_vault_connector() {
  local _resp
  log "Creating credential-provider v2 connector for vault use (port ${PORT_CRED_PROVIDER})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"${VAULT_CONNECTOR_NAME}\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_CRED_PROVIDER}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v2\"}")
  require_uuid "$_resp" "${VAULT_CONNECTOR_NAME} connector"
}

# --- Step 2: Credential -------------------------------------------------------
setup_credential() {
  local _resp cred_attr_defs ks_type_uuid ks_pass_uuid ks_file_uuid pkcs12_b64 pkcs12_filename _existing _list

  _list=$(ilm_curl GET /v1/credentials)
  _existing=$(find_named_item "$_list" "$CREDENTIAL_NAME")
  if [[ -n "$_existing" ]]; then
    CRED_UUID=$(echo "$_existing" | jq -r '.uuid')
    ok "reusing existing credential '${CREDENTIAL_NAME}'  $CRED_UUID"
    return 0
  fi

  log "Fetching SoftKeyStore credential attribute definitions..."
  cred_attr_defs=$(ilm_curl GET \
    "/v1/connectors/${CRED_CONN_UUID}/attributes/credentialProvider/SoftKeyStore")
  ks_type_uuid=$(attr_uuid "$cred_attr_defs" "keyStoreType"     "string")
  ks_pass_uuid=$(attr_uuid "$cred_attr_defs" "keyStorePassword" "secret")
  ks_file_uuid=$(attr_uuid "$cred_attr_defs" "keyStore"         "file")

  log "Creating credential '${CREDENTIAL_NAME}' from $(basename "$PKCS12_BUNDLE")..."
  pkcs12_b64=$(base64 < "$PKCS12_BUNDLE" | tr -d '\n')
  pkcs12_filename=$(basename "$PKCS12_BUNDLE")

  _resp=$(ilm_curl POST /v1/credentials -d \
    "$(jq -n \
      --arg name        "$CREDENTIAL_NAME" \
      --arg connUuid    "$CRED_CONN_UUID" \
      --arg pass        "$PKCS12_PASSWORD" \
      --arg b64         "$pkcs12_b64" \
      --arg fname       "$pkcs12_filename" \
      --arg ksTypeUuid  "$ks_type_uuid" \
      --arg ksPassUuid  "$ks_pass_uuid" \
      --arg ksFileUuid  "$ks_file_uuid" \
      '{
        name: $name,
        connectorUuid: $connUuid,
        kind: "SoftKeyStore",
        attributes: [
          {
            name: "keyStoreType",
            content: [{data: "PKCS12", reference: "PKCS12"}],
            contentType: "string",
            uuid: $ksTypeUuid,
            version: "v2"
          },
          {
            name: "keyStorePassword",
            content: [{data: {secret: $pass}}],
            contentType: "secret",
            uuid: $ksPassUuid,
            version: "v2"
          },
          {
            name: "keyStore",
            content: [{data: {content: $b64, fileName: $fname, mimeType: "application/x-pkcs12"}}],
            contentType: "file",
            uuid: $ksFileUuid,
            version: "v2"
          }
        ],
        customAttributes: []
      }')")
  CRED_UUID=$(require_uuid "$_resp" "credential '${CREDENTIAL_NAME}'")
  ok "credential  $CRED_UUID"
}

# --- Step 3: Authority --------------------------------------------------------
setup_authority() {
  local _resp auth_attr_defs auth_url_uuid auth_cred_uuid _existing _list

  _list=$(ilm_curl GET /v1/authorities)
  _existing=$(find_named_item "$_list" "$AUTHORITY_NAME")
  if [[ -n "$_existing" ]]; then
    AUTH_UUID=$(echo "$_existing" | jq -r '.uuid')
    ok "reusing existing authority '${AUTHORITY_NAME}'  $AUTH_UUID"
    return 0
  fi

  log "Fetching EJBCA authority attribute definitions..."
  auth_attr_defs=$(ilm_curl GET \
    "/v1/connectors/${EJBCA_CONN_UUID}/attributes/authorityProvider/EJBCA")
  auth_url_uuid=$(attr_uuid  "$auth_attr_defs" "url"        "string")
  auth_cred_uuid=$(attr_uuid "$auth_attr_defs" "credential" "credential")

  log "Creating EJBCA authority '${AUTHORITY_NAME}'..."
  _resp=$(ilm_curl POST /v1/authorities -d \
    "$(jq -n \
      --arg name         "$AUTHORITY_NAME" \
      --arg connUuid     "$EJBCA_CONN_UUID" \
      --arg credUuid     "$CRED_UUID" \
      --arg credName     "$CREDENTIAL_NAME" \
      --arg url          "$EJBCA_URL" \
      --arg authUrlUuid  "$auth_url_uuid" \
      --arg authCredUuid "$auth_cred_uuid" \
      '{
        name: $name,
        connectorUuid: $connUuid,
        kind: "EJBCA",
        attributes: [
          {
            name: "url",
            content: [{data: $url}],
            contentType: "string",
            uuid: $authUrlUuid,
            version: "v2"
          },
          {
            name: "credential",
            content: [{data: {uuid: $credUuid, name: $credName}, reference: $credName}],
            contentType: "credential",
            uuid: $authCredUuid,
            version: "v2"
          }
        ],
        customAttributes: []
      }')")
  AUTH_UUID=$(require_uuid "$_resp" "EJBCA authority '${AUTHORITY_NAME}'")
  ok "authority  $AUTH_UUID"
}

# --- Step 4: Token ------------------------------------------------------------
setup_token() {
  local _resp token_attr_defs tok_action_uuid tok_name_uuid tok_code_uuid _existing
  local opts_uuid create_attrs options_attr_json load_group_uuid _list

  _list=$(ilm_curl GET /v1/tokens)
  _existing=$(find_named_item "$_list" "$TOKEN_NAME")
  if [[ -n "$_existing" ]]; then
    TOKEN_UUID=$(echo "$_existing" | jq -r '.uuid')
    ok "reusing existing token '${TOKEN_NAME}'  $TOKEN_UUID"
    return 0
  fi

  log "Fetching SOFT token attribute definitions..."
  token_attr_defs=$(ilm_curl GET \
    "/v1/connectors/${CRYPTO_CONN_UUID}/attributes/cryptographyProvider/SOFT")

  # The SOFT crypto connector returns two different attribute schemas depending on whether it already has any token
  # instances:
  #   - empty connector  -> data_createTokenAction/newTokenName/tokenCode at top level
  #   - has token(s)     -> a 'data_options' selector whose 'group_loadToken' callback (option=new) yields the real create attributes
  # This script may run against either state, so it must handle both.
  opts_uuid=$(echo "$token_attr_defs" | jq -r \
    'first(.[] | select(.name=="data_options" and .type=="data") | .uuid) // empty')

  if [[ -n "$opts_uuid" ]]; then
    load_group_uuid=$(group_uuid "$token_attr_defs" "group_loadToken")
    log "Resolving 'new token' attributes via connector callback..."
    create_attrs=$(ilm_curl POST \
      "/v1/connectors/${CRYPTO_CONN_UUID}/cryptographyProvider/SOFT/callback" -d \
      "$(jq -n --arg uuid "$load_group_uuid" \
        '{uuid:$uuid,name:"group_loadToken",pathVariable:{option:"new"},requestParameter:{},body:{}}')")
    options_attr_json=$(jq -nc --arg optsUuid "$opts_uuid" \
      '{name:"data_options",content:[{reference:"Create new Token",data:"new"}],contentType:"string",uuid:$optsUuid,version:"v2"}')
  else
    create_attrs="$token_attr_defs"
    options_attr_json=""
  fi
  tok_action_uuid=$(attr_uuid "$create_attrs" "data_createTokenAction" "string")
  tok_name_uuid=$(attr_uuid   "$create_attrs" "data_newTokenName"      "string")
  tok_code_uuid=$(attr_uuid   "$create_attrs" "data_tokenCode"         "secret")

  log "Creating soft token '${TOKEN_NAME}'..."
  _resp=$(ilm_curl POST /v1/tokens -d \
    "$(jq -n \
      --arg name          "$TOKEN_NAME" \
      --arg connUuid      "$CRYPTO_CONN_UUID" \
      --arg pin           "$TOKEN_PASSWORD" \
      --arg tokActionUuid "$tok_action_uuid" \
      --arg tokNameUuid   "$tok_name_uuid" \
      --arg tokCodeUuid   "$tok_code_uuid" \
      --argjson optionsAttr "${options_attr_json:-null}" \
      '{
        name: $name,
        connectorUuid: $connUuid,
        kind: "SOFT",
        attributes: (
          [
            {name: "data_createTokenAction", content: [{reference: "new", data: "new"}], contentType: "string", uuid: $tokActionUuid, version: "v2"},
            {name: "data_newTokenName",      content: [{data: $name}],                   contentType: "string", uuid: $tokNameUuid,   version: "v2"},
            {name: "data_tokenCode",         content: [{data: {secret: $pin}}],          contentType: "secret", uuid: $tokCodeUuid,   version: "v2"}
          ]
          + (if $optionsAttr == null then [] else [$optionsAttr] end)
        ),
        customAttributes: []
      }')")
  TOKEN_UUID=$(require_uuid "$_resp" "soft token '${TOKEN_NAME}'")
  ok "token  $TOKEN_UUID"
}

# --- Step 5: Token profile ----------------------------------------------------
setup_token_profile() {
  local _resp _existing _list

  _list=$(ilm_curl GET /v1/tokenProfiles)
  _existing=$(find_named_item "$_list" "$TOKEN_PROFILE_NAME")
  if [[ -n "$_existing" ]]; then
    TOKEN_PROFILE_UUID=$(echo "$_existing" | jq -r '.uuid')
    if [[ "$(echo "$_existing" | jq -r '.enabled // false')" != "true" ]]; then
      ilm_curl PATCH "/v1/tokens/${TOKEN_UUID}/tokenProfiles/${TOKEN_PROFILE_UUID}/enable" >/dev/null
    fi
    ok "reusing existing token profile '${TOKEN_PROFILE_NAME}'  $TOKEN_PROFILE_UUID"
    return 0
  fi

  log "Creating token profile '${TOKEN_PROFILE_NAME}'..."
  _resp=$(ilm_curl POST /v1/tokens/${TOKEN_UUID}/tokenProfiles -d \
    "$(jq -n --arg name "$TOKEN_PROFILE_NAME" \
      '{name: $name, description: "", attributes: [], customAttributes: [],
        usage: ["sign","verify","encrypt","decrypt"]}')")
  TOKEN_PROFILE_UUID=$(require_uuid "$_resp" "token profile '${TOKEN_PROFILE_NAME}'")
  ok "token profile  $TOKEN_PROFILE_UUID"

  log "Enabling token profile..."
  ilm_curl PATCH "/v1/tokens/${TOKEN_UUID}/tokenProfiles/${TOKEN_PROFILE_UUID}/enable" \
    >/dev/null
  ok "token profile enabled"
}

# --- Step 6: Time Quality configuration --------------------------------------
setup_time_quality_config() {
  local _resp ntp_servers_json _existing _list

  _list=$(list_paginated /v1/timeQualityConfigurations/list)
  _existing=$(find_named_item "$_list" "$TIME_QUALITY_CONFIG_NAME")
  if [[ -n "$_existing" ]]; then
    TIME_QUALITY_UUID=$(echo "$_existing" | jq -r '.uuid')
    ok "reusing existing Time Quality configuration '${TIME_QUALITY_CONFIG_NAME}'  $TIME_QUALITY_UUID"
    return 0
  fi

  # Convert comma-separated NTP server list to a JSON array
  ntp_servers_json=$(echo "$TIME_QUALITY_NTP_SERVERS" | \
    jq -Rc 'split(",") | map(ltrimstr(" ") | rtrimstr(" "))')

  log "Creating Time Quality configuration '${TIME_QUALITY_CONFIG_NAME}'..."
  _resp=$(ilm_curl POST /v1/timeQualityConfigurations -d \
    "$(jq -n \
      --arg  name              "$TIME_QUALITY_CONFIG_NAME" \
      --arg  accuracy          "$TIME_QUALITY_ACCURACY" \
      --argjson ntpServers     "$ntp_servers_json" \
      --arg  checkInterval     "$TIME_QUALITY_NTP_CHECK_INTERVAL" \
      --arg  checkTimeout      "$TIME_QUALITY_NTP_CHECK_TIMEOUT" \
      --argjson samplesPerSrv  "$TIME_QUALITY_NTP_SAMPLES_PER_SERVER" \
      --argjson minReachable   "$TIME_QUALITY_NTP_SERVERS_MIN_REACHABLE" \
      --arg  maxClockDrift     "$TIME_QUALITY_MAX_CLOCK_DRIFT" \
      --argjson leapSecGuard   "$TIME_QUALITY_LEAP_SECOND_GUARD" \
      '{
        name:                   $name,
        accuracy:               $accuracy,
        ntpServers:             $ntpServers,
        ntpCheckInterval:       $checkInterval,
        ntpCheckTimeout:        $checkTimeout,
        ntpSamplesPerServer:    $samplesPerSrv,
        ntpServersMinReachable: $minReachable,
        maxClockDrift:          $maxClockDrift,
        leapSecondGuard:        $leapSecGuard,
        customAttributes:       []
      }')")
  TIME_QUALITY_UUID=$(require_uuid "$_resp" "Time Quality configuration '${TIME_QUALITY_CONFIG_NAME}'")
  ok "Time Quality configuration  $TIME_QUALITY_UUID"
}

# --- Step 7a: Vault instance -------------------------------------------------
# Created (or reused) under the credential-provider v2 connector, bound to its `secret` interface.
# The connector requires no instance data attributes, so the request sends an empty attributes array.
setup_vault_instance() {
  local _resp _list _existing iface_uuid

  _list=$(list_paginated /v1/vaults/list)
  _existing=$(find_named_item "$_list" "$VAULT_INSTANCE_NAME")
  if [[ -n "$_existing" ]]; then
    VAULT_INSTANCE_UUID=$(echo "$_existing" | jq -r '.uuid')
    ok "reusing existing vault instance '${VAULT_INSTANCE_NAME}'  $VAULT_INSTANCE_UUID"
    return 0
  fi

  iface_uuid=$(vault_secret_interface_uuid)

  log "Creating vault instance '${VAULT_INSTANCE_NAME}'..."
  _resp=$(ilm_curl POST /v1/vaults -d \
    "$(jq -n \
      --arg name      "$VAULT_INSTANCE_NAME" \
      --arg connUuid  "$VAULT_CONN_UUID" \
      --arg ifaceUuid "$iface_uuid" \
      '{connectorUuid: $connUuid, interfaceUuid: $ifaceUuid, name: $name,
        attributes: [], customAttributes: []}')")
  VAULT_INSTANCE_UUID=$(require_uuid "$_resp" "vault instance '${VAULT_INSTANCE_NAME}'")
  ok "vault instance  $VAULT_INSTANCE_UUID"
}

# vault_secret_interface_uuid -- uuid of the vault connector's `secret` interface (needed as
# interfaceUuid when creating a vault instance).
vault_secret_interface_uuid() {
  local connectors iface
  connectors=$(ilm_curl POST /v2/connectors/list -d \
    '{"itemsPerPage":1000,"pageNumber":1,"filters":[]}' | jq '.items // []')
  iface=$(echo "$connectors" | jq -r --arg u "$VAULT_CONN_UUID" \
    'first(.[] | select(.uuid==$u) | .interfaces[] | select(.code=="secret") | .uuid) // empty')
  [[ -z "$iface" ]] && die "Vault connector ${VAULT_CONN_UUID} exposes no 'secret' interface"
  echo "$iface"
}

# --- Step 7b: Vault profile --------------------------------------------------
# Created under the (reused) vault instance; backs the TSP profiles' Basic credentials.
# The connector requires no profile data attributes, so the request sends an empty attributes array.
setup_vault_profile() {
  local _resp _existing _list

  _list=$(list_paginated /v1/vaultProfiles/list)
  _existing=$(find_named_item "$_list" "$VAULT_PROFILE_NAME")
  if [[ -n "$_existing" ]]; then
    VAULT_PROFILE_UUID=$(echo "$_existing" | jq -r '.uuid')
    if [[ "$(echo "$_existing" | jq -r '.enabled // false')" != "true" ]]; then
      ilm_curl PATCH "/v1/vaults/${VAULT_INSTANCE_UUID}/vaultProfiles/${VAULT_PROFILE_UUID}/enable" >/dev/null
    fi
    ok "reusing existing vault profile '${VAULT_PROFILE_NAME}'  $VAULT_PROFILE_UUID"
    return 0
  fi

  log "Creating vault profile '${VAULT_PROFILE_NAME}'..."
  _resp=$(ilm_curl POST "/v1/vaults/${VAULT_INSTANCE_UUID}/vaultProfiles" -d \
    "$(jq -n --arg name "$VAULT_PROFILE_NAME" \
      '{name: $name, description: "", attributes: [], customAttributes: []}')")
  VAULT_PROFILE_UUID=$(require_uuid "$_resp" "vault profile '${VAULT_PROFILE_NAME}'")
  ok "vault profile  $VAULT_PROFILE_UUID"

  log "Enabling vault profile..."
  ilm_curl PATCH "/v1/vaults/${VAULT_INSTANCE_UUID}/vaultProfiles/${VAULT_PROFILE_UUID}/enable" >/dev/null
  ok "vault profile enabled"
}

# --- Step 8: Mapped user -----------------------------------------------------
# The user the TSP Basic credentials authenticate as. Created without a certificate; a basic
# credential may not map to a system user, so a dedicated regular user is used.
setup_mapped_user() {
  local _resp _list _existing
  _list=$(ilm_curl GET /v1/users)
  _existing=$(find_named_item "$_list" "$MAPPED_USER_USERNAME")
  if [[ -z "$_existing" ]]; then
    # GET /v1/users matches on .username, not .name
    _existing=$(echo "$_list" | jq -c --arg u "$MAPPED_USER_USERNAME" 'first(.[] | select(.username==$u)) // empty')
  fi
  if [[ -n "$_existing" ]]; then
    MAPPED_USER_UUID=$(echo "$_existing" | jq -r '.uuid')
    ok "reusing existing user '${MAPPED_USER_USERNAME}'  $MAPPED_USER_UUID"
    return 0
  fi

  log "Creating user '${MAPPED_USER_USERNAME}' (${MAPPED_USER_FIRST_NAME} ${MAPPED_USER_LAST_NAME})..."
  _resp=$(ilm_curl POST /v1/users -d \
    "$(jq -n \
      --arg username  "$MAPPED_USER_USERNAME" \
      --arg firstName "$MAPPED_USER_FIRST_NAME" \
      --arg lastName  "$MAPPED_USER_LAST_NAME" \
      --arg email     "$MAPPED_USER_EMAIL" \
      '{username: $username, firstName: $firstName, lastName: $lastName, email: $email, enabled: true}')")
  MAPPED_USER_UUID=$(require_uuid "$_resp" "user '${MAPPED_USER_USERNAME}'")
  ok "user  $MAPPED_USER_UUID"
}

# --- Step 8b: Timestamping role ----------------------------------------------
# Serving one RFC 3161 timestamp request runs OPA authorization checks as the calling user,
# scattered across the request path (TsaServiceImpl -> resolver -> CryptographicOperationServiceImpl):
#   tspProfiles/timestamp   - AuthPermissionEvaluationServiceImpl.tspProfileTimestamping (entry gate)
#   tspProfiles/detail      - TspProfileServiceImpl.getTspProfile
#   signingProfiles/detail  - SigningProfileServiceImpl.getSigningProfileModel
#   keys/sign               - CryptographicOperationServiceImpl.signDataWithoutEventHistory (the actual sign)
#   tokens/detail           - same method, parentResource on the sign annotation
#   tokenProfiles/detail    - tokenProfile permission evaluation
# A freshly created user has none of these, so without this step timestamp requests are rejected
# (often deep in the chain, not at the gate).
#
# This function only creates the role and attaches it to the user. The permissions are object-scoped
# to the concrete TSP/signing profiles, token and token profile, which only exist after the TSA sets
# are built -- so they are applied later by grant_timestamping_permissions().
setup_timestamping_role() {
  local _resp _existing _list

  _list=$(ilm_curl GET /v1/roles)
  _existing=$(find_named_item "$_list" "$MAPPED_USER_ROLE_NAME")
  if [[ -n "$_existing" ]]; then
    MAPPED_USER_ROLE_UUID=$(echo "$_existing" | jq -r '.uuid')
    ok "reusing existing role '${MAPPED_USER_ROLE_NAME}'  $MAPPED_USER_ROLE_UUID"
  else
    log "Creating role '${MAPPED_USER_ROLE_NAME}'..."
    _resp=$(ilm_curl POST /v1/roles -d \
      "$(jq -n --arg name "$MAPPED_USER_ROLE_NAME" \
        '{name: $name, description: "TSP timestamping for the mapped user", customAttributes: []}')")
    MAPPED_USER_ROLE_UUID=$(require_uuid "$_resp" "role '${MAPPED_USER_ROLE_NAME}'")
    ok "role  $MAPPED_USER_ROLE_UUID"
  fi

  if [[ "$(ilm_curl GET "/v1/users/${MAPPED_USER_UUID}/roles" \
        | jq -r --arg u "$MAPPED_USER_ROLE_UUID" 'any(.[]; .uuid==$u)')" == "true" ]]; then
    ok "role already attached to user '${MAPPED_USER_USERNAME}'"
  else
    log "Attaching role '${MAPPED_USER_ROLE_NAME}' to user '${MAPPED_USER_USERNAME}'..."
    ilm_curl PUT "/v1/users/${MAPPED_USER_UUID}/roles/${MAPPED_USER_ROLE_UUID}" >/dev/null
    ok "role attached"
  fi
}

# --- Step 18: Object-scoped timestamping permissions -------------------------
# Applied after both TSA sets exist, so every grant targets concrete object UUIDs rather than the
# whole resource. The OPA method policy (CZERTAINLY-Auth-OPA-Policies/policies/method_policy.rego)
# honors object-scoped grants for BOTH request shapes on the timestamp path:
#   - checks that carry the object UUID (tspProfiles/timestamp via SecuredUUID; tokens/detail via the
#     SecuredParentUUID token instance) are matched by the "ActionAllowedForSpecificObject" rule;
#   - name-based checks that carry NO uuid (tspProfiles/detail and signingProfiles/detail load by
#     String name) are matched by the "ActionAllowedForSomeObjects" rule, which grants when the action
#     is allowed for some object under the resource.
# NOTE on keys/sign: the Auth service rejects object-scoped permissions on the 'keys' resource
# (objectAccess=false in the Auth seed -> "Resource 'Keys' does not support object access permissions"),
# so keys/sign must be granted resource-wide as an action, not against any object uuid.
# savePermissions replaces the role's whole permission set, so this is safe to re-apply.
grant_timestamping_permissions() {
  local perm_body
  local nq_tsp_name="${TSP_PROFILE_NAME_BASE}-non-qualified"
  local q_tsp_name="${TSP_PROFILE_NAME_BASE}-qualified"
  local nq_sp_name="${SIGNING_PROFILE_NAME_BASE}-non-qualified"
  local q_sp_name="${SIGNING_PROFILE_NAME_BASE}-qualified"

  perm_body=$(jq -n \
    --arg tspNqUuid "$TSP_PROFILE_UUID_NQ" --arg tspNqName "$nq_tsp_name" \
    --arg tspQUuid  "$TSP_PROFILE_UUID_Q"  --arg tspQName  "$q_tsp_name" \
    --arg spNqUuid  "$SIGNING_PROFILE_UUID_NQ" --arg spNqName "$nq_sp_name" \
    --arg spQUuid   "$SIGNING_PROFILE_UUID_Q"  --arg spQName  "$q_sp_name" \
    --arg tokenUuid "$TOKEN_UUID"          --arg tokenName "$TOKEN_NAME" \
    --arg tpUuid    "$TOKEN_PROFILE_UUID"  --arg tpName    "$TOKEN_PROFILE_NAME" \
    '{
      allowAllResources: false,
      resources: [
        {name:"tspProfiles", allowAllActions:false, actions:[], objects:[
          {uuid:$tspNqUuid, name:$tspNqName, allow:["timestamp","detail"], deny:[]},
          {uuid:$tspQUuid,  name:$tspQName,  allow:["timestamp","detail"], deny:[]}
        ]},
        {name:"signingProfiles", allowAllActions:false, actions:[], objects:[
          {uuid:$spNqUuid, name:$spNqName, allow:["detail"], deny:[]},
          {uuid:$spQUuid,  name:$spQName,  allow:["detail"], deny:[]}
        ]},
        {name:"keys", allowAllActions:false, actions:["sign"], objects:[]},
        {name:"tokens", allowAllActions:false, actions:[], objects:[
          {uuid:$tokenUuid, name:$tokenName, allow:["detail"], deny:[]}
        ]},
        {name:"tokenProfiles", allowAllActions:false, actions:[], objects:[
          {uuid:$tpUuid, name:$tpName, allow:["detail"], deny:[]}
        ]}
      ]
    }')

  log "Granting object-scoped timestamping permissions to role '${MAPPED_USER_ROLE_NAME}'..."
  ilm_curl POST "/v1/roles/${MAPPED_USER_ROLE_UUID}/permissions" -d "$perm_body" >/dev/null
  ok "object-scoped permissions granted"
}

# --- Step 9: Key pair ---------------------------------------------------------
# Usage: setup_key_pair <key_name> <out_key_uuid_var> <out_priv_item_uuid_var>
setup_key_pair() {
  local key_name="$1" out_key_uuid="$2" out_priv_item_uuid="$3"
  local _resp keypair_attr_defs key_alias_uuid key_alg_uuid key_spec_group_uuid
  local key_spec_attrs rsa_key_size_uuid key_details _key_uuid _priv_uuid _existing _list

  _list=$(ilm_curl GET /v1/keys/pairs)
  _existing=$(find_named_item "$_list" "$key_name")
  if [[ -n "$_existing" ]]; then
    _key_uuid=$(echo "$_existing" | jq -r '.uuid')
    ok "reusing existing key '${key_name}'  $_key_uuid"
    key_details=$(ilm_curl GET "/v1/keys/${_key_uuid}")
    _priv_uuid=$(echo "$key_details" | jq -r \
      'first(.items[] | select(.type == "Private") | .uuid) // empty')
    [[ -z "$_priv_uuid" ]] && die "Reused key ${_key_uuid} has no Private key item"
    ok "private key item  $_priv_uuid"
    printf -v "$out_key_uuid"       '%s' "$_key_uuid"
    printf -v "$out_priv_item_uuid" '%s' "$_priv_uuid"
    return 0
  fi

  log "Fetching key pair attribute definitions..."
  keypair_attr_defs=$(ilm_curl GET \
    "/v1/tokens/${TOKEN_UUID}/tokenProfiles/${TOKEN_PROFILE_UUID}/keys/keyPair/attributes")
  key_alias_uuid=$(attr_uuid       "$keypair_attr_defs" "data_keyAlias"     "string")
  key_alg_uuid=$(attr_uuid         "$keypair_attr_defs" "data_keyAlgorithm" "string")
  key_spec_group_uuid=$(group_uuid "$keypair_attr_defs" "group_keySpec")

  log "Fetching RSA key-spec attributes via callback..."
  key_spec_attrs=$(ilm_curl POST "/v1/keys/${TOKEN_PROFILE_UUID}/callback" -d \
    "$(jq -n --arg uuid "$key_spec_group_uuid" \
      '{"uuid":$uuid,"name":"group_keySpec","pathVariable":{"algorithm":"RSA"},
        "requestParameter":{},"body":{},"filter":{}}')")
  rsa_key_size_uuid=$(attr_uuid "$key_spec_attrs" "data_rsaKeySize" "integer")

  log "Creating RSA 2048 key pair '${key_name}'..."
  _resp=$(ilm_curl POST \
    "/v1/tokens/${TOKEN_UUID}/tokenProfiles/${TOKEN_PROFILE_UUID}/keys/keyPair" -d \
    "$(jq -n \
      --arg name            "$key_name" \
      --arg keyAliasUuid    "$key_alias_uuid" \
      --arg keyAlgUuid      "$key_alg_uuid" \
      --arg rsaKeySizeUuid  "$rsa_key_size_uuid" \
      '{
        groupUuids: [],
        name: $name,
        description: "",
        attributes: [
          {
            name: "data_keyAlias",
            content: [{data: $name}],
            contentType: "string",
            uuid: $keyAliasUuid,
            version: "v2"
          },
          {
            name: "data_keyAlgorithm",
            content: [{data: "RSA", reference: "RSA"}],
            contentType: "string",
            uuid: $keyAlgUuid,
            version: "v2"
          },
          {
            name: "data_rsaKeySize",
            content: [{data: 2048, reference: "RSA_2048"}],
            contentType: "integer",
            uuid: $rsaKeySizeUuid,
            version: "v2"
          }
        ],
        customAttributes: []
      }')")
  _key_uuid=$(require_uuid "$_resp" "RSA key pair '${key_name}'")
  ok "key  $_key_uuid"

  log "Enabling key..."
  ilm_curl PATCH "/v1/keys/${_key_uuid}/enable" >/dev/null
  ok "key enabled"

  log "Fetching key details for private key item UUID..."
  key_details=$(ilm_curl GET "/v1/keys/${_key_uuid}")
  _priv_uuid=$(echo "$key_details" | jq -r \
    'first(.items[] | select(.type == "Private") | .uuid) // empty')
  if [[ -z "$_priv_uuid" ]]; then
    echo "ERROR: Could not find Private key item in key ${_key_uuid}. Available items:" >&2
    echo "$key_details" | jq -r '.items[] | "  type=\(.type)  uuid=\(.uuid)"' >&2
    exit 1
  fi
  ok "private key item  $_priv_uuid"

  printf -v "$out_key_uuid"       '%s' "$_key_uuid"
  printf -v "$out_priv_item_uuid" '%s' "$_priv_uuid"
}

# --- Step 10: RA profile (with dynamic EJBCA profile lookup) ------------------
# Usage: setup_ra_profile <ra_name> <cert_profile_name> <out_ra_profile_uuid_var>
setup_ra_profile() {
  local ra_name="$1" ejbca_cert_profile="$2" out_ra_uuid="$3"
  local _resp ra_attrs ee_profile_attr_uuid cert_profile_attr_uuid ca_attr_uuid
  local send_notif_attr_uuid key_recover_attr_uuid username_gen_attr_uuid
  local ejbca_authority_id ee_profile_id cert_profiles cert_profile_id ca_list ejbca_ca_id
  local _ra_uuid _existing _list

  _list=$(ilm_curl GET /v1/raProfiles)
  _existing=$(find_named_item "$_list" "$ra_name")
  if [[ -n "$_existing" ]]; then
    _ra_uuid=$(echo "$_existing" | jq -r '.uuid')
    if [[ "$(echo "$_existing" | jq -r '.enabled // false')" != "true" ]]; then
      ilm_curl PATCH "/v1/authorities/${AUTH_UUID}/raProfiles/${_ra_uuid}/enable" >/dev/null
    fi
    ok "reusing existing RA profile '${ra_name}'  $_ra_uuid"
    printf -v "$out_ra_uuid" '%s' "$_ra_uuid"
    return 0
  fi

  log "Fetching available RA profile attributes from authority..."
  ra_attrs=$(ilm_curl GET "/v1/authorities/${AUTH_UUID}/attributes/raProfile")

  # Extract attribute definition UUIDs from the schema
  ee_profile_attr_uuid=$(attr_uuid   "$ra_attrs" "endEntityProfile"       "object")
  cert_profile_attr_uuid=$(attr_uuid "$ra_attrs" "certificateProfile"     "object")
  ca_attr_uuid=$(attr_uuid           "$ra_attrs" "certificationAuthority" "object")
  send_notif_attr_uuid=$(attr_uuid   "$ra_attrs" "sendNotifications"      "boolean")
  key_recover_attr_uuid=$(attr_uuid  "$ra_attrs" "keyRecoverable"         "boolean")
  username_gen_attr_uuid=$(attr_uuid "$ra_attrs" "usernameGenMethod"      "string")

  # The EJBCA internal authority instance UUID is embedded as a static callback mapping value
  ejbca_authority_id=$(echo "$ra_attrs" | jq -r '
    .[] | select(.name=="certificationAuthority") |
    .attributeCallback.mappings[] |
    select(.to=="authorityId" and has("value")) | .value')

  # Resolve end entity profile ID by name
  ee_profile_id=$(echo "$ra_attrs" | jq -r \
    --arg name "$EJBCA_EE_PROFILE" \
    '.[] | select(.name=="endEntityProfile") | .content[] | select(.data.name==$name) | .data.id')
  [[ -z "$ee_profile_id" ]] && {
    echo "ERROR: End entity profile '$EJBCA_EE_PROFILE' not found. Available:" >&2
    echo "$ra_attrs" | jq -r '.[] | select(.name=="endEntityProfile") | .content[].data.name' >&2
    exit 1
  }
  ok "end-entity profile '$EJBCA_EE_PROFILE'  id=$ee_profile_id"

  log "Resolving certificate profile '${ejbca_cert_profile}'..."
  cert_profiles=$(ilm_curl POST "/v1/raProfiles/${AUTH_UUID}/callback" -d \
    "$(jq -n \
      --arg uuid   "$cert_profile_attr_uuid" \
      --arg authId "$ejbca_authority_id" \
      --argjson eeId "$ee_profile_id" \
      '{"uuid":$uuid,"name":"certificateProfile","pathVariable":{"endEntityProfileId":$eeId,"authorityId":$authId},"requestParameter":{},"body":{},"filter":{}}')")
  cert_profile_id=$(echo "$cert_profiles" | jq -r \
    --arg name "$ejbca_cert_profile" '.[] | select(.data.name==$name) | .data.id')
  [[ -z "$cert_profile_id" ]] && {
    echo "ERROR: Certificate profile '$ejbca_cert_profile' not found. Available:" >&2
    echo "$cert_profiles" | jq -r '.[].data.name' >&2
    exit 1
  }
  ok "certificate profile '$ejbca_cert_profile'  id=$cert_profile_id"

  log "Resolving CA '${EJBCA_CA_NAME}'..."
  ca_list=$(ilm_curl POST "/v1/raProfiles/${AUTH_UUID}/callback" -d \
    "$(jq -n \
      --arg uuid   "$ca_attr_uuid" \
      --arg authId "$ejbca_authority_id" \
      --argjson eeId "$ee_profile_id" \
      '{"uuid":$uuid,"name":"certificationAuthority","pathVariable":{"authorityId":$authId,"endEntityProfileId":$eeId},"requestParameter":{},"body":{},"filter":{}}')")
  ejbca_ca_id=$(echo "$ca_list" | jq -r \
    --arg name "$EJBCA_CA_NAME" '.[] | select(.data.name==$name) | .data.id')
  [[ -z "$ejbca_ca_id" ]] && {
    echo "ERROR: CA '$EJBCA_CA_NAME' not found. Available:" >&2
    echo "$ca_list" | jq -r '.[].data.name' >&2
    exit 1
  }
  ok "CA '$EJBCA_CA_NAME'  id=$ejbca_ca_id"

  log "Creating RA profile '${ra_name}'..."
  _resp=$(ilm_curl POST "/v1/authorities/${AUTH_UUID}/raProfiles" -d \
    "$(jq -n \
      --arg  name          "$ra_name" \
      --arg  eeProfileName "$EJBCA_EE_PROFILE" \
      --argjson eeId       "$ee_profile_id" \
      --arg  eeAttrUuid    "$ee_profile_attr_uuid" \
      --arg  cpName        "$ejbca_cert_profile" \
      --argjson cpId       "$cert_profile_id" \
      --arg  cpAttrUuid    "$cert_profile_attr_uuid" \
      --arg  caName        "$EJBCA_CA_NAME" \
      --argjson caId       "$ejbca_ca_id" \
      --arg  caAttrUuid    "$ca_attr_uuid" \
      --arg  snAttrUuid    "$send_notif_attr_uuid" \
      --arg  krAttrUuid    "$key_recover_attr_uuid" \
      --arg  ugAttrUuid    "$username_gen_attr_uuid" \
      '{
        name: $name,
        description: "",
        attributes: [
          {
            name: "endEntityProfile",
            content: [{data: {id: $eeId, name: $eeProfileName}, reference: $eeProfileName}],
            contentType: "object",
            uuid: $eeAttrUuid,
            version: "v2"
          },
          {
            name: "certificateProfile",
            content: [{data: {id: $cpId, name: $cpName}, reference: $cpName}],
            contentType: "object",
            uuid: $cpAttrUuid,
            version: "v2"
          },
          {
            name: "certificationAuthority",
            content: [{data: {id: $caId, name: $caName}, reference: $caName}],
            contentType: "object",
            uuid: $caAttrUuid,
            version: "v2"
          },
          {
            name: "sendNotifications",
            content: [{data: false}],
            contentType: "boolean",
            uuid: $snAttrUuid,
            version: "v2"
          },
          {
            name: "keyRecoverable",
            content: [{data: false}],
            contentType: "boolean",
            uuid: $krAttrUuid,
            version: "v2"
          },
          {
            name: "usernameGenMethod",
            content: [{data: "CN"}],
            contentType: "string",
            uuid: $ugAttrUuid,
            version: "v2"
          }
        ],
        customAttributes: []
      }')")
  _ra_uuid=$(require_uuid "$_resp" "RA profile '${ra_name}'")
  ok "RA profile  $_ra_uuid"

  log "Enabling RA profile..."
  ilm_curl PATCH "/v1/authorities/${AUTH_UUID}/raProfiles/${_ra_uuid}/enable" >/dev/null
  ok "RA profile enabled"

  printf -v "$out_ra_uuid" '%s' "$_ra_uuid"
}

# --- Step 11: Issue TSA certificate -------------------------------------------
# Usage: issue_certificate <cn> <key_uuid> <priv_item_uuid> <ra_profile_uuid> <out_cert_uuid_var>
issue_certificate() {
  local cn="$1" key_uuid="$2" priv_item_uuid="$3" ra_profile_uuid="$4" out_cert_uuid="$5"
  local _resp csr_attrs cn_uuid sig_attrs sig_scheme_uuid sig_digest_uuid _cert_uuid

  log "Fetching CSR attribute definitions..."
  csr_attrs=$(ilm_curl GET "/v1/certificates/csr/attributes")
  cn_uuid=$(attr_uuid "$csr_attrs" "commonName" "string")

  log "Fetching signature attribute definitions..."
  sig_attrs=$(ilm_curl GET \
    "/v1/operations/tokens/${TOKEN_UUID}/tokenProfiles/${TOKEN_PROFILE_UUID}/keys/${key_uuid}/items/${priv_item_uuid}/signature/RSA/attributes")
  sig_scheme_uuid=$(attr_uuid "$sig_attrs" "data_rsaSigScheme" "string")
  sig_digest_uuid=$(attr_uuid "$sig_attrs" "data_sigDigest"    "string")

  log "Issuing TSA certificate  CN=${cn}..."
  _resp=$(ilm_curl POST \
    "/v2/operations/authorities/${AUTH_UUID}/raProfiles/${ra_profile_uuid}/certificates" -d \
    "$(jq -n \
      --arg cn               "$cn" \
      --arg keyUuid          "$key_uuid" \
      --arg tokenProfileUuid "$TOKEN_PROFILE_UUID" \
      --arg cnUuid           "$cn_uuid" \
      --arg sigSchemeUuid    "$sig_scheme_uuid" \
      --arg sigDigestUuid    "$sig_digest_uuid" \
      '{
        format: "pkcs10",
        request: "",
        attributes: [],
        csrAttributes: [
          {
            name: "commonName",
            content: [{data: $cn}],
            contentType: "string",
            uuid: $cnUuid,
            version: "v2"
          }
        ],
        signatureAttributes: [
          {
            name: "data_rsaSigScheme",
            content: [{data: "PKCS1-v1_5", reference: "PKCS#1 v1.5"}],
            contentType: "string",
            uuid: $sigSchemeUuid,
            version: "v2"
          },
          {
            name: "data_sigDigest",
            content: [{data: "SHA-384", reference: "SHA-384"}],
            contentType: "string",
            uuid: $sigDigestUuid,
            version: "v2"
          }
        ],
        keyUuid: $keyUuid,
        tokenProfileUuid: $tokenProfileUuid,
        customAttributes: []
      }')")
  _cert_uuid=$(require_uuid "$_resp" "TSA certificate CN=${cn}")
  ok "issued certificate  $_cert_uuid"

  printf -v "$out_cert_uuid" '%s' "$_cert_uuid"
}

# --- Step 12: Poll for certificate issuance result ----------------------------
# Usage: poll_certificate <cert_uuid> <cn>
poll_certificate() {
  local cert_uuid="$1" cn="$2"
  local cert_state="" cert_details attempt history err_msg err_text

  log "Waiting for certificate issuance to complete (CN=${cn})..."
  for (( attempt=1; attempt<=CERT_POLL_ATTEMPTS; attempt++ )); do
    cert_details=$(ilm_curl GET "/v1/certificates/${cert_uuid}")
    cert_state=$(echo "$cert_details" | jq -r '.state // empty')
    case "$cert_state" in
      issued)
        ok "certificate state: issued"
        break
        ;;
      failed)
        history=$(ilm_curl GET "/v1/certificates/${cert_uuid}/history")
        err_msg=$(echo "$history" | jq -r '
          first(
            .[] | select(.event=="Issue Certificate" and .status=="FAILED") | .message
          ) // empty')
        # message is a JSON-encoded string: {"message":"<text>"}
        if [[ -n "$err_msg" ]]; then
          err_text=$(echo "$err_msg" | jq -r '. | fromjson | .message' 2>/dev/null \
            || echo "$err_msg")
        else
          err_text="(no error message available in certificate history)"
        fi
        die "Certificate issuance failed: ${err_text}"
        ;;
      *)
        log "  attempt ${attempt}/${CERT_POLL_ATTEMPTS}: state='${cert_state}' -- waiting ${CERT_POLL_INTERVAL}s..."
        sleep "$CERT_POLL_INTERVAL"
        ;;
    esac
  done
  if [[ "$cert_state" != "issued" ]]; then
    die "Certificate issuance timed out after $(( CERT_POLL_ATTEMPTS * CERT_POLL_INTERVAL ))s (last state: '${cert_state}')"
  fi
}


# --- Step 13: Trust the certificate chain -------------------------------------
# Usage: trust_certificate_chain <cert_uuid>
#
# Walks issuerCertificateUuid upward from <cert_uuid> and marks the root CA as
# trustedCa=true. Then waits for the certificate to be re-validated as VALID.
# Required before creating a signing profile: ILM rejects certificates
# whose issuer chain is not fully trusted or whose validation status is not VALID.
trust_certificate_chain() {
  local cert_uuid="$1"
  log "Trusting certificate chain for ${cert_uuid}..."

  local root_uuid
  root_uuid=$(find_root_certificate "$cert_uuid")
  [[ -z "$root_uuid" ]] && return 0

  mark_certificate_as_trusted "$root_uuid"
  wait_for_certificate_validation "$cert_uuid"
  ok "Certificate chain trusted and validated"
}

# find_root_certificate <cert_uuid>
# Returns the UUID of the root CA, or empty if cert is self-signed.
find_root_certificate() {
  local cert_uuid="$1"
  local current_uuid

  current_uuid=$(wait_for_issuer_linkage "$cert_uuid")
  [[ -z "$current_uuid" ]] && return 0

  while [[ -n "$current_uuid" ]]; do
    local cert_details next_uuid
    cert_details=$(ilm_curl GET "/v1/certificates/${current_uuid}")
    next_uuid=$(echo "$cert_details" | jq -r '.issuerCertificateUuid // empty')

    if [[ -z "$next_uuid" ]]; then
      echo "$current_uuid"
      return 0
    fi

    log "  Skipping intermediate ${current_uuid}..."
    current_uuid="$next_uuid"
  done
}

# wait_for_issuer_linkage <cert_uuid>
# Polls until issuerCertificateUuid is available; returns issuer UUID or empty for self-signed.
wait_for_issuer_linkage() {
  local cert_uuid="$1"
  local cert_details current_uuid attempt

  for (( attempt=1; attempt<=10; attempt++ )); do
    cert_details=$(ilm_curl GET "/v1/certificates/${cert_uuid}")
    current_uuid=$(echo "$cert_details" | jq -r '.issuerCertificateUuid // empty')

    [[ -n "$current_uuid" ]] && { echo "$current_uuid"; return 0; }

    if is_self_signed "$cert_details"; then
      ok "Certificate is self-signed (subjectDn == issuerDn), no chain to trust"
      return 0
    fi

    if [[ $attempt -lt 10 ]]; then
      log "  Issuer linkage not yet available, waiting... (${attempt}/10)"
      sleep 0.5
    else
      local issuer
      issuer=$(echo "$cert_details" | jq -r '.issuerDn // empty')
      die "Certificate ${cert_uuid} has issuerDn='${issuer}' but issuerCertificateUuid is still empty after ${attempt} attempts. Issuer cert may not be in the platform."
    fi
  done
}

# is_self_signed <cert_details_json>
is_self_signed() {
  local cert_details="$1"
  local subject issuer
  subject=$(echo "$cert_details" | jq -r '.subjectDn // empty')
  issuer=$(echo "$cert_details" | jq -r '.issuerDn // empty')
  [[ "$subject" == "$issuer" ]]
}

# mark_certificate_as_trusted <root_uuid>
mark_certificate_as_trusted() {
  local root_uuid="$1"
  log "  Found root certificate ${root_uuid}, marking as trusted..."
  ilm_curl PATCH "/v1/certificates/${root_uuid}" -d '{"trustedCa": true}' >/dev/null
  ok "  Root certificate ${root_uuid} marked trusted"
}

# wait_for_certificate_validation <cert_uuid>
# Polls until the certificate validationStatus becomes VALID after trusting the chain.
# Marking the root CA as trusted does NOT automatically trigger re-validation, so we
# explicitly request validation results which triggers validation as a side effect.
wait_for_certificate_validation() {
  local cert_uuid="$1"
  local validation_result validation_status attempt

  log "  Waiting for certificate ${cert_uuid} to be re-validated..."
  for (( attempt=1; attempt<=20; attempt++ )); do
    # Request validation result; this endpoint triggers validation if not recent
    validation_result=$(ilm_curl GET "/v1/certificates/${cert_uuid}/validate")
    validation_status=$(echo "$validation_result" | jq -r '.resultStatus // empty')

    if [[ "$validation_status" == "valid" || "$validation_status" == "expiring" ]]; then
      ok "  Certificate validation status: ${validation_status}"
      return 0
    fi

    if [[ $attempt -lt 20 ]]; then
      sleep 0.5
    else
      die "Certificate ${cert_uuid} validation status is '${validation_status}' after ${attempt} attempts (expected 'valid' or 'expiring'). Validation result: ${validation_result}"
    fi
  done
}

# --- Step 14: TSP profile -----------------------------------------------------
# Usage: setup_tsp_profile <name> <out_tsp_uuid_var>
setup_tsp_profile() {
  local tsp_name="$1" out_tsp_uuid="$2"
  local _resp _tsp_uuid _existing _list

  _list=$(list_paginated /v1/tspProfiles/list)
  _existing=$(find_named_item "$_list" "$tsp_name")
  if [[ -n "$_existing" ]]; then
    _tsp_uuid=$(echo "$_existing" | jq -r '.uuid')
    if [[ "$(echo "$_existing" | jq -r '.enabled // false')" != "true" ]]; then
      ilm_curl PATCH "/v1/tspProfiles/${_tsp_uuid}/enable" >/dev/null
    fi
    ok "reusing existing TSP profile '${tsp_name}'  $_tsp_uuid"
    printf -v "$out_tsp_uuid" '%s' "$_tsp_uuid"
    return 0
  fi

  log "Creating TSP profile '${tsp_name}'..."
  _resp=$(ilm_curl POST /v1/tspProfiles -d \
    "$(jq -n --arg name "$tsp_name" --arg vaultProfileUuid "$VAULT_PROFILE_UUID" \
      '{name: $name,
        vaultProfileUuid: $vaultProfileUuid,
        allowedAuthenticationMethods: ["clientCertificate", "basicPassword"],
        customAttributes: []}')")
  _tsp_uuid=$(require_uuid "$_resp" "TSP profile '${tsp_name}'")
  ok "TSP profile  $_tsp_uuid"

  log "Enabling TSP profile..."
  ilm_curl PATCH "/v1/tspProfiles/${_tsp_uuid}/enable" >/dev/null
  ok "TSP profile enabled"

  printf -v "$out_tsp_uuid" '%s' "$_tsp_uuid"
}

# --- Step 17: TSP Basic credential -------------------------------------------
# Usage: setup_tsp_basic_credential <tsp_uuid>
# Creates a username/password credential on the TSP profile, mapped to MAPPED_USER_UUID.
# Idempotent: usernames are unique per profile (create returns 409), so an existing one is reused.
setup_tsp_basic_credential() {
  local tsp_uuid="$1"
  local _creds _existing

  _creds=$(ilm_curl GET "/v1/tspProfiles/${tsp_uuid}/basicCredentials")
  _existing=$(echo "$_creds" | jq -c --arg u "$TSP_CREDENTIAL_USERNAME" \
    'first(.[] | select(.username==$u)) // empty')
  if [[ -n "$_existing" ]]; then
    ok "reusing existing Basic credential '${TSP_CREDENTIAL_USERNAME}' on TSP profile ${tsp_uuid}"
    return 0
  fi

  log "Creating Basic credential '${TSP_CREDENTIAL_USERNAME}' on TSP profile ${tsp_uuid}..."
  ilm_curl POST "/v1/tspProfiles/${tsp_uuid}/basicCredentials" -d \
    "$(jq -n \
      --arg username      "$TSP_CREDENTIAL_USERNAME" \
      --arg password      "$TSP_CREDENTIAL_PASSWORD" \
      --arg mappedUserUuid "$MAPPED_USER_UUID" \
      '{username: $username, password: $password, mappedUserUuid: $mappedUserUuid}')" >/dev/null
  ok "Basic credential created"
}

# --- Step 15: Signing Profile -------------------------------------------------
# Usage: setup_signing_profile <sp_name> <cert_uuid> <policy_oid> <time_quality_uuid> <formatter_conn_uuid> <out_sp_uuid_var>
#
# Pass a non-empty <time_quality_uuid> for the qualified profile to enable
# qualifiedTimestamp and link to the Time Quality configuration.
# Pass an empty string for the non-qualified profile.
setup_signing_profile() {
  local sp_name="$1" cert_uuid="$2" policy_oid="$3" time_quality_uuid="$4" formatter_conn_uuid="$5" out_sp_uuid="$6"
  local _resp sig_attrs sig_scheme_uuid sig_digest_uuid _sp_uuid formatter_attrs
  local qualified_timestamp _existing _list

  _list=$(list_paginated /v1/signingProfiles/list)
  _existing=$(find_named_item "$_list" "$sp_name")
  if [[ -n "$_existing" ]]; then
    _sp_uuid=$(echo "$_existing" | jq -r '.uuid')
    if [[ "$(echo "$_existing" | jq -r '.enabled // false')" != "true" ]]; then
      ilm_curl PATCH "/v1/signingProfiles/${_sp_uuid}/enable" >/dev/null
    fi
    ok "reusing existing Signing Profile '${sp_name}'  $_sp_uuid (keeps its existing certificate; the cert issued this run is left unused)"
    printf -v "$out_sp_uuid" '%s' "$_sp_uuid"
    return 0
  fi

  if [[ -n "$time_quality_uuid" ]]; then
    qualified_timestamp="true"
  else
    qualified_timestamp="false"
  fi

  log "Fetching signing operation attributes for certificate ${cert_uuid}..."
  sig_attrs=$(ilm_curl GET \
    "/v1/signingProfiles/certificates/${cert_uuid}/signatureAttributes")
  sig_scheme_uuid=$(attr_uuid "$sig_attrs" "data_rsaSigScheme" "string")
  sig_digest_uuid=$(attr_uuid "$sig_attrs" "data_sigDigest"    "string")

  log "Fetching signature formatter connector attributes..."
  formatter_attrs=$(ilm_curl GET \
    "/v1/signingProfiles/signatureFormatterConnectors/${formatter_conn_uuid}/formatterAttributes" \
    | jq '[.[] | .version = ("v" + (.version | tostring))]')

  log "Creating Signing Profile '${sp_name}'..."
  _resp=$(ilm_curl POST /v1/signingProfiles -d \
    "$(jq -n \
      --arg  name                  "$sp_name" \
      --arg  policyOid             "$policy_oid" \
      --arg  certUuid              "$cert_uuid" \
      --arg  sigSchemeUuid         "$sig_scheme_uuid" \
      --arg  sigDigestUuid         "$sig_digest_uuid" \
      --argjson qualifiedTimestamp "$qualified_timestamp" \
      --arg  timeQualityUuid       "$time_quality_uuid" \
      --arg  formatterConnUuid     "$formatter_conn_uuid" \
      --argjson formatterAttrs     "$formatter_attrs" \
      '{
        name: $name,
        workflow: (
          {
            type: "timestamping",
            signatureFormatterConnectorUuid: $formatterConnUuid,
            signatureFormatterConnectorAttributes: $formatterAttrs,
            qualifiedTimestamp: $qualifiedTimestamp,
            defaultPolicyId: $policyOid,
            allowedPolicyIds: [],
            allowedDigestAlgorithms: []
          }
          | if $timeQualityUuid != "" then
              . + {timeQualityConfigurationUuid: $timeQualityUuid}
            else . end
        ),
        signingScheme: {
          signingScheme: "managed",
          managedSigningType: "static_key",
          certificateUuid: $certUuid,
          signingOperationAttributes: [
            {
              name: "data_rsaSigScheme",
              content: [{data: "PKCS1-v1_5", reference: "PKCS#1 v1.5"}],
              contentType: "string",
              uuid: $sigSchemeUuid,
              version: "v2"
            },
            {
              name: "data_sigDigest",
              content: [{data: "SHA-384", reference: "SHA-384"}],
              contentType: "string",
              uuid: $sigDigestUuid,
              version: "v2"
            }
          ]
        },
        customAttributes: []
      }')")
  _sp_uuid=$(require_uuid "$_resp" "Signing Profile '${sp_name}'")
  ok "Signing Profile  $_sp_uuid"

  log "Enabling Signing Profile..."
  ilm_curl PATCH "/v1/signingProfiles/${_sp_uuid}/enable" >/dev/null
  ok "Signing Profile enabled"

  printf -v "$out_sp_uuid" '%s' "$_sp_uuid"
}

# --- Step 16: Link Signing Profile ↔ TSP Profile (bidirectional) ---------------
# Usage: link_tsp_signing_profile <tsp_uuid> <tsp_name> <sp_uuid>
#
# Direction 1: TSP profile → Signing Profile (sets defaultSigningProfileUuid)
# Direction 2: Signing Profile → TSP profile (activates TSP protocol)
link_tsp_signing_profile() {
  local tsp_uuid="$1" tsp_name="$2" sp_uuid="$3"
  local _resp

  # PUT replaces the resource: re-send vaultProfileUuid and the auth methods or they would be stripped.
  log "Linking TSP profile '${tsp_name}' to Signing Profile (setting default)..."
  ilm_curl PUT "/v1/tspProfiles/${tsp_uuid}" -d \
    "$(jq -n \
      --arg name   "$tsp_name" \
      --arg spUuid "$sp_uuid" \
      --arg vaultProfileUuid "$VAULT_PROFILE_UUID" \
      '{name: $name,
        defaultSigningProfileUuid: $spUuid,
        vaultProfileUuid: $vaultProfileUuid,
        allowedAuthenticationMethods: ["clientCertificate", "basicPassword"],
        customAttributes: []}')" \
    >/dev/null
  ok "TSP profile default Signing Profile set"

  log "Activating TSP protocol on Signing Profile for TSP profile '${tsp_name}'..."
  _resp=$(ilm_curl PATCH "/v1/signingProfiles/${sp_uuid}/protocols/tsp/activate/${tsp_uuid}")
  ok "TSP protocol activated  signingUrl=$(echo "$_resp" | jq -r '.signingUrl // "(unknown)"')"
}

# --- Per-set orchestration ----------------------------------------------------
# setup_tsa_set <suffix> <ejbca_cert_profile> <policy_oid> <time_quality_uuid> <global_suffix>
#
# Idempotent. If the set's Signing Profile already exists the whole set is treated as already configured and reused
# WITHOUT issuing a new certificate: EJBCA binds a key to a single end-entity - reusing keys is rejected.
setup_tsa_set() {
  local suffix="$1" cert_profile="$2" policy_oid="$3" tq_uuid="$4" g="$5"
  local key_name="${KEY_NAME_BASE}-${suffix}"
  local ra_name="${RA_PROFILE_NAME_BASE}-${suffix}"
  local tsp_name="${TSP_PROFILE_NAME_BASE}-${suffix}"
  local sp_name="${SIGNING_PROFILE_NAME_BASE}-${suffix}"
  local key_uuid="" priv_uuid="" ra_uuid="" cert_uuid="" tsp_uuid="" sp_uuid=""
  local existing_sp _list sp_details

  log "=== Setting up TSA ${suffix} set ==="

  _list=$(list_paginated /v1/signingProfiles/list)
  existing_sp=$(find_named_item "$_list" "$sp_name")
  if [[ -n "$existing_sp" ]]; then
    sp_uuid=$(echo "$existing_sp" | jq -r '.uuid')
    ok "TSA ${suffix} set already configured (Signing Profile '${sp_name}'  $sp_uuid); reusing, no new certificate issued"
    _list=$(ilm_curl GET /v1/keys/pairs)
    key_uuid=$(uuid_of_named "$_list" "$key_name")
    _list=$(ilm_curl GET /v1/raProfiles)
    ra_uuid=$(uuid_of_named "$_list" "$ra_name")
    _list=$(list_paginated /v1/tspProfiles/list)
    tsp_uuid=$(uuid_of_named "$_list" "$tsp_name")
    # A reused set with no matching TSP profile is a half-configured state: grant_timestamping_permissions
    # would otherwise emit a tspProfiles grant keyed to an empty UUID, so the timestamp right is silently
    # never granted and only surfaces as an OPA rejection at request time. Fail fast instead.
    [[ -z "$tsp_uuid" ]] && die "Reused Signing Profile '${sp_name}' ($sp_uuid) has no matching TSP profile '${tsp_name}'; resolve the inconsistency (recreate or rename the TSP profile) and re-run"
    # The detail DTO nests the cert as signingScheme.certificate (CertificateSimpleDto), not certificateUuid.
    sp_details=$(ilm_curl GET "/v1/signingProfiles/${sp_uuid}")
    cert_uuid=$(echo "$sp_details" | jq -r '.signingScheme.certificate.uuid // empty')
    [[ -z "$cert_uuid" ]] && die "Reused Signing Profile '${sp_name}' ($sp_uuid) has no signing certificate; resolve the inconsistency and re-run"
    setup_tsp_basic_credential "$tsp_uuid"
  else
    setup_key_pair    "$key_name" key_uuid priv_uuid
    setup_ra_profile  "$ra_name" "$cert_profile" ra_uuid
    issue_certificate "${CERTIFICATE_DN}-${suffix}" "$key_uuid" "$priv_uuid" "$ra_uuid" cert_uuid
    poll_certificate  "$cert_uuid" "${CERTIFICATE_DN}-${suffix}"
    trust_certificate_chain "$cert_uuid"
    setup_tsp_profile "$tsp_name" tsp_uuid
    setup_signing_profile "$sp_name" "$cert_uuid" "$policy_oid" "$tq_uuid" "$FORMATTER_CONN_UUID" sp_uuid
    link_tsp_signing_profile "$tsp_uuid" "$tsp_name" "$sp_uuid"
    setup_tsp_basic_credential "$tsp_uuid"
  fi

  printf -v "KEY_UUID_${g}"             '%s' "$key_uuid"
  printf -v "RA_PROFILE_UUID_${g}"      '%s' "$ra_uuid"
  printf -v "ISSUED_CERT_UUID_${g}"     '%s' "$cert_uuid"
  printf -v "TSP_PROFILE_UUID_${g}"     '%s' "$tsp_uuid"
  printf -v "SIGNING_PROFILE_UUID_${g}" '%s' "$sp_uuid"
}

# --- Summary ------------------------------------------------------------------
print_summary() {
  local nq_key_name="${KEY_NAME_BASE}-non-qualified"
  local q_key_name="${KEY_NAME_BASE}-qualified"
  local nq_ra_name="${RA_PROFILE_NAME_BASE}-non-qualified"
  local q_ra_name="${RA_PROFILE_NAME_BASE}-qualified"
  local nq_tsp_name="${TSP_PROFILE_NAME_BASE}-non-qualified"
  local q_tsp_name="${TSP_PROFILE_NAME_BASE}-qualified"
  local nq_sp_name="${SIGNING_PROFILE_NAME_BASE}-non-qualified"
  local q_sp_name="${SIGNING_PROFILE_NAME_BASE}-qualified"

  cat <<EOF

Setup complete. Created resources:

  Shared infrastructure:
    connector       common-credential-provider      $CRED_CONN_UUID
    connector       ejbca-ng-connector              $EJBCA_CONN_UUID
    connector       software-cryptography-provider  $CRYPTO_CONN_UUID
    connector       $FORMATTER_CONNECTOR_NAME       $FORMATTER_CONN_UUID
    connector       $VAULT_CONNECTOR_NAME           $VAULT_CONN_UUID
    credential      $CREDENTIAL_NAME                $CRED_UUID
    authority       $AUTHORITY_NAME                 $AUTH_UUID
    token           $TOKEN_NAME                     $TOKEN_UUID
    token-profile   $TOKEN_PROFILE_NAME             $TOKEN_PROFILE_UUID
    vault-instance  $VAULT_INSTANCE_NAME            $VAULT_INSTANCE_UUID
    vault-profile   $VAULT_PROFILE_NAME             $VAULT_PROFILE_UUID
    mapped-user     $MAPPED_USER_USERNAME          $MAPPED_USER_UUID
    role            $MAPPED_USER_ROLE_NAME         $MAPPED_USER_ROLE_UUID  (object-scoped: tspProfiles, signingProfiles, keys, tokens, tokenProfiles)

  TSA non-qualified set:
    key             $nq_key_name    $KEY_UUID_NQ
    ra-profile      $nq_ra_name     $RA_PROFILE_UUID_NQ
    certificate     CN=${CERTIFICATE_DN}-non-qualified   $ISSUED_CERT_UUID_NQ
    tsp-profile     $nq_tsp_name    $TSP_PROFILE_UUID_NQ
    signing-profile $nq_sp_name     $SIGNING_PROFILE_UUID_NQ
    basic-cred      $TSP_CREDENTIAL_USERNAME (mapped user $MAPPED_USER_USERNAME)

  TSA qualified set:
    time-quality    $TIME_QUALITY_CONFIG_NAME       $TIME_QUALITY_UUID
    key             $q_key_name     $KEY_UUID_Q
    ra-profile      $q_ra_name      $RA_PROFILE_UUID_Q
    certificate     CN=${CERTIFICATE_DN}-qualified   $ISSUED_CERT_UUID_Q
    tsp-profile     $q_tsp_name     $TSP_PROFILE_UUID_Q
    signing-profile $q_sp_name      $SIGNING_PROFILE_UUID_Q
    basic-cred      $TSP_CREDENTIAL_USERNAME (mapped user $MAPPED_USER_USERNAME)
EOF
}

# --- Main ---------------------------------------------------------------------
main() {
  parse_args "$@"
  validate
  setup_connectors
  setup_credential
  setup_authority
  setup_token
  setup_token_profile
  setup_time_quality_config
  setup_vault_instance
  setup_vault_profile
  setup_mapped_user
  setup_timestamping_role

  setup_tsa_set "non-qualified" "$EJBCA_CERT_PROFILE"           "$POLICY_ID_NON_QUALIFIED" ""                   NQ
  setup_tsa_set "qualified"     "$EJBCA_CERT_PROFILE_QUALIFIED" "$POLICY_ID_QUALIFIED"     "$TIME_QUALITY_UUID" Q

  grant_timestamping_permissions

  print_summary
}

main "$@"

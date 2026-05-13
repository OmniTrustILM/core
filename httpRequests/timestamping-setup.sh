#!/usr/bin/env bash
# timestamping-setup.sh
#
# Automates the ILM timestamping environment setup:
#   1. Creates four connectors (credential-provider, EJBCA, crypto-provider, signature-formatter)
#   2. Creates a SoftKeyStore credential from a PKCS12 bundle
#   3. Creates an EJBCA authority instance
#   4. Creates a soft token
#   5. Creates a token profile
#   6. Creates a Time Quality configuration (used by the qualified signing profile)
#   For each of two sets (non-qualified / qualified):
#       7. Creates an RSA 2048 key pair
#       8. Creates an RA profile (resolving EJBCA profile IDs dynamically)
#       9. Issues a TSA certificate with the requested DN suffix
#      10. Polls for certificate issuance completion
#      11. Trusts the certificate chain (marks root CA as trusted, triggers validation)
#      12. Creates and enables a TSP profile
#      13. Creates and enables a Signing Profile
#          (qualified profile links to the Time Quality configuration)
#      14. Links the Signing Profile to the TSP Profile bidirectionally
#
# Requires: curl, jq, base64

set -euo pipefail

# --- Defaults -----------------------------------------------------------------
ILM_HOST="http://localhost:8080"
CLIENT_CERT_PEM=""

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

# Policy OIDs (hardcoded; can be overridden via CLI)
POLICY_ID_NON_QUALIFIED="1.2.3.4.5.6"
POLICY_ID_QUALIFIED="1.2.3.4.5.7"

# Time Quality configuration (used by the qualified signing profile)
TIME_QUALITY_CONFIG_NAME="time-quality"
TIME_QUALITY_NTP_SERVERS="localhost"       # comma-separated list, e.g. "pool.ntp.org,time.cloudflare.com"
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
CRED_CONN_UUID=""
EJBCA_CONN_UUID=""
CRYPTO_CONN_UUID=""
FORMATTER_CONN_UUID=""
CRED_UUID=""
AUTH_UUID=""
TOKEN_UUID=""
TOKEN_PROFILE_UUID=""

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
  --client-cert-pem FILE      ILM admin client certificate PEM
  --pkcs12-bundle FILE        Path to PKCS12 bundle with EJBCA client credentials
  --certificate-dn PREFIX     DN prefix for TSA certificates.
                              Actual CNs will be <PREFIX>-non-qualified and <PREFIX>-qualified.

Connector options (defaults: localhost, ports 8200/8210/8230/8270):
  --connector-host HOST       Hostname for connectors as seen from ILM server
  --port-cred-provider PORT   common-credential-provider port     (default: 8200)
  --port-ejbca PORT           ejbca-ng-connector port             (default: 8210)
  --port-crypto-provider PORT software-cryptography-provider port (default: 8230)
  --port-formatter PORT       signature-formatter-connector port  (default: 8270)
  --formatter-connector-name NAME
                              Signature Formatter Connector name  (default: signature-formatter)

Credential/token options:
  --pkcs12-password PASS      PKCS12 bundle password     (default: 00000000)
  --token-password PASS       Soft token PIN             (default: same as pkcs12-password)

ILM API auth:
  --ilm-host HOST             URL of ILM API                (default: http://localhost:8080)
  --client-cert-pem FILE      Admin client certificate PEM  (required)

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
  --time-quality-ntp-servers SERVERS          Comma-separated NTP server list (default: localhost)
  --time-quality-accuracy DURATION            ISO-8601 duration (default: PT1S)
  --time-quality-ntp-check-interval DURATION  ISO-8601 duration (default: PT10S)
  --time-quality-ntp-check-timeout DURATION   ISO-8601 duration (default: PT5S)
  --time-quality-ntp-samples-per-server N     (default: 4)
  --time-quality-ntp-servers-min-reachable N  (default: 1)
  --time-quality-max-clock-drift DURATION     ISO-8601 duration (default: PT1S)
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
  local tmp http_code response
  tmp=$(mktemp)
  http_code=$(curl -s -o "$tmp" -w "%{http_code}" -X "$method" \
    -H "ssl-client-cert: ${CLIENT_CERT_HEADER_VAL}" \
    -H "content-type: application/json" \
    "${ILM_HOST}/api${path}" \
    "$@")
  response=$(<"$tmp"); rm -f "$tmp"
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
      --ilm-host)                               ILM_HOST="$2";                               shift 2 ;;
      --client-cert-pem)                        CLIENT_CERT_PEM="$2";                        shift 2 ;;
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
  [[ -z "$CLIENT_CERT_PEM" ]]  && { echo "ERROR: --client-cert-pem is required";  errors=$((errors+1)); }
  [[ $errors -gt 0 ]] && usage

  [[ ! -f "$PKCS12_BUNDLE" ]]   && { echo "ERROR: PKCS12 bundle not found: $PKCS12_BUNDLE"; exit 1; }
  [[ ! -f "$CLIENT_CERT_PEM" ]] && { echo "ERROR: Client cert PEM not found: $CLIENT_CERT_PEM"; exit 1; }

  command -v jq     &>/dev/null || { echo "ERROR: jq is required but not installed";     exit 1; }
  command -v curl   &>/dev/null || { echo "ERROR: curl is required but not installed";   exit 1; }
  command -v base64 &>/dev/null || { echo "ERROR: base64 is required but not installed"; exit 1; }

  [[ -z "$TOKEN_PASSWORD" ]] && TOKEN_PASSWORD="$PKCS12_PASSWORD"

  # Build the ssl-client-cert header value: extract only the base64 body between
  # BEGIN/END CERTIFICATE markers (ignoring any human-readable dump before them),
  # then URL-encode the result (only +, / and = require encoding).
  local _cert_b64
  _cert_b64=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$CLIENT_CERT_PEM" \
    | grep -v "^-----" | tr -d '\n\r')
  CLIENT_CERT_HEADER_VAL=$(printf '%s' "$_cert_b64" | sed 's/+/%2B/g; s|/|%2F|g; s/=/%3D/g')
}

# --- Step 1: Connectors -------------------------------------------------------
setup_connectors() {
  local _resp

  log "Creating credential-provider connector (port ${PORT_CRED_PROVIDER})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"common-credential-provider\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_CRED_PROVIDER}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v1\"}")
  CRED_CONN_UUID=$(require_uuid "$_resp" "common-credential-provider connector")
  ok "common-credential-provider  $CRED_CONN_UUID"

  log "Creating ejbca-ng connector (port ${PORT_EJBCA})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"ejbca-ng-connector\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_EJBCA}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v1\"}")
  EJBCA_CONN_UUID=$(require_uuid "$_resp" "ejbca-ng-connector connector")
  ok "ejbca-ng-connector           $EJBCA_CONN_UUID"

  log "Creating software-cryptography-provider connector (port ${PORT_CRYPTO_PROVIDER})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"software-cryptography-provider\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_CRYPTO_PROVIDER}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v1\"}")
  CRYPTO_CONN_UUID=$(require_uuid "$_resp" "software-cryptography-provider connector")
  ok "software-cryptography-provider  $CRYPTO_CONN_UUID"

  log "Creating signature-formatter connector (port ${PORT_FORMATTER})..."
  _resp=$(ilm_curl POST /v2/connectors -d \
    "{\"name\":\"${FORMATTER_CONNECTOR_NAME}\",\"url\":\"http://${CONNECTOR_HOST}:${PORT_FORMATTER}\",\"authType\":\"none\",\"customAttributes\":[],\"version\":\"v2\"}")
  FORMATTER_CONN_UUID=$(require_uuid "$_resp" "signature-formatter connector")
  ok "signature-formatter  $FORMATTER_CONN_UUID"
}

# --- Step 2: Credential -------------------------------------------------------
setup_credential() {
  local _resp cred_attr_defs ks_type_uuid ks_pass_uuid ks_file_uuid pkcs12_b64 pkcs12_filename

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
  local _resp auth_attr_defs auth_url_uuid auth_cred_uuid

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
  local _resp token_attr_defs tok_action_uuid tok_name_uuid tok_code_uuid

  log "Fetching SOFT token attribute definitions..."
  token_attr_defs=$(ilm_curl GET \
    "/v1/connectors/${CRYPTO_CONN_UUID}/attributes/cryptographyProvider/SOFT")
  tok_action_uuid=$(attr_uuid "$token_attr_defs" "data_createTokenAction" "string")
  tok_name_uuid=$(attr_uuid   "$token_attr_defs" "data_newTokenName"      "string")
  tok_code_uuid=$(attr_uuid   "$token_attr_defs" "data_tokenCode"         "secret")

  log "Creating soft token '${TOKEN_NAME}'..."
  _resp=$(ilm_curl POST /v1/tokens -d \
    "$(jq -n \
      --arg name          "$TOKEN_NAME" \
      --arg connUuid      "$CRYPTO_CONN_UUID" \
      --arg pin           "$TOKEN_PASSWORD" \
      --arg tokActionUuid "$tok_action_uuid" \
      --arg tokNameUuid   "$tok_name_uuid" \
      --arg tokCodeUuid   "$tok_code_uuid" \
      '{
        name: $name,
        connectorUuid: $connUuid,
        kind: "SOFT",
        attributes: [
          {
            name: "data_createTokenAction",
            content: [{data: "new"}],
            contentType: "string",
            uuid: $tokActionUuid,
            version: "v2"
          },
          {
            name: "data_newTokenName",
            content: [{data: $name}],
            contentType: "string",
            uuid: $tokNameUuid,
            version: "v2"
          },
          {
            name: "data_tokenCode",
            content: [{data: {secret: $pin}}],
            contentType: "secret",
            uuid: $tokCodeUuid,
            version: "v2"
          }
        ],
        customAttributes: []
      }')")
  TOKEN_UUID=$(require_uuid "$_resp" "soft token '${TOKEN_NAME}'")
  ok "token  $TOKEN_UUID"
}

# --- Step 5: Token profile ----------------------------------------------------
setup_token_profile() {
  local _resp

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
  local _resp ntp_servers_json

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

# --- Step 7: Key pair ---------------------------------------------------------
# Usage: setup_key_pair <key_name> <out_key_uuid_var> <out_priv_item_uuid_var>
setup_key_pair() {
  local key_name="$1" out_key_uuid="$2" out_priv_item_uuid="$3"
  local _resp keypair_attr_defs key_alias_uuid key_alg_uuid key_spec_group_uuid
  local key_spec_attrs rsa_key_size_uuid key_details _key_uuid _priv_uuid

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

# --- Step 8: RA profile (with dynamic EJBCA profile lookup) -------------------
# Usage: setup_ra_profile <ra_name> <cert_profile_name> <out_ra_profile_uuid_var>
setup_ra_profile() {
  local ra_name="$1" ejbca_cert_profile="$2" out_ra_uuid="$3"
  local _resp ra_attrs ee_profile_attr_uuid cert_profile_attr_uuid ca_attr_uuid
  local send_notif_attr_uuid key_recover_attr_uuid username_gen_attr_uuid
  local ejbca_authority_id ee_profile_id cert_profiles cert_profile_id ca_list ejbca_ca_id
  local _ra_uuid

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

# --- Step 9: Issue TSA certificate --------------------------------------------
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

# --- Step 10: Poll for certificate issuance result ----------------------------
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


# --- Trust the certificate chain ----------------------------------------------
# Usage: trust_certificate_chain <cert_uuid>
#
# Walks issuerCertificateUuid upward from <cert_uuid> and marks the root CA as
# trustedCa=true. Then waits for the certificate to be re-validated as VALID.
# Required before creating a signing profile: CZERTAINLY rejects certificates
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

# --- Step 11: TSP profile -----------------------------------------------------
# Usage: setup_tsp_profile <name> <out_tsp_uuid_var>
setup_tsp_profile() {
  local tsp_name="$1" out_tsp_uuid="$2"
  local _resp _tsp_uuid

  log "Creating TSP profile '${tsp_name}'..."
  _resp=$(ilm_curl POST /v1/tspProfiles -d \
    "$(jq -n --arg name "$tsp_name" '{name: $name, customAttributes: []}')")
  _tsp_uuid=$(require_uuid "$_resp" "TSP profile '${tsp_name}'")
  ok "TSP profile  $_tsp_uuid"

  log "Enabling TSP profile..."
  ilm_curl PATCH "/v1/tspProfiles/${_tsp_uuid}/enable" >/dev/null
  ok "TSP profile enabled"

  printf -v "$out_tsp_uuid" '%s' "$_tsp_uuid"
}

# --- Step 12: Signing Profile -------------------------------------------------
# Usage: setup_signing_profile <sp_name> <cert_uuid> <policy_oid> <time_quality_uuid> <formatter_conn_uuid> <out_sp_uuid_var>
#
# Pass a non-empty <time_quality_uuid> for the qualified profile to enable
# qualifiedTimestamp and link to the Time Quality configuration.
# Pass an empty string for the non-qualified profile.
setup_signing_profile() {
  local sp_name="$1" cert_uuid="$2" policy_oid="$3" time_quality_uuid="$4" formatter_conn_uuid="$5" out_sp_uuid="$6"
  local _resp sig_attrs sig_scheme_uuid sig_digest_uuid _sp_uuid formatter_attrs
  local qualified_timestamp

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

# --- Step 13: Link Signing Profile ↔ TSP Profile (bidirectional) ---------------
# Usage: link_tsp_signing_profile <tsp_uuid> <tsp_name> <sp_uuid>
#
# Direction 1: TSP profile → Signing Profile (sets defaultSigningProfileUuid)
# Direction 2: Signing Profile → TSP profile (activates TSP protocol)
link_tsp_signing_profile() {
  local tsp_uuid="$1" tsp_name="$2" sp_uuid="$3"
  local _resp

  log "Linking TSP profile '${tsp_name}' to Signing Profile (setting default)..."
  ilm_curl PUT "/v1/tspProfiles/${tsp_uuid}" -d \
    "$(jq -n \
      --arg name   "$tsp_name" \
      --arg spUuid "$sp_uuid" \
      '{name: $name, defaultSigningProfileUuid: $spUuid, customAttributes: []}')" \
    >/dev/null
  ok "TSP profile default Signing Profile set"

  log "Activating TSP protocol on Signing Profile for TSP profile '${tsp_name}'..."
  _resp=$(ilm_curl PATCH "/v1/signingProfiles/${sp_uuid}/protocols/tsp/activate/${tsp_uuid}")
  ok "TSP protocol activated  signingUrl=$(echo "$_resp" | jq -r '.signingUrl // "(unknown)"')"
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
    credential      $CREDENTIAL_NAME                $CRED_UUID
    authority       $AUTHORITY_NAME                 $AUTH_UUID
    token           $TOKEN_NAME                     $TOKEN_UUID
    token-profile   $TOKEN_PROFILE_NAME             $TOKEN_PROFILE_UUID

  TSA non-qualified set:
    key             $nq_key_name    $KEY_UUID_NQ
    ra-profile      $nq_ra_name     $RA_PROFILE_UUID_NQ
    certificate     CN=${CERTIFICATE_DN}-non-qualified   $ISSUED_CERT_UUID_NQ
    tsp-profile     $nq_tsp_name    $TSP_PROFILE_UUID_NQ
    signing-profile $nq_sp_name     $SIGNING_PROFILE_UUID_NQ

  TSA qualified set:
    time-quality    $TIME_QUALITY_CONFIG_NAME       $TIME_QUALITY_UUID
    key             $q_key_name     $KEY_UUID_Q
    ra-profile      $q_ra_name      $RA_PROFILE_UUID_Q
    certificate     CN=${CERTIFICATE_DN}-qualified   $ISSUED_CERT_UUID_Q
    tsp-profile     $q_tsp_name     $TSP_PROFILE_UUID_Q
    signing-profile $q_sp_name      $SIGNING_PROFILE_UUID_Q
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

  # ----- Non-qualified set -----
  log "=== Setting up TSA non-qualified set ==="
  setup_key_pair \
    "${KEY_NAME_BASE}-non-qualified" \
    KEY_UUID_NQ PRIVATE_KEY_ITEM_UUID_NQ
  setup_ra_profile \
    "${RA_PROFILE_NAME_BASE}-non-qualified" \
    "$EJBCA_CERT_PROFILE" \
    RA_PROFILE_UUID_NQ
  issue_certificate \
    "${CERTIFICATE_DN}-non-qualified" \
    "$KEY_UUID_NQ" "$PRIVATE_KEY_ITEM_UUID_NQ" "$RA_PROFILE_UUID_NQ" \
    ISSUED_CERT_UUID_NQ
  poll_certificate "$ISSUED_CERT_UUID_NQ" "${CERTIFICATE_DN}-non-qualified"
  trust_certificate_chain "$ISSUED_CERT_UUID_NQ"
  setup_tsp_profile \
    "${TSP_PROFILE_NAME_BASE}-non-qualified" \
    TSP_PROFILE_UUID_NQ
  setup_signing_profile \
    "${SIGNING_PROFILE_NAME_BASE}-non-qualified" \
    "$ISSUED_CERT_UUID_NQ" "$POLICY_ID_NON_QUALIFIED" \
    "" \
    "$FORMATTER_CONN_UUID" \
    SIGNING_PROFILE_UUID_NQ
  link_tsp_signing_profile \
    "$TSP_PROFILE_UUID_NQ" "${TSP_PROFILE_NAME_BASE}-non-qualified" \
    "$SIGNING_PROFILE_UUID_NQ"

  # ----- Qualified set -----
  log "=== Setting up TSA qualified set ==="
  setup_key_pair \
    "${KEY_NAME_BASE}-qualified" \
    KEY_UUID_Q PRIVATE_KEY_ITEM_UUID_Q
  setup_ra_profile \
    "${RA_PROFILE_NAME_BASE}-qualified" \
    "$EJBCA_CERT_PROFILE_QUALIFIED" \
    RA_PROFILE_UUID_Q
  issue_certificate \
    "${CERTIFICATE_DN}-qualified" \
    "$KEY_UUID_Q" "$PRIVATE_KEY_ITEM_UUID_Q" "$RA_PROFILE_UUID_Q" \
    ISSUED_CERT_UUID_Q
  poll_certificate "$ISSUED_CERT_UUID_Q" "${CERTIFICATE_DN}-qualified"
  trust_certificate_chain "$ISSUED_CERT_UUID_Q"
  setup_tsp_profile \
    "${TSP_PROFILE_NAME_BASE}-qualified" \
    TSP_PROFILE_UUID_Q
  setup_signing_profile \
    "${SIGNING_PROFILE_NAME_BASE}-qualified" \
    "$ISSUED_CERT_UUID_Q" "$POLICY_ID_QUALIFIED" \
    "$TIME_QUALITY_UUID" \
    "$FORMATTER_CONN_UUID" \
    SIGNING_PROFILE_UUID_Q
  link_tsp_signing_profile \
    "$TSP_PROFILE_UUID_Q" "${TSP_PROFILE_NAME_BASE}-qualified" \
    "$SIGNING_PROFILE_UUID_Q"

  print_summary
}

main "$@"

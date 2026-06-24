#!/usr/bin/env python3
"""ASN.1 structure viewer for DER/PEM encoded files (timestamp responses, CMS tokens, etc.).

Displays human-readable indented tree with named fields for known structures
(RFC 3161 TimeStampResp, RFC 5652 CMS SignedData, TSTInfo, X.509, etc.).
"""

import sys
import base64
import re

# Tree drawing characters
PIPE   = "│   "
TEE    = "├── "
ELBOW  = "└── "
BLANK  = "    "


# --- OID database ---

_OID_NAMES = {
    "1.2.840.113549.1.7.1": "id-data",
    "1.2.840.113549.1.7.2": "id-signedData",
    "1.2.840.113549.1.9.3": "id-contentType",
    "1.2.840.113549.1.9.4": "id-messageDigest",
    "1.2.840.113549.1.9.5": "id-signingTime",
    "1.2.840.113549.1.9.52": "id-aa-CMSAlgorithmProtection",
    "1.2.840.113549.1.9.16.1.4": "id-ct-TSTInfo",
    "1.2.840.113549.1.9.16.2.12": "id-smime-aa-signingCertificate",
    "1.2.840.113549.1.9.16.2.47": "id-smime-aa-signingCertificateV2",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.8": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "2.16.840.1.101.3.4.2.1": "sha-256",
    "2.16.840.1.101.3.4.2.2": "sha-384",
    "2.16.840.1.101.3.4.2.3": "sha-512",
    "1.3.6.1.5.5.7.1.1": "id-pe-authorityInfoAccess",
    "1.3.6.1.5.5.7.48.1": "id-ad-ocsp",
    "1.3.6.1.5.5.7.48.2": "id-ad-caIssuers",
    "2.5.4.3": "id-at-commonName",
    "2.5.4.5": "id-at-serialNumber",
    "2.5.4.6": "id-at-countryName",
    "2.5.4.7": "id-at-localityName",
    "2.5.4.8": "id-at-stateOrProvinceName",
    "2.5.4.10": "id-at-organizationName",
    "2.5.4.11": "id-at-organizationalUnitName",
    "2.5.4.13": "id-at-description",
    "2.5.29.14": "id-ce-subjectKeyIdentifier",
    "2.5.29.15": "id-ce-keyUsage",
    "2.5.29.17": "id-ce-subjectAltName",
    "2.5.29.19": "id-ce-basicConstraints",
    "2.5.29.31": "id-ce-cRLDistributionPoints",
    "2.5.29.32": "id-ce-certificatePolicies",
    "2.5.29.35": "id-ce-authorityKeyIdentifier",
    "2.5.29.37": "id-ce-extKeyUsage",
    "1.3.6.1.5.5.7.3.8": "id-kp-timeStamping",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.113549.1.9.1": "id-emailAddress",
    "1.2.840.113549.1.1.9": "id-mgf1",
}

_ATTR_NAMES = {
    "1.2.840.113549.1.9.3": "Content Type",
    "1.2.840.113549.1.9.4": "Message Digest",
    "1.2.840.113549.1.9.5": "Signing Time",
    "1.2.840.113549.1.9.52": "CMS Algorithm Protection",
    "1.2.840.113549.1.9.16.2.12": "Signing Certificate",
    "1.2.840.113549.1.9.16.2.47": "Signing Certificate V2",
}

_PKI_STATUS = {
    0: "granted", 1: "grantedWithMods", 2: "rejection",
    3: "waiting", 4: "revocationWarning", 5: "revocationNotification",
}

_PKI_FAILURE_BITS = {
    0: "badAlg", 2: "badRequest", 5: "badDataFormat",
    14: "timeNotAvailable", 15: "unacceptedPolicy",
    16: "unacceptedExtension", 17: "addInfoNotAvailable",
    25: "systemFailure",
}

_X509_ATTR_SHORT = {
    "2.5.4.3": "CN", "2.5.4.5": "SERIALNUMBER", "2.5.4.6": "C",
    "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.13": "DESC",
    "1.2.840.113549.1.9.1": "E",
}


# --- ASN.1 tag constants ---

UNIVERSAL_TAGS = {
    1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING",
    5: "NULL", 6: "OID", 10: "ENUMERATED", 12: "UTF8String",
    13: "RELATIVE OID", 16: "SEQUENCE", 17: "SET", 19: "PrintableString",
    22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime", 28: "BMPString",
    30: "VisibleString",
}


# --- Node tree ---

class Node:
    __slots__ = ("tag_class", "constructed", "tag_number", "value", "children",
                 "data", "val_offset", "val_length")

    def __init__(self, tag_class, constructed, tag_number, value, children,
                 data=None, val_offset=0, val_length=0):
        self.tag_class = tag_class
        self.constructed = constructed
        self.tag_number = tag_number
        self.value = value
        self.children = children
        self.data = data
        self.val_offset = val_offset
        self.val_length = val_length

    @property
    def is_universal(self):
        return self.tag_class == 0

    @property
    def is_context(self):
        return self.tag_class == 2


# --- DER parsing ---

def detect_and_load(data: bytes) -> bytes:
    try:
        text = data.decode("ascii", errors="strict").strip()
        m = re.search(r"-----BEGIN [^-]+-----\s*(.+?)\s*-----END", text, re.DOTALL)
        if m:
            return base64.b64decode(re.sub(r"\s+", "", m.group(1)))
    except Exception:
        pass
    return data


def _parse_tag_length(data, offset):
    if offset >= len(data):
        return None
    b = data[offset]
    tag_class = (b >> 6) & 3
    constructed = bool(b & 0x20)
    tag_number = b & 0x1F
    offset += 1
    if tag_number == 0x1F:
        tag_number = 0
        while offset < len(data):
            b = data[offset]; offset += 1
            tag_number = (tag_number << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    if offset >= len(data):
        return None
    b = data[offset]; offset += 1
    if b == 0x80:
        return (tag_class, constructed, tag_number, offset, -1)
    elif b & 0x80:
        n = b & 0x7F
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        length = b
    return (tag_class, constructed, tag_number, offset, length)


def _looks_constructed(data):
    if len(data) < 2:
        return False
    try:
        pos = 0
        count = 0
        while pos < len(data):
            r = _parse_tag_length(data, pos)
            if r is None:
                return False
            _, _, _, vo, vl = r
            if vl < 0 or vo + vl > len(data):
                return False
            pos = vo + vl
            count += 1
        return pos == len(data) and count >= 1
    except Exception:
        return False


def parse_der(data, offset=0, end=None):
    if end is None:
        end = len(data)
    nodes = []
    while offset < end:
        r = _parse_tag_length(data, offset)
        if r is None:
            break
        tc, con, tn, vo, vl = r
        if vl < 0:
            break
        ve = vo + vl
        value_bytes = data[vo:ve]
        if con:
            children = parse_der(data, vo, ve)
            nodes.append(Node(tc, True, tn, None, children, data, vo, vl))
        elif tc != 0 and _looks_constructed(value_bytes):
            children = parse_der(data, vo, ve)
            nodes.append(Node(tc, True, tn, None, children, data, vo, vl))
        else:
            nodes.append(Node(tc, False, tn, value_bytes, [], data, vo, vl))
        offset = ve
    return nodes


# --- OID decoding ---

def decode_oid(value_bytes):
    if not value_bytes:
        return ""
    components = [value_bytes[0] // 40, value_bytes[0] % 40]
    val = 0
    for b in value_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            components.append(val)
            val = 0
    return ".".join(str(c) for c in components)


def oid_name(dotted):
    return _OID_NAMES.get(dotted, "")


# --- Value formatting ---

def format_value(node):
    tn = node.tag_number if node.is_universal else 4
    v = node.value or b""
    if tn == 1:
        return "TRUE" if v and v[0] else "FALSE"
    if tn == 2:
        n = int.from_bytes(v, "big", signed=True) if v else 0
        if len(v) <= 8:
            return str(n)
        return f"({len(v)} bytes) {v[:16].hex()}{'...' if len(v) > 16 else ''}"
    if tn == 5:
        return ""
    if tn == 6:
        dotted = decode_oid(v)
        name = oid_name(dotted)
        return f"{dotted} ({name})" if name else dotted
    if tn == 10:
        return str(int.from_bytes(v, "big", signed=True) if v else 0)
    if tn in (12, 19, 22, 28, 30):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex()
    if tn in (23, 24):
        try:
            return v.decode("ascii")
        except UnicodeDecodeError:
            return v.hex()
    max_hex = 32
    h = v.hex()
    if len(h) > max_hex * 2:
        return f"({len(v)} bytes) {h[:max_hex * 2]}..."
    return f"({len(v)} bytes) {h}" if v else ""


def format_value_raw(tag_number, value):
    max_hex = 32
    h = value.hex()
    if len(h) > max_hex * 2:
        return f"({len(value)} bytes) {h[:max_hex * 2]}..."
    return f"({len(value)} bytes) {h}" if value else ""


def get_first_oid(node):
    for c in node.children:
        if c.is_universal and c.tag_number == 6 and c.value:
            return decode_oid(c.value)
    return None


def _extract_oid_value(node):
    """Extract dotted OID string from an OID node."""
    if node.is_universal and node.tag_number == 6 and node.value:
        return decode_oid(node.value)
    return None


# --- Structure schemas ---

def _uni(tn):
    return lambda n: n.is_universal and n.tag_number == tn

def _ctx(tn):
    return lambda n: n.is_context and n.tag_number == tn

def _any():
    return lambda n: True


SCHEMAS = {
    "TimeStampResp": [
        ("status", _uni(16), "PKIStatusInfo", False),
        ("timeStampToken", _uni(16), "ContentInfo", True),
    ],
    "PKIStatusInfo": [
        ("status", _uni(2), "_PKIStatus", False),
        ("statusString", _uni(16), None, True),
        ("failInfo", _uni(3), "_PKIFailInfo", True),
    ],
    "ContentInfo": [
        ("contentType", _uni(6), None, False),
        ("content", _ctx(0), "_ContentInfo_dispatch", False),
    ],
    "SignedData": [
        ("version", _uni(2), None, False),
        ("digestAlgorithms", _uni(17), "_AlgIdSet", False),
        ("encapContentInfo", _uni(16), "EncapsulatedContentInfo", False),
        ("certificates", _ctx(0), "_CertificateSet", True),
        ("crls", _ctx(1), None, True),
        ("signerInfos", _uni(17), "_SignerInfoSet", False),
    ],
    "EncapsulatedContentInfo": [
        ("eContentType", _uni(6), None, False),
        ("eContent", _ctx(0), "_EContent_dispatch", True),
    ],
    "TSTInfo": [
        ("version", _uni(2), None, False),
        ("policy", _uni(6), None, False),
        ("messageImprint", _uni(16), "MessageImprint", False),
        ("serialNumber", _uni(2), None, False),
        ("genTime", _uni(24), None, False),
        ("accuracy", _uni(16), "Accuracy", True),
        ("ordering", _uni(1), None, True),
        ("nonce", _uni(2), None, True),
        ("tsa", _ctx(0), "_GeneralName", True),
        ("extensions", _ctx(1), "_Extensions", True),
    ],
    "MessageImprint": [
        ("hashAlgorithm", _uni(16), "AlgorithmIdentifier", False),
        ("hashedMessage", _uni(4), None, False),
    ],
    "AlgorithmIdentifier": [
        ("algorithm", _uni(6), None, False),
        ("parameters", _any(), "_AlgParams_dispatch", True),
    ],
    "Accuracy": [
        ("seconds", _uni(2), None, True),
        ("millis", _ctx(0), None, True),
        ("micros", _ctx(1), None, True),
    ],
    "SignerInfo": [
        ("version", _uni(2), None, False),
        ("sid", _uni(16), "_IssuerAndSerialNumber", False),
        ("digestAlgorithm", _uni(16), "AlgorithmIdentifier", False),
        ("signedAttrs", _ctx(0), "_SignedAttrs", True),
        ("signatureAlgorithm", _uni(16), "AlgorithmIdentifier", False),
        ("signature", _uni(4), None, False),
        ("unsignedAttrs", _ctx(1), "_UnsignedAttrs", True),
    ],
    "IssuerAndSerialNumber": [
        ("issuer", _uni(16), "_DistinguishedName", False),
        ("serialNumber", _uni(2), None, False),
    ],
    "SubjectPublicKeyInfo": [
        ("algorithm", _uni(16), "AlgorithmIdentifier", False),
        ("subjectPublicKey", _uni(3), None, False),
    ],
    "RsaPssParams": [
        ("hashAlgorithm", _ctx(0), "_AlgIdUnwrap", True),
        ("maskGenAlgorithm", _ctx(1), "_AlgIdUnwrap", True),
        ("saltLength", _ctx(2), None, True),
        ("trailerField", _ctx(3), None, True),
    ],
    "CMSAlgorithmProtection": [
        ("digestAlgorithm", _uni(16), "AlgorithmIdentifier", False),
        ("signatureAlgorithm", _ctx(1), "_AlgIdUnwrap", True),
        ("macAlgorithm", _ctx(2), "_AlgIdUnwrap", True),
    ],
    "SigningCertificateV2": [
        ("certs", _uni(16), "_ESSCertIDv2List", False),
    ],
    "ESSCertIDv2": [
        ("hashAlgorithm", _uni(16), "AlgorithmIdentifier", True),
        ("certHash", _uni(4), None, False),
        ("issuerSerial", _uni(16), "_IssuerSerial", True),
    ],
    "IssuerSerial": [
        ("issuer", _uni(16), "_GeneralNames", False),
        ("serialNumber", _uni(2), None, False),
    ],
}


# --- Structure detection ---

def detect_structure(nodes):
    if len(nodes) != 1:
        return None
    root = nodes[0]
    if not (root.is_universal and root.tag_number == 16 and root.children):
        return None
    children = root.children
    if (len(children) == 2
            and children[0].is_universal and children[0].tag_number == 6
            and children[1].is_context and children[1].tag_number == 0):
        return "ContentInfo"
    if children and children[0].is_universal and children[0].tag_number == 16:
        inner = children[0].children
        if inner and inner[0].is_universal and inner[0].tag_number == 2:
            val = int.from_bytes(inner[0].value, "big", signed=True) if inner[0].value else -1
            if 0 <= val <= 5:
                return "TimeStampResp"
    return None


# --- Tree prefix helpers ---

def _child_prefix(parent_prefix, is_last):
    connector = ELBOW if is_last else TEE
    continuation = BLANK if is_last else PIPE
    return parent_prefix + connector, parent_prefix + continuation


# --- Printing ---

def print_node(node, prefix="", connector="", schema=None, field_name=None):
    """Print a node with tree lines."""
    if node.is_universal:
        tag_label = UNIVERSAL_TAGS.get(node.tag_number, f"TAG({node.tag_number})")
    else:
        tag_label = f"[{node.tag_number}]"

    if field_name:
        label = f"{field_name} ({tag_label})"
    else:
        label = tag_label

    if node.constructed or node.children:
        struct_label = _resolve_struct_label(schema)
        if struct_label:
            print(f"{connector}{label}  {struct_label}")
        else:
            print(f"{connector}{label}")

        child_schema = _resolve_child_schema(node, schema)
        _print_children(node.children, prefix, child_schema)
    else:
        val_str = _format_with_schema(node, schema)
        if val_str is None:
            val_str = format_value(node)
        if val_str:
            print(f"{connector}{label}: {val_str}")
        else:
            print(f"{connector}{label}")


def _emit_list(items, prefix, schema_fn):
    for i, item in enumerate(items):
        is_last = (i == len(items) - 1)
        conn, cont = _child_prefix(prefix, is_last)
        fname, sch = schema_fn(item, i)
        print_node(item, prefix=cont, connector=conn, schema=sch, field_name=fname)


def _emit_children_plain(children, prefix):
    _emit_list(children, prefix, lambda n, i: (None, None))


def _resolve_struct_label(schema):
    if schema in SCHEMAS:
        return schema
    return {
        "_SignedAttrs": "Signed Attributes",
        "_UnsignedAttrs": "Unsigned Attributes",
        "_IssuerAndSerialNumber": "IssuerAndSerialNumber",
        "_Extensions": "Extensions",
    }.get(schema)


def _resolve_child_schema(node, schema):
    if schema in SCHEMAS:
        return schema
    if schema == "_IssuerAndSerialNumber":
        return "IssuerAndSerialNumber"
    if schema in ("_SignedAttrs", "_UnsignedAttrs", "_AlgIdSet", "_SignerInfoSet",
                  "_CertificateSet", "_DistinguishedName", "_Extensions",
                  "_Extensions_wrapper", "_Validity", "_Certificate",
                  "_GeneralName", "_GeneralNames", "_AlgIdUnwrap",
                  "_ESSCertIDv2List", "_IssuerSerial", "_AlgParams_dispatch"):
        return schema
    return None


def _format_with_schema(node, schema):
    if schema == "_PKIStatus" and node.is_universal and node.tag_number == 2:
        val = int.from_bytes(node.value, "big", signed=True) if node.value else 0
        name = _PKI_STATUS.get(val, "unknown")
        return f"{val} ({name})"
    if schema == "_PKIFailInfo" and node.is_universal and node.tag_number == 3:
        return _format_failure_info(node.value)
    return None


def _format_failure_info(value):
    if not value or len(value) < 2:
        return format_value_raw(3, value or b"")
    bits = value[1:]
    flags = []
    for byte_idx, b in enumerate(bits):
        for bit_idx in range(8):
            if b & (0x80 >> bit_idx):
                bit_pos = byte_idx * 8 + bit_idx
                name = _PKI_FAILURE_BITS.get(bit_pos, f"bit{bit_pos}")
                flags.append(name)
    return ", ".join(flags) if flags else "(none)"


def _print_children(children, prefix, schema):
    if schema in SCHEMAS:
        target = children
        specs = SCHEMAS[schema]
        if (len(children) == 1 and children[0].is_universal
                and children[0].tag_number == 16 and children[0].children
                and specs and not specs[0][1](children[0])):
            target = children[0].children
        _print_with_schema(target, prefix, specs, schema)
    elif schema == "_Extensions_wrapper":
        for c in children:
            if c.is_universal and c.tag_number == 16 and c.children:
                _print_extensions(c.children, prefix)
            else:
                conn, cont = _child_prefix(prefix, True)
                print_node(c, prefix=cont, connector=conn)
    elif schema == "_Validity":
        _print_validity(children, prefix)
    elif schema in ("_SignedAttrs", "_UnsignedAttrs"):
        _print_attributes(children, prefix)
    elif schema == "_AlgIdSet":
        _emit_list(children, prefix, lambda n, i: (None, "AlgorithmIdentifier"))
    elif schema == "_SignerInfoSet":
        _emit_list(children, prefix, lambda n, i: (
            f"signer[{i}]" if len(children) > 1 else "signer", "SignerInfo"))
    elif schema == "_CertificateSet":
        _emit_list(children, prefix, lambda n, i: (
            f"certificate[{i}]" if len(children) > 1 else "certificate", "_Certificate"))
    elif schema == "_DistinguishedName":
        _print_dn(children, prefix)
    elif schema == "_Extensions":
        _print_extensions(children, prefix)
    elif schema == "_Certificate":
        _print_certificate(children, prefix)
    elif schema == "_GeneralName":
        _print_general_name(children, prefix)
    elif schema == "_GeneralNames":
        _print_general_names(children, prefix)
    elif schema == "_AlgIdUnwrap":
        # Context-tagged wrapper around AlgorithmIdentifier — unwrap one level
        _emit_list(children, prefix, lambda n, i: (None, "AlgorithmIdentifier"))
    elif schema == "_ESSCertIDv2List":
        _emit_list(children, prefix, lambda n, i: (None, "ESSCertIDv2"))
    elif schema == "_IssuerSerial":
        _print_with_schema(children, prefix, SCHEMAS["IssuerSerial"], "IssuerSerial")
    elif schema == "_AlgParams_dispatch":
        _print_alg_params(children, prefix)
    else:
        _emit_children_plain(children, prefix)


def _print_with_schema(children, prefix, field_specs, schema_name):
    spec_idx = 0
    collected_oid = None

    for child_idx, child in enumerate(children):
        is_last = (child_idx == len(children) - 1)
        conn, cont = _child_prefix(prefix, is_last)

        matched_name = None
        matched_schema = None
        while spec_idx < len(field_specs):
            name, matcher, sub_schema, optional = field_specs[spec_idx]
            if matcher(child):
                matched_name = name
                matched_schema = sub_schema
                spec_idx += 1
                break
            elif optional:
                spec_idx += 1
            else:
                break

        # OID-driven dispatch for ContentInfo
        if schema_name == "ContentInfo" and matched_name == "contentType":
            if child.is_universal and child.tag_number == 6 and child.value:
                collected_oid = decode_oid(child.value)

        if schema_name == "ContentInfo" and matched_name == "content" and collected_oid:
            inner_schema = {"1.2.840.113549.1.7.2": "SignedData"}.get(collected_oid)
            if inner_schema and child.children:
                print_node(child, prefix=cont, connector=conn,
                           field_name=matched_name, schema=inner_schema)
                continue

        # EncapsulatedContentInfo eContent dispatch
        if schema_name == "EncapsulatedContentInfo" and matched_name == "eContentType":
            if child.is_universal and child.tag_number == 6 and child.value:
                collected_oid = decode_oid(child.value)

        if schema_name == "EncapsulatedContentInfo" and matched_name == "eContent" and collected_oid:
            _print_econtent(child, conn, cont, matched_name, collected_oid)
            continue

        # AlgorithmIdentifier parameters dispatch
        if schema_name == "AlgorithmIdentifier" and matched_name == "algorithm":
            if child.is_universal and child.tag_number == 6 and child.value:
                collected_oid = decode_oid(child.value)

        if schema_name == "AlgorithmIdentifier" and matched_name == "parameters" and collected_oid:
            param_schema = _alg_param_schema(collected_oid)
            if param_schema:
                print_node(child, prefix=cont, connector=conn,
                           field_name=matched_name, schema=param_schema)
                continue

        print_node(child, prefix=cont, connector=conn,
                   field_name=matched_name, schema=matched_schema)


def _alg_param_schema(alg_oid):
    """Return schema name for algorithm parameters based on algorithm OID."""
    if alg_oid == "1.2.840.113549.1.1.10":  # rsassa-pss
        return "RsaPssParams"
    return None


def _print_alg_params(children, prefix):
    """Fallback for algorithm parameters without OID context."""
    _emit_children_plain(children, prefix)


def _print_econtent(node, connector, prefix, field_name, content_oid):
    inner_schema = {"1.2.840.113549.1.9.16.1.4": "TSTInfo"}.get(content_oid)

    if inner_schema and node.children:
        print(f"{connector}{field_name} ([0])")
        for i, c in enumerate(node.children):
            is_last = (i == len(node.children) - 1)
            conn2, cont2 = _child_prefix(prefix, is_last)
            if c.is_universal and c.tag_number == 4 and c.value:
                inner_nodes = parse_der(c.value)
                if inner_nodes:
                    for n in inner_nodes:
                        print_node(n, prefix=cont2, connector=conn2,
                                   schema=inner_schema)
                else:
                    print_node(c, prefix=cont2, connector=conn2)
            else:
                print_node(c, prefix=cont2, connector=conn2)
    else:
        print_node(node, prefix=prefix, connector=connector, field_name=field_name)


def _print_attributes(children, prefix):
    """Print CMS signed/unsigned attributes with named types and flattened values."""
    for i, attr_node in enumerate(children):
        is_last = (i == len(children) - 1)
        conn, cont = _child_prefix(prefix, is_last)
        if not (attr_node.is_universal and attr_node.tag_number == 16
                and len(attr_node.children) >= 2):
            print_node(attr_node, prefix=cont, connector=conn)
            continue
        oid_node = attr_node.children[0]
        dotted = _extract_oid_value(oid_node) or ""
        attr_name = _ATTR_NAMES.get(dotted, oid_name(dotted) or dotted)

        # The attribute value is in the SET (second child), try to show it inline
        value_set = attr_node.children[1] if len(attr_node.children) >= 2 else None
        if value_set and value_set.is_universal and value_set.tag_number == 17:
            # Try to render known attribute types with a compact value
            compact = _format_attr_value(dotted, value_set)
            if compact is not None:
                print(f"{conn}{attr_name}: {compact}")
                continue

            # For structured attribute values, print the attribute name as header
            # and the SET children as the body (skip OID, skip SET wrapper)
            print(f"{conn}{attr_name}")
            _print_attr_value_children(dotted, value_set.children, cont)
        else:
            print(f"{conn}{attr_name}")
            _emit_children_plain(attr_node.children[1:], cont)


def _format_attr_value(oid, value_set):
    """Try to format attribute value as a compact inline string. Returns None if not possible."""
    children = value_set.children
    if not children or len(children) != 1:
        return None
    val = children[0]

    # Content Type: single OID
    if oid == "1.2.840.113549.1.9.3" and val.is_universal and val.tag_number == 6:
        return format_value(val)

    # Message Digest: single OCTET STRING
    if oid == "1.2.840.113549.1.9.4" and val.is_universal and val.tag_number == 4:
        return format_value(val)

    # Signing Time: single time value
    if oid == "1.2.840.113549.1.9.5" and val.is_universal and val.tag_number in (23, 24):
        return format_value(val)

    return None


def _print_attr_value_children(oid, children, prefix):
    """Print attribute value SET children with structure awareness."""
    # CMS Algorithm Protection (id-aa-CMSAlgorithmProtection)
    if oid == "1.2.840.113549.1.9.52" and children:
        _emit_list(children, prefix, lambda n, i: (None, "CMSAlgorithmProtection"))
        return

    # Signing Certificate V2
    if oid == "1.2.840.113549.1.9.16.2.47" and children:
        _emit_list(children, prefix, lambda n, i: (None, "SigningCertificateV2"))
        return

    # Signing Certificate (v1) — similar structure
    if oid == "1.2.840.113549.1.9.16.2.12" and children:
        _emit_children_plain(children, prefix)
        return

    _emit_children_plain(children, prefix)


def _print_general_name(children, prefix):
    """Print GeneralName — recognizes [4] directoryName as a DN."""
    for i, c in enumerate(children):
        is_last = (i == len(children) - 1)
        conn, cont = _child_prefix(prefix, is_last)
        if c.is_context and c.tag_number == 4 and c.children:
            # directoryName — contains a Name (SEQUENCE of RDNs)
            print(f"{conn}directoryName ([4])")
            for j, inner in enumerate(c.children):
                jlast = (j == len(c.children) - 1)
                conn2, cont2 = _child_prefix(cont, jlast)
                if inner.is_universal and inner.tag_number == 16 and inner.children:
                    _print_dn(inner.children, cont)
                else:
                    print_node(inner, prefix=cont2, connector=conn2)
        elif c.is_context and c.tag_number == 1:
            # rfc822Name
            val = format_value(c)
            print(f"{conn}rfc822Name ([1]): {val}")
        elif c.is_context and c.tag_number == 2:
            # dNSName
            val = format_value(c)
            print(f"{conn}dNSName ([2]): {val}")
        elif c.is_context and c.tag_number == 6:
            # uniformResourceIdentifier
            val = format_value(c)
            print(f"{conn}URI ([6]): {val}")
        else:
            print_node(c, prefix=cont, connector=conn)


def _print_general_names(children, prefix):
    """Print SEQUENCE OF GeneralName."""
    for i, c in enumerate(children):
        is_last = (i == len(children) - 1)
        conn, cont = _child_prefix(prefix, is_last)
        if c.is_context:
            # Each child is a GeneralName choice — wrap in a list for _print_general_name
            _print_general_name([c], prefix)
        else:
            print_node(c, prefix=cont, connector=conn)


def _print_dn(children, prefix):
    parts = []
    for rdn_set in children:
        if not (rdn_set.is_universal and rdn_set.tag_number == 17):
            continue
        for atv in rdn_set.children:
            if not (atv.is_universal and atv.tag_number == 16 and len(atv.children) >= 2):
                continue
            oid_node, val_node = atv.children[0], atv.children[1]
            dotted = _extract_oid_value(oid_node) or ""
            short = _X509_ATTR_SHORT.get(dotted, dotted)
            val = format_value(val_node)
            parts.append(f"{short}={val}")
    if parts:
        conn, _ = _child_prefix(prefix, True)
        print(f"{conn}{', '.join(parts)}")
    else:
        _emit_children_plain(children, prefix)


def _print_extensions(children, prefix):
    for i, ext in enumerate(children):
        is_last = (i == len(children) - 1)
        conn, cont = _child_prefix(prefix, is_last)
        if not (ext.is_universal and ext.tag_number == 16 and ext.children):
            print_node(ext, prefix=cont, connector=conn)
            continue
        oid_node = ext.children[0]
        dotted = _extract_oid_value(oid_node) or ""
        name = oid_name(dotted) or dotted or "Extension"
        critical = False
        value_idx = 1
        if len(ext.children) > 1 and ext.children[1].is_universal and ext.children[1].tag_number == 1:
            critical = True
            value_idx = 2
        crit_str = " CRITICAL" if critical else ""

        # Try to auto-parse OCTET STRING extension values
        remaining = ext.children[value_idx:]
        if (len(remaining) == 1 and remaining[0].is_universal
                and remaining[0].tag_number == 4 and remaining[0].value):
            inner = parse_der(remaining[0].value)
            if inner:
                print(f"{conn}{name}{crit_str}")
                _emit_children_plain(inner, cont)
                continue

        print(f"{conn}{name}{crit_str}")
        _emit_children_plain(remaining, cont)


def _print_validity(children, prefix):
    names = ["notBefore", "notAfter"]
    _emit_list(children, prefix, lambda n, i: (names[i] if i < len(names) else None, None))


def _print_certificate(children, prefix):
    if len(children) >= 3:
        tbs = children[0]
        conn, cont = _child_prefix(prefix, False)
        print(f"{conn}tbsCertificate (SEQUENCE)")
        _print_tbs_certificate(tbs.children, cont)
        conn, cont = _child_prefix(prefix, False)
        print_node(children[1], prefix=cont, connector=conn,
                   field_name="signatureAlgorithm", schema="AlgorithmIdentifier")
        conn, cont = _child_prefix(prefix, True)
        print_node(children[2], prefix=cont, connector=conn, field_name="signatureValue")
    else:
        _emit_children_plain(children, prefix)


def _print_tbs_certificate(children, prefix):
    specs = [
        ("version", _ctx(0), None, True),
        ("serialNumber", _uni(2), None, False),
        ("signature", _uni(16), "AlgorithmIdentifier", False),
        ("issuer", _uni(16), "_DistinguishedName", False),
        ("validity", _uni(16), "_Validity", False),
        ("subject", _uni(16), "_DistinguishedName", False),
        ("subjectPublicKeyInfo", _uni(16), "SubjectPublicKeyInfo", False),
        ("issuerUniqueID", _ctx(1), None, True),
        ("subjectUniqueID", _ctx(2), None, True),
        ("extensions", _ctx(3), "_Extensions_wrapper", True),
    ]
    _print_with_schema(children, prefix, specs, "_TBSCertificate")


# --- Main ---

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("Usage: asn1-dump.py [file]")
        print("  Reads DER or PEM from file or stdin and prints ASN.1 tree.")
        print("  Recognizes TimeStampResp, CMS SignedData, TSTInfo, X.509 structures.")
        sys.exit(0)

    if len(sys.argv) > 1:
        with open(sys.argv[1], "rb") as f:
            raw = f.read()
    else:
        raw = sys.stdin.buffer.read()

    der = detect_and_load(raw)
    nodes = parse_der(der)
    structure = detect_structure(nodes)

    if structure and nodes:
        print_node(nodes[0], schema=structure)
    else:
        for i, n in enumerate(nodes):
            is_last = (i == len(nodes) - 1)
            conn, cont = _child_prefix("", is_last)
            print_node(n, prefix=cont, connector=conn)


if __name__ == "__main__":
    main()

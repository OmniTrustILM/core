#!/usr/bin/env python3
"""Extracts a single-signer CMS SignedData (RFC 5652) into parts for signature verification.

Writes into the output directory:
  signedattrs.der  the signedAttrs re-tagged from [0] IMPLICIT to SET OF (RFC 5652 5.4)
  signature.bin    the raw SignerInfo signature value
  signer.der       the embedded certificate named by SignerInfo.sid, when certificates
                   are present -- CertificateSet is unordered, so the first one is not
                   necessarily the signer's

Prints one verdict line per check performed:
  messageDigest OK|MISMATCH <digest>   whether signedAttrs describe the eContent carried here
  query OK|MISMATCH <term>             whether the TSTInfo answers the supplied TimeStampReq
  MALFORMED <reason>                   the token or query could not be parsed

The exit status reports extraction only:
  0 when the parts were written (also MISMATCH)
  1 when the input is malformed
"""

import hashlib
import sys


# DER tags used by the CMS structures below.
INTEGER = 0x02
OCTET_STRING = 0x04
OBJECT_IDENTIFIER = 0x06
GENERALIZED_TIME = 0x18
SEQUENCE = 0x30
SET = 0x31
CONTEXT_0_PRIMITIVE = 0x80  # [0] IMPLICIT, primitive
CONTEXT_0 = 0xA0  # [0] IMPLICIT
CONTEXT_3 = 0xA3  # [3] EXPLICIT

MESSAGE_DIGEST_OID = bytes.fromhex("06092a864886f70d010904")  # 1.2.840.113549.1.9.4
SUBJECT_KEY_IDENTIFIER_OID = bytes.fromhex("0603551d0e")  # 2.5.29.14
DIGEST_BY_LENGTH = {32: "sha256", 48: "sha384", 64: "sha512"}


class Malformed(Exception):
    pass


def usage(stream=sys.stdout):
    print("Usage: cms-extract.py <token.der> <output-dir> [query.tsq]", file=stream)
    print("  Writes signedattrs.der and signature.bin into <output-dir> and prints one", file=stream)
    print("  verdict line per check: messageDigest, query, or MALFORMED <reason>.", file=stream)


def read_node(buf, offset):
    """Reads one DER TLV at `offset`; returns its tag and content/end boundaries."""
    if offset + 2 > len(buf):
        raise Malformed("truncated header")
    tag = buf[offset]
    first = buf[offset + 1]
    if first & 0x80 == 0:
        length, header = first, 2
    else:
        count = first & 0x7F
        length = int.from_bytes(buf[offset + 2:offset + 2 + count], "big")
        header = 2 + count
    start = offset + header
    if start + length > len(buf):
        raise Malformed("truncated content")
    return {"tag": tag, "start": offset, "content": start, "end": start + length}


def children(buf, node):
    out, offset = [], node["content"]
    while offset < node["end"]:
        child = read_node(buf, offset)
        out.append(child)
        offset = child["end"]
    return out


def value_of(buf, node):
    """The node's content octets, tag and length stripped."""
    return buf[node["content"]:node["end"]]


def encoding_of(buf, node):
    """The node's full DER encoding, tag and length included."""
    return buf[node["start"]:node["end"]]


def child_with_tag(buf, node, tag, what, last=False):
    """The first (or last) child carrying `tag`; `what` names it if it is missing."""
    candidates = children(buf, node)
    found = next((c for c in (reversed(candidates) if last else candidates)
                  if c["tag"] == tag), None)
    if found is None:
        raise Malformed(f"no {what}")
    return found


# --- CMS SignedData navigation ---

def signed_data_of(buf):
    """ContentInfo ::= { contentType id-signedData, content [0] EXPLICIT SignedData }"""
    content_info = read_node(buf, 0)
    wrapper = child_with_tag(buf, content_info, CONTEXT_0, "SignedData wrapper")
    return read_node(buf, wrapper["content"])


def econtent_of(buf, signed_data):
    """The eContent octets, i.e. the TSTInfo this token asserts.

    encapContentInfo is the first SEQUENCE among the SignedData children, ahead of the
    optional [0] certificates and [1] crls.
    """
    encap = child_with_tag(buf, signed_data, SEQUENCE, "encapContentInfo")
    wrapper = child_with_tag(buf, encap, CONTEXT_0, "eContent")
    return value_of(buf, read_node(buf, wrapper["content"]))


def signer_info_of(buf, signed_data):
    """The sole SignerInfo.

    signerInfos is the last SET, which distinguishes it from the digestAlgorithms SET that
    precedes encapContentInfo.
    """
    signer_infos = child_with_tag(buf, signed_data, SET, "signerInfos", last=True)
    return read_node(buf, signer_infos["content"])


def signature_of(buf, signer_info, signed_attrs):
    """The signature value: the OCTET STRING that follows signedAttrs.

    Anchoring on signedAttrs keeps this off the earlier OCTET STRING that a subjectKeyIdentifier
    form of `sid` would contribute.
    """
    signature = next((c for c in reversed(children(buf, signer_info))
                      if c["tag"] == OCTET_STRING and c["start"] >= signed_attrs["end"]), None)
    if signature is None:
        raise Malformed("no signature")
    return value_of(buf, signature)


def signed_attrs_der(buf, signed_attrs):
    """signedAttrs re-tagged from [0] IMPLICIT to SET OF, which is the encoding the signature
    covers per RFC 5652 5.4."""
    der = bytearray(encoding_of(buf, signed_attrs))
    der[0] = SET
    return bytes(der)


# --- Locating the signer's certificate ---

def signer_id_of(buf, signer_info):
    fields = children(buf, signer_info)
    if len(fields) < 2:
        raise Malformed("truncated SignerInfo")
    sid = fields[1]
    if sid["tag"] == SEQUENCE:
        parts = children(buf, sid)
        if len(parts) < 2 or parts[1]["tag"] != INTEGER:
            raise Malformed("malformed issuerAndSerialNumber")
        return "isn", (encoding_of(buf, parts[0]), value_of(buf, parts[1]))
    if sid["tag"] == CONTEXT_0_PRIMITIVE:
        return "ski", value_of(buf, sid)
    raise Malformed("unrecognized SignerIdentifier")


def certificate_ski(buf, tbs):
    """The subjectKeyIdentifier extension value, or None when the certificate carries none."""
    wrapper = next((c for c in children(buf, tbs) if c["tag"] == CONTEXT_3), None)
    if wrapper is None:
        return None
    for extension in children(buf, read_node(buf, wrapper["content"])):
        parts = children(buf, extension)
        if not parts or encoding_of(buf, parts[0]) != SUBJECT_KEY_IDENTIFIER_OID:
            continue
        extn_value = next((p for p in parts if p["tag"] == OCTET_STRING), None)
        if extn_value is None:
            raise Malformed("subjectKeyIdentifier extension has no extnValue")
        # extnValue wraps the DER of the extension, here another OCTET STRING.
        octets = value_of(buf, extn_value)
        return value_of(octets, read_node(octets, 0))
    return None


def certificate_identity(buf, certificate):
    tbs = child_with_tag(buf, certificate, SEQUENCE, "tbsCertificate")
    fields = children(buf, tbs)
    if fields and fields[0]["tag"] == CONTEXT_0:
        fields = fields[1:]
    if len(fields) < 3 or fields[0]["tag"] != INTEGER:
        raise Malformed("malformed tbsCertificate")
    return encoding_of(buf, fields[2]), value_of(buf, fields[0]), certificate_ski(buf, tbs)


def signer_certificate(buf, signed_data, signer_info):
    wrapper = next((c for c in children(buf, signed_data) if c["tag"] == CONTEXT_0), None)
    if wrapper is None:
        return None

    kind, wanted = signer_id_of(buf, signer_info)
    for certificate in children(buf, wrapper):
        if certificate["tag"] != SEQUENCE:  # a CertificateChoices alternative, not a Certificate
            continue
        issuer, serial, ski = certificate_identity(buf, certificate)
        if kind == "isn" and (issuer, serial) == wanted:
            return certificate
        if kind == "ski" and ski is not None and ski == wanted:
            return certificate
    raise Malformed("no embedded certificate matches the SignerInfo sid")


def digest_verdict(buf, signed_attrs, econtent):
    """Compares the signed messageDigest attribute against the eContent the token carries."""
    signed = None
    for attribute in children(buf, signed_attrs):
        fields = children(buf, attribute)
        if not fields or encoding_of(buf, fields[0]) != MESSAGE_DIGEST_OID:
            continue
        if len(fields) < 2 or fields[1]["tag"] != SET:
            raise Malformed("messageDigest attribute has no attrValues SET")
        values = children(buf, fields[1])
        if len(values) != 1 or values[0]["tag"] != OCTET_STRING:
            raise Malformed("messageDigest attrValues is not a single OCTET STRING")
        signed = value_of(buf, values[0])
        break
    if signed is None:
        raise Malformed("no messageDigest attribute")

    name = DIGEST_BY_LENGTH.get(len(signed))
    if name is None:
        raise Malformed(f"unexpected messageDigest length {len(signed)}")

    actual = hashlib.new(name, econtent).digest()
    return f"{'OK' if actual == signed else 'MISMATCH'} {name}"


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


# --- RFC 3161 request/response binding ---

def message_imprint_of(buf, imprint):
    """(hash algorithm OID, hashed message) from a MessageImprint. """
    algorithm = child_with_tag(buf, imprint, SEQUENCE, "hashAlgorithm")
    oid = child_with_tag(buf, algorithm, OBJECT_IDENTIFIER, "hashAlgorithm OID")
    digest = child_with_tag(buf, imprint, OCTET_STRING, "hashedMessage")
    return value_of(buf, oid), value_of(buf, digest)


def integer_value(octets):
    return None if octets is None else int.from_bytes(octets, "big", signed=True)


def query_terms(buf):
    """(imprint, nonce, policy) requested by a TimeStampReq; nonce and policy may be absent."""
    request = read_node(buf, 0)
    fields = children(buf, request)
    imprint = child_with_tag(buf, request, SEQUENCE, "messageImprint in the query")
    policy = next((c for c in fields if c["tag"] == OBJECT_IDENTIFIER), None)
    nonce = next((c for c in fields
                  if c["tag"] == INTEGER and c["start"] >= imprint["end"]), None)
    return (message_imprint_of(buf, imprint),
            integer_value(value_of(buf, nonce) if nonce else None),
            value_of(buf, policy) if policy else None)


def token_terms(buf):
    """(imprint, nonce, policy) asserted by a TSTInfo; nonce may be absent."""
    info = read_node(buf, 0)
    fields = children(buf, info)
    policy = child_with_tag(buf, info, OBJECT_IDENTIFIER, "policy in the TSTInfo")
    imprint = child_with_tag(buf, info, SEQUENCE, "messageImprint in the TSTInfo")
    gentime = child_with_tag(buf, info, GENERALIZED_TIME, "genTime in the TSTInfo")
    nonce = next((c for c in fields
                  if c["tag"] == INTEGER and c["start"] >= gentime["end"]), None)
    return (message_imprint_of(buf, imprint),
            integer_value(value_of(buf, nonce) if nonce else None),
            value_of(buf, policy))


def query_verdict(query, econtent):
    """Compares the TSTInfo with the request that asked for it."""
    want_imprint, want_nonce, want_policy = query_terms(query)
    got_imprint, got_nonce, got_policy = token_terms(econtent)

    if got_imprint != want_imprint:
        return "MISMATCH imprint"
    if want_nonce is not None and got_nonce != want_nonce:
        return "MISMATCH nonce"
    if want_policy is not None and got_policy != want_policy:
        return "MISMATCH policy"
    return "OK"


def extract(buf, outdir, query=None):
    signed_data = signed_data_of(buf)
    econtent = econtent_of(buf, signed_data)
    signer_info = signer_info_of(buf, signed_data)
    signed_attrs = child_with_tag(buf, signer_info, CONTEXT_0, "signedAttrs")

    write_file(f"{outdir}/signedattrs.der", signed_attrs_der(buf, signed_attrs))
    write_file(f"{outdir}/signature.bin", signature_of(buf, signer_info, signed_attrs))

    signer = signer_certificate(buf, signed_data, signer_info)
    if signer is not None:
        write_file(f"{outdir}/signer.der", encoding_of(buf, signer))

    print(f"messageDigest {digest_verdict(buf, signed_attrs, econtent)}")
    if query is not None:
        print(f"query {query_verdict(query, econtent)}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        usage()
        sys.exit(0)
    if len(sys.argv) not in (3, 4):
        usage(sys.stderr)
        sys.exit(2)

    with open(sys.argv[1], "rb") as f:
        buf = f.read()
    query = None
    if len(sys.argv) == 4:
        with open(sys.argv[3], "rb") as f:
            query = f.read()
    try:
        extract(buf, sys.argv[2], query)
    except Malformed as exc:
        print(f"MALFORMED {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

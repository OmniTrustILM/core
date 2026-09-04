"""Generate the ratified cryptographic asset identity decision tables.

The table is committed at ``src/main/resources/cbom/identity-tables.json`` and read
from the classpath, so no build needs Python and no build reaches the network. This
script is what produced those bytes, and the ``Generated artifacts`` job in
``.github/workflows/build_pr.yml`` re-runs it on every pull request and fails if one
byte differs -- which is what makes the committed file reviewable without reading it.

Regenerate after changing any input::

    python3 scripts/cbom/build_identity_tables.py \
        --output src/main/resources/cbom/identity-tables.json

A regeneration that moves the bytes re-keys the cryptographic asset inventory, so the
SHA-256 pinned by ``IdentityTablesTest`` has to be ratified in the same commit.

Inputs live under ``src/main/cbom/identity``. The CycloneDX registry snapshot provides
families and elliptic-curve equivalence data; the OID strand and grammar tables are
ratified OmniTrust decisions that have no complete upstream source.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import warnings

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
SOURCE_DIR = REPO_ROOT / "src" / "main" / "cbom" / "identity"
REGISTRY = SOURCE_DIR / "cryptography-defs.json"
# The bytes of `schema/cryptography-defs.json` in CycloneDX/specification at this commit; README.md
# beside the inputs pins the same value, and moving the snapshot moves both.
REGISTRY_UPSTREAM_COMMIT = "5cbdee80a1"
DEFS_SCHEMA = SOURCE_DIR / "cryptography-defs.schema.json"
OID_STRAND = SOURCE_DIR / "oid-strand.json"
DEFAULT_OUTPUT = REPO_ROOT / "src" / "main" / "resources" / "cbom" / "identity-tables.json"

# secg first: cbom-lens pins "Canonical namespace: secg/* for short-Weierstrass
# curves", the 1.7 golden and the upstream conformance fixtures both emit secg/*,
# and the OID table landed there independently. Electing secg means the common case
# needs no folding at all.
AUTHORITY_PRIORITY = [
    "secg", "nist", "x962", "x963", "brainpool", "anssi", "oscaa",
    "bls", "bn", "mnt", "nums", "oakley", "wtls", "gost", "other",
]

# PQC candidate families the registry cannot express. Measured on a 101-document
# corpus: 370 of 472 family-less algorithm assets carry one of these names, and
# `open-quantum-safe/liboqs` alone contributes 418 assets almost entirely of this
# shape. Leaving them family-less is not survivable for this epic — the AC5
# `algorithmFamily` filter and any PQC rule set keyed on that field would be blind to
# Kyber, Falcon and SPHINCS+, which is precisely the surface the inventory exists to
# report. So they become documented pseudo-families, exactly as RSA and EC already
# are: not registry tokens, marked as pseudo, and grouped so they can be filtered.
PQC_PSEUDO_FAMILIES = [
    "bcrypt",
    "Kyber", "Dilithium", "Falcon", "SPHINCS+", "Classic McEliece", "FrodoKEM",
    "BIKE", "HQC", "NTRU", "NTRU-Prime", "CROSS", "MQOM", "SNOVA", "UOV", "MAYO",
    "X-Wing", "SIKE", "GeMSS", "Rainbow", "Picnic", "SQIsign", "LESS", "PERK",
    "RYDE", "MIRATH", "QR-UOV", "HAWK", "Raccoon", "AIMer",
]

PSEUDO_FAMILIES = {
    # A pseudo-family is a deliberate generalization, not a guess: the registry has
    # no bare RSA or EC token, yet a bare key is exactly what PQC triage must catch.
    # The members list is what makes subsumption (concrete beats pseudo without
    # refuting the OID) decidable.
    "RSA": ["RSAES-OAEP", "RSAES-PKCS1", "RSASSA-PKCS1", "RSASSA-PSS", "RSA-X931"],
    "EC": ["ECDSA", "ECDH", "ECIES", "EdDSA", "SM2", "MQV", "X3DH", "BLS", "SM9"],
}

# A pseudo-family stands alone: it has no concrete registry member that could subsume
# it, so it is listed with an empty member set rather than omitted, keeping the
# subsumption check total.
PSEUDO_FAMILIES.update({name: [] for name in PQC_PSEUDO_FAMILIES})

# Fernet is not post-quantum and not a registry token, but it is the same case: a real,
# named construction that producers write and the registry cannot express. Five corpus
# rows carry it as a bare name and resolved to no family at all, which is the answer that
# loses information -- "AES-CBC plus HMAC, keyed and versioned this specific way" is a
# construction, not an absence. Empty member set for the same reason the PQC entries have
# one: nothing concrete can subsume it.
PSEUDO_FAMILIES["Fernet"] = []

# NOTE ON PATTERN DESIGN: every rule here is used for BOTH matching a family and
# SUBSTITUTING the matched text out of the variant residue. A rule must therefore not
# consume characters another slot needs — `^RSA-?\d` ate the leading digit of a key
# size, so `RSA4096` kept `096` as a variant and split from `RSA-4096` across 23 corpus
# rows. Use a lookahead when the pattern needs to see a character it must not eat.
#
# Ordered, word-guarded name grammar. Order IS the rule: the first match wins, so
# every entry that could be a prefix or infix of a later one must come first.
# Guards are on [A-Za-z0-9] adjacency rather than on separators, because the real
# hazards are unseparated: RSAES-OAEP contains AES, HMACSHA2 contains SHA,
# "design" contains DES. The class is ASCII on purpose: a non-ASCII letter counts as a
# word boundary, so `ÉEd25519` elects EdDSA. That is the same ASCII-only reading every
# fold in the keyed path applies, and it keeps the guard independent of the runtime's
# Unicode tables.
# ``AsciiText.PYTHON_WHITESPACE`` again, spelled for a character class inside an emitted
# pattern. A guard written with an ASCII space only is defeated by the one character this
# codebase repeatedly documents as arriving from producer text pasted out of a document:
# ``familyFromName`` matches the raw component name, with no whitespace collapse in front of it.
# Spelled as escape sequences, not as the characters themselves: both engines read `\t`, `\xhh`
# and `\uhhhh` the same way, and the artifact stays ASCII, where a literal no-break space would be
# invisible in every diff of the file whose whole purpose is to be diffed.
GUARD_SEPARATORS = (r"-_ \t\n\x0B\f\r\x1C\x1D\x1E\x1F\x85\xA0"
                    r"\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A"
                    r"\u2028\u2029\u202F\u205F\u3000")

NAME_GRAMMAR = [
    # --- exact producer strings, highest precedence -----------------------------
    {"pattern": r"(?<![A-Za-z0-9])ChaCha20[-_]?Poly1305", "family": "ChaCha20",
     "why": "cbom-lens ChaCha20-Poly1305 and the unseparated ChaCha20Poly1305 spelling "
            "(separator-insensitive: CHACHA20_POLY1305 elected Poly1305 as its family, "
            "one construction with two families decided by an underscore)"},
    {"pattern": r"^3DES-EDE-CBC$", "family": "3DES", "why": "cbom-lens familyExact"},
    {"pattern": r"^RC4-128$", "family": "RC4", "why": "cbom-lens familyExact"},
    {"pattern": r"(?<![A-Za-z0-9])(HSS[-_/ ]?LMS|LMOTS|LMS)(?![A-Za-z0-9])", "family": "LMS",
     "why": "cbom-lens familyExact, widened twice: the anchored form matched only the bare name, and the "
            "two-word HSS-LMS literal that replaced it still let the registered parameter-set names fall "
            "through to the SHA-2 rule -- LMS_SHA256_M32_H5 and LMOTS_SHA256_N32_W8 are what RFC 8554 and "
            "SP 800-208 register and what a JCA-call scanner emits, so a separator decided whether a stateful "
            "hash-based signature was inventoried as a signature or as a digest. Word-guarded on both sides so "
            "the bare tokens resolve and nothing matches inside another word; bare HSS is not listed, since the "
            "token is also a telecom name"},
    {"pattern": r"(?<![A-Za-z0-9])XMSS", "family": "XMSS",
     "why": "cbom-lens familyExact, widened: XMSS-SHA2_10_256 and XMSS-MT spellings fell through to "
            "the SHA-2 rule; the left guard keeps the token from matching inside another word"},
    {"pattern": r"^ssh-ed25519$", "family": "EdDSA", "why": "cbom-lens familyExact"},
    {"pattern": r"^ssh-rsa$", "family": "RSASSA-PKCS1", "why": "cbom-lens familyExact"},
    {"pattern": r"^ssh-dss$", "family": "DSA", "why": "cbom-lens familyExact"},
    # Word-guarded, not anchored. The anchored form resolved a bare `Ed25519` and nothing
    # else, so every name that says the same thing with a word beside it fell through to no
    # family at all -- measured, 19 corpus rows: `Ed25519 host key` (x4), straylight's
    # `ed25519 (pub, sign, certify, ...)` (x12), `SSH Ed25519 key`, `Ed25519/Ed448` and
    # `Ed25519/Ed448 (OID)`. A key artifact named after its algorithm is still that algorithm;
    # leaving those family-less made the AC5 `algorithmFamily` filter blind to the most common
    # Edwards spelling in the corpus. The guard keeps it from matching inside a longer token,
    # so `X25519` and `Curve25519` are untouched.
    #
    # The RFC 8032 `ph`/`ctx` suffix is admitted through a lookahead and never consumed: every
    # rule's match is also what the variant residue strips, so consuming the suffix left
    # `Ed25519ph`, `Ed25519ctx` and bare `EdDSA` on one key, and the `ph`/`ctx` tokens in the
    # variant vocabulary had no way to fire.
    {"pattern": r"(?<![A-Za-z0-9])Ed(25519|448)(?=(?:ph|ctx)?(?![A-Za-z0-9]))", "family": "EdDSA",
     "why": "registry has no Ed25519 family token; EdDSA is the family, Ed25519 the curve"},

    # --- KDFs and password-based constructions FIRST ----------------------------
    # The outer construction wins over the inner primitive, the same principle that
    # puts signature schemes ahead of digests. Measured on the wide corpus:
    # `PBKDF2-HMAC-SHA-256` derived HMAC and `HKDF-SHA-256` derived SHA-2, both
    # contradicted by their own OIDs.
    {"pattern": r"(?<![A-Za-z0-9])Concat(enation)?[-_ ]?KDF", "family": "SP800-56C",
     "why": "7 corpus rows name the construction rather than its standard; SP800-56C is the "
            "registry token for it, and the KDF block runs before the digests so the outer "
            "construction wins over the inner hash"},
    {"pattern": r"(?<![A-Za-z0-9])PBKDF2", "family": "PBKDF2", "why": "Cosmian KMS PBKDF2-HMAC-SHA-256"},
    {"pattern": r"(?<![A-Za-z0-9])PBKDF1", "family": "PBKDF1", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])PBMAC1", "family": "PBMAC1", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])PBES2", "family": "PBES2", "why": "observed in the wild"},
    {"pattern": r"(?<![A-Za-z0-9])PBES1", "family": "PBES1", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])HKDF", "family": "HKDF", "why": "sbom-tools HKDF-SHA-256"},
    {"pattern": r"(?<![A-Za-z0-9])Argon2", "family": "Argon2", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])yescrypt", "family": "yescrypt", "why": "before scrypt"},
    {"pattern": r"(?<![A-Za-z0-9])scrypt", "family": "scrypt", "why": "registry token"},

    # --- MAC before digest: HMAC-SHA256 must not read as SHA-2 ------------------
    {"pattern": r"(?<![A-Za-z0-9])HMAC(?![A-Za-z0-9])", "family": "HMAC",
     "why": "cbomkit HMAC-SHA256 / HMAC-SHA512"},
    {"pattern": r"^HMAC", "family": "HMAC",
     "why": "cbomkit HMACSHA2 - no separator, so the guarded rule above misses it"},
    {"pattern": r"(?<![A-Za-z0-9])(CMAC|GMAC)(?![A-Za-z0-9])", "family": "CMAC",
     "why": "MAC tokens must not fall through to their underlying cipher"},
    {"pattern": r"(?<![A-Za-z0-9])Poly1305(?![A-Za-z0-9])", "family": "Poly1305",
     "why": "standalone Poly1305; the size stoplist stops 1305 reading as a size"},

    # --- key agreement, BEFORE the RSA composites --------------------------------
    # `ECDHE-RSA-AES128-GCM-SHA256` is a real cipher-suite spelling. Matched against
    # the `-RSA` rule first it becomes an RSA signature asset, which is simply wrong:
    # the key-agreement token is the more specific statement about the name.
    {"pattern": r"(?<![A-Za-z0-9])X(25519|448)(?![A-Za-z0-9])", "family": "ECDH",
     "why": "the registry has no X25519 family token; it is an ECDH variant and the "
            "curve carries the rest (11 assets in the wild corpus)"},
    {"pattern": r"(?<![A-Za-z0-9])ECDHE?(?![A-Za-z0-9])", "family": "ECDH",
     "why": "cbomkit ECDH; cbom-lens maps ECDHE- to ECDH; ahead of -RSA"},
    {"pattern": r"(?<![A-Za-z0-9])ECIES(?![A-Za-z0-9])", "family": "ECIES", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])DHE(?![A-Za-z0-9])", "family": "FFDH",
     "why": "cbom-lens maps DHE- to FFDH; ahead of -RSA"},

    # --- signature schemes before their component primitives --------------------
    # A composite name that mentions BOTH a signature family and a digest is a
    # signature scheme, not a hash. Measured: `ECDSA-SHA256` derived SHA-2 while 1.7
    # declares `algorithmFamily: ECDSA` for the same asset, which broke 1.6/1.7
    # parity; `RSA-SHA256` did the same. So every signature family is matched before
    # the digest rules, not after.
    {"pattern": r"^RSA(ES)?-?OAEP", "family": "RSAES-OAEP",
     "why": "RSA-OAEP and RSAES-OAEP are one algorithm; the short spelling had no rule"},
    # A scheme spelling with the key size interposed. These were reaching the digest
    # rules and deriving SHA-2 — an RSA signature asset stored as a hash — but the
    # cipher-suite classifier was catching them first and yielding no family at all,
    # which masked the gap. Authored from the registry tokens and by symmetry with the
    # size-less spellings above, NOT from a hold-out witness; see §1.5.
    {"pattern": r"^RSA[-_]?\d{3,5}[-_]OAEP", "family": "RSAES-OAEP",
     "why": "RSA-2048-OAEP-SHA256: the size sits between the family and the scheme"},
    {"pattern": r"^RSA[-_]?\d{3,5}[-_]PSS", "family": "RSASSA-PSS",
     "why": "RSA-2048-PSS-SHA256, same interposed-size shape"},
    {"pattern": r"^RSA[-_]?\d{3,5}[-_]PKCS1", "family": "RSASSA-PKCS1",
     "why": "RSA-2048-PKCS1v15-SHA256, same interposed-size shape; a digest suffix "
            "makes PKCS#1 v1.5 a signature scheme rather than the encryption scheme"},
    {"pattern": r"^RSA[-_]?PSS(?=[-_]|$)", "family": "RSASSA-PSS",
     "why": "RSA-PSS-SHA256: the size-less PSS spelling had no rule and fell to the digest rules, storing an RSA signature asset as a hash. Symmetry with ^RSASSA-PSS"},
    {"pattern": r"^RSA[-_]?\d{3,5}[-_](?=(SHA|MD)\d)", "family": "RSASSA-PKCS1",
     "why": r"rsa-2048-sha1-signed-key (authoring corpus): the interposed-size form of the existing ^RSA-(?=(SHA|MD)\d) rule — a digest-suffixed RSA name is a signature scheme, never the digest"},
    {"pattern": r"^RSA[-_]?PKCS1(?:[-_.]?v?1[._]5)?(?=[-_])", "family": "RSASSA-PKCS1",
     "why": "RSA-PKCS1-1.5-SHA512 (authoring corpus): PKCS#1 v1.5 with a digest is a "
            "signature scheme; the cipher-suite classifier had been swallowing it"},
    {"pattern": r"^RSAES-PKCS1", "family": "RSAES-PKCS1", "why": "explicit registry token"},
    {"pattern": r"^RSASSA-PKCS1", "family": "RSASSA-PKCS1", "why": "explicit registry token"},
    {"pattern": r"-RSAPSS", "family": "RSASSA-PSS", "why": "cbom-lens: PSS before PKCS1"},
    {"pattern": r"^RSASSA-PSS", "family": "RSASSA-PSS", "why": "cbomkit RSASSA-PSS"},
    {"pattern": r"^RSA-X931", "family": "RSA-X931", "why": "registry data token"},
    {"pattern": r"-RSA(?![A-Za-z0-9])", "family": "RSASSA-PKCS1", "why": "cbom-lens substring rule"},
    {"pattern": r"with-?RSA.*MGF1", "family": "RSASSA-PSS",
     "why": "eclipse-keypont SHA256withRSAandMGF1: MGF1 means PSS, and the old guard "
            "blocked on the following 'and' so it read as SHA-2"},
    {"pattern": r"with-?RSA(Encryption)?(?![A-Za-z0-9])", "family": "RSASSA-PKCS1",
     "why": "theia SHA512withRSA; corroborated by OID 1.2.840.113549.1.1.13"},
    {"pattern": r"^rsa-sha2-", "family": "RSASSA-PKCS1", "why": "cbom-lens, RFC 8332"},
    {"pattern": r"^RSA-(?=(SHA|MD)\d)", "family": "RSASSA-PKCS1",
     "why": "conformance fixture RSA-SHA256: digest-suffixed RSA is a signature scheme"},
    {"pattern": r"withECDSA(?![A-Za-z0-9])", "family": "ECDSA", "why": "JCA infix form"},
    {"pattern": r"withDSA(?![A-Za-z0-9])", "family": "DSA", "why": "JCA infix form"},
    # Signature families, ahead of the digest rules for the reason above.
    {"pattern": r"(?<![A-Za-z0-9])ML-?DSA", "family": "ML-DSA",
     "why": "cbom-lens familyPrefix; MLDSA44 has no separator"},
    {"pattern": r"(?<![A-Za-z0-9])ML-?KEM", "family": "ML-KEM",
     "why": "cbom-lens familyPrefix; MLKEM768 has no separator"},
    {"pattern": r"(?<![A-Za-z0-9])SLH-?DSA", "family": "SLH-DSA", "why": "cbom-lens familyPrefix"},
    {"pattern": r"(?<![A-Za-z0-9])ECDSA", "family": "ECDSA",
     "why": "ECDSA-SHA256 must be ECDSA, not SHA-2 - the measured parity break"},
    {"pattern": r"^ecdsa-sha2-", "family": "ECDSA", "why": "cbom-lens familyPrefix"},
    {"pattern": r"(?<![A-Za-z0-9])EdDSA(?![A-Za-z0-9])", "family": "EdDSA", "why": "cbomkit EdDSA"},
    {"pattern": r"^DSA-(?=(SHA|MD)\d)", "family": "DSA", "why": "digest-suffixed DSA"},

    # --- PQC candidates. Pseudo-families; see PQC_PSEUDO_FAMILIES ---------------
    # Ordered longest-first where one name contains another (X25519MLKEM768 is a
    # hybrid and must not read as bare ML-KEM; NTRU-Prime before NTRU).
    {"pattern": r"(?<![A-Za-z0-9])X-?Wing", "family": "X-Wing", "why": "hybrid KEM, liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])X25519MLKEM768", "family": "X-Wing",
     "why": "the standard hybrid group; grouped with the hybrids, not bare ML-KEM"},
    {"pattern": r"(?<![A-Za-z0-9])(CRYSTALS-?)?Kyber", "family": "Kyber",
     "why": "pre-standard name; deliberately NOT folded into ML-KEM - different parameters"},
    {"pattern": r"(?<![A-Za-z0-9])(CRYSTALS-?)?Dilithium", "family": "Dilithium",
     "why": "pre-standard name; deliberately NOT folded into ML-DSA"},
    {"pattern": r"(?<![A-Za-z0-9])SPHINCS", "family": "SPHINCS+", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])Falcon", "family": "Falcon", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])FrodoKEM", "family": "FrodoKEM", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])Classic-?\s?McEliece", "family": "Classic McEliece", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])McEliece", "family": "Classic McEliece", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])NTRU-?Prime", "family": "NTRU-Prime", "why": "before NTRU"},
    {"pattern": r"(?<![A-Za-z0-9])(s?)NTRU", "family": "NTRU", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])BIKE(?![A-Za-z])", "family": "BIKE",
     "why": "liboqs. Guarded against a following letter, not a digit: `bikeshed` elected the family, while "
            "liboqs's own pre-0.5 spellings BIKE1-L1-CPA, BIKE2 and BIKE3 glue a digit to the token"},
    {"pattern": r"(?<![A-Za-z0-9])HQC", "family": "HQC", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])CROSS(?![A-Za-z0-9])", "family": "CROSS", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])MQOM", "family": "MQOM", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])SNOVA", "family": "SNOVA", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])QR-?UOV", "family": "QR-UOV", "why": "before UOV"},
    {"pattern": r"(?<![A-Za-z0-9])UOV", "family": "UOV", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])MAYO", "family": "MAYO", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])SIKE|(?<![A-Za-z0-9])SIDH", "family": "SIKE",
     "why": "broken by SIDH attack; still present in real inventories"},
    {"pattern": r"(?<![A-Za-z0-9])GeMSS", "family": "GeMSS", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])Rainbow", "family": "Rainbow", "why": "broken; still inventoried"},
    {"pattern": r"(?<![A-Za-z0-9])Picnic", "family": "Picnic", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])SQIsign", "family": "SQIsign", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])HAWK(?![A-Za-z0-9])", "family": "HAWK", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])Raccoon", "family": "Raccoon", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])AIMer", "family": "AIMer", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])PERK(?![A-Za-z0-9])", "family": "PERK", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])RYDE(?![A-Za-z0-9])", "family": "RYDE", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])MIRATH", "family": "MIRATH", "why": "liboqs"},
    {"pattern": r"(?<![A-Za-z0-9])LESS(?![A-Za-z0-9])", "family": "LESS", "why": "liboqs"},

    # --- key-exchange names that LOOK like digests, before the digest rules ------
    {"pattern": r"^curve25519-sha", "family": "ECDH",
     "why": "SSH KEX name; it read as SHA-2 and collided with SHA-256 on 33 components"},
    {"pattern": r"^(diffie-hellman|dh)-group", "family": "FFDH", "why": "SSH/IKE KEX name"},
    {"pattern": r"(?<![A-Za-z0-9])ecdh-sha2", "family": "ECDH", "why": "SSH KEX name"},
    {"pattern": r"(?<![A-Za-z0-9])rsassa-?pss", "family": "RSASSA-PSS",
     "why": "camelCase rsassaPss defeated the anchored rule"},
    {"pattern": r"(?<![A-Za-z0-9])SM3(?![A-Za-z0-9])", "family": "SM3", "why": "observed"},
    {"pattern": r"(?<![A-Za-z0-9])SM2(?![A-Za-z0-9])", "family": "SM2", "why": "observed"},
    {"pattern": r"(?<![A-Za-z0-9])SM4(?![A-Za-z0-9])", "family": "SM4", "why": "observed"},
    {"pattern": r"(?<![A-Za-z0-9])bcrypt", "family": "bcrypt", "why": "observed"},

    # --- SHA-3 and SHAKE before SHA-2; SHA-1 before SHA-2 -----------------------
    {"pattern": r"(?<![A-Za-z0-9])SHA-?3(?![0-9])", "family": "SHA-3",
     "why": "SHA3-256 / SHA-3-256 / SHA3_256 all before the SHA-2 rule"},
    {"pattern": r"(?<![A-Za-z0-9])SHAKE", "family": "SHA-3", "why": "cbom-lens familyPrefix"},
    {"pattern": r"(?<![A-Za-z0-9])SHA-?1(?![0-9])", "family": "SHA-1",
     "why": "cbomkit SHA1 and cbom-lens SHA-1; guarded so SHA-1 never eats SHA-160-ish forms"},
    {"pattern": r"(?<![A-Za-z0-9])SHA-?(224|256|384|512)(?![0-9])", "family": "SHA-2",
     "why": "cbomkit SHA256/384/512 (no dash) and cbom-lens SHA-256 etc"},
    {"pattern": r"(?<![A-Za-z0-9])SHA-?2(?![0-9])", "family": "SHA-2",
     "why": "the bare family spelling `SHA2`, as in SLH-DSA-SHA2-128s. Unrecognised it "
            "survived into the variant residue as `shas`/`shaf`, which the closed "
            "vocabulary then rejected — losing the s/f parameter-set distinction"},
    # A digest, so it ranks with the digests: placed in the exact-string block it outranked
    # HMAC and every signature rule, and `HMAC-RIPEMD160`, `RIPEMD160withRSA` and
    # `PBKDF2-HMAC-RIPEMD160` all keyed as the inner hash instead of the outer construction.
    {"pattern": r"(?<![A-Za-z0-9])RIPEMD", "family": "RIPEMD",
     "why": "cbom-lens familyExact RIPEMD-160, widened: the anchored form left a bare `RIPEMD` "
            "family-less, and the guard still admits the -160 and -128 spellings. Ranked with the "
            "digests rather than in the exact-string block: first rule wins, so from there it "
            "outranked HMAC and every signature rule and `HMAC-RIPEMD160`, `RIPEMD160withRSA` and "
            "`PBKDF2-HMAC-RIPEMD160` elected the inner hash instead of the outer construction. The "
            "rank is part of the rule, so it is stated in the field the artifact carries"},
    {"pattern": r"(?<![A-Za-z0-9])BLAKE2", "family": "BLAKE2", "why": "cbom-lens familyPrefix"},
    {"pattern": r"(?<![A-Za-z0-9])BLAKE3", "family": "BLAKE3", "why": "no OID anchor exists"},
    {"pattern": r"(?<![A-Za-z0-9])MD-?5(?![0-9])", "family": "MD5", "why": "cbomkit MD5"},
    {"pattern": r"(?<![A-Za-z0-9])MD-?4(?![0-9])", "family": "MD4", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])MD-?2(?![0-9])", "family": "MD2", "why": "registry token"},

    # --- key agreement, remainder -----------------------------------------------
    {"pattern": r"(?<![A-Za-z0-9])DH(?![A-Za-z0-9])", "family": "FFDH",
     "why": "bare Diffie-Hellman"},

    # --- 3DES strictly before DES; DES guarded so 'design' cannot match ---------
    {"pattern": r"(?<![A-Za-z0-9])(3DES|DES3|TDES|DESede)(?![A-Za-z0-9])", "family": "3DES",
     "why": "3DES before DES. DES3 is in the alternation because the DES rule below admits a trailing digit "
            "for DES56 and DES64, so `DES3-CBC` elected DES and keyed identically to `DES-CBC` -- the merge "
            "of a broken cipher into a different one"},
    {"pattern": r"(?<![A-Za-z0-9])DES(?![A-Za-z])", "family": "DES",
     "why": "guarded against letters so 'design' cannot match, but DES56 and DES64 are "
            "real observed names and a digit must be allowed to follow"},

    # --- AES guarded so RSAES-OAEP cannot match --------------------------------
    {"pattern": r"(?<![A-Za-z0-9])AES", "family": "AES",
     "why": "cbomkit AES128 / AES128-GCM have no separator; guard blocks RSAES-*"},
    {"pattern": r"(?<![A-Za-z0-9])(ChaCha20|ChaCha)(?![A-Za-z0-9])", "family": "ChaCha20",
     "why": "ChaCha20 before ChaCha"},
    {"pattern": r"(?<![A-Za-z0-9])ElGamal", "family": "ElGamal", "why": "observed in the wild"},
    {"pattern": r"(?<![A-Za-z0-9])Diffie-?\s?Hellman", "family": "FFDH",
     "why": "observed spelled out; the bare DH rule cannot match it"},
    {"pattern": r"(?<![A-Za-z0-9])Blowfish", "family": "Blowfish", "why": "observed in the wild"},
    {"pattern": r"(?<![A-Za-z0-9])Twofish", "family": "Twofish", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])Serpent", "family": "Serpent", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])Whirlpool", "family": "Whirlpool", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])Salsa20", "family": "Salsa20", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])Ascon", "family": "Ascon", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])IDEA(?![A-Za-z0-9])", "family": "IDEA", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])CAST-?5(?![0-9])", "family": "CAST5", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])CAST-?6(?![0-9])", "family": "CAST6", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])CAMELLIA", "family": "CAMELLIA", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])ARIA", "family": "ARIA", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])SEED(?![A-Za-z0-9])", "family": "SEED", "why": "registry token"},
    # One rule per token: RC2/RC4/RC5/RC6 are four different families and four
    # different risk verdicts, so they must never share a rule.
    {"pattern": r"(?<![A-Za-z0-9])RC2(?![A-Za-z0-9])", "family": "RC2", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])RC4", "family": "RC4", "why": "cbom-lens RC4-128"},
    {"pattern": r"(?<![A-Za-z0-9])RC5(?![A-Za-z0-9])", "family": "RC5", "why": "registry token"},
    {"pattern": r"(?<![A-Za-z0-9])RC6(?![A-Za-z0-9])", "family": "RC6", "why": "registry token"},

    # --- GOST, Skipjack, Fernet ---------------------------------------------------
    # The registry has one GOST token for what are several algorithms -- 34.10 signs, 34.11
    # hashes, 34.12 and 28147 encrypt -- so a name that cites the standard must stay on the
    # name tier, where the number keeps it distinct. Under the bare family the sub-64 standard
    # digits vanished from the residue and the year was read as the key size, so
    # `GOST R 34.10-2012` and `GOST R 34.11-2012` shared `ALG|GOST|2012`.
    {"pattern": r"(?<![A-Za-z0-9])GOST(?![" + GUARD_SEPARATORS + r"]*R?["
                + GUARD_SEPARATORS + r"]*(?:28147|34[._-]?1[012]|34[._-]?3))", "family": "GOST",
     "why": "registry token with no rule at all until now: `GOST cipher/hash (legacy)` resolved to "
            "nothing. One guard, against a following standard number -- 28147, 34.10, 34.11, 34.12 or "
            "34.3, separated by the reference whitespace set or by nothing (`GOST R 34.11-2012`, "
            "`GOST_R_34_10_2012`, `GOST28147`, Bouncy Castle's `GOST3411` and `GOSTR3410`) -- because the "
            "single registry token cannot carry which standard is meant, so a name citing one stays on the "
            "name tier where the number keeps 34.10 apart from 34.11. The guard spells the reference "
            "whitespace set rather than an ASCII space: `GOST R 34.10` written with U+00A0 for either space "
            "defeated the narrow spelling and merged 34.10 with 34.11 again. Nothing else is guarded: a "
            "trailing key size or mode (`GOST-256-CTR`, `GOST-512`) and a glued word (`GOSTHASH`, `GOSTKDF`) "
            "elect the family, since a bare `[0-9]` lookahead and a right word guard between them left only "
            "six plain-ASCII spellings able to reach it. Cipher suites naming GOST are classified as suites "
            "before family derivation runs, so they cannot reach this"},
    {"pattern": r"(?<![A-Za-z0-9])Skipjack", "family": "Skipjack",
     "why": "registry token with no rule; `Skipjack (broken cipher)` resolved to nothing, and a "
            "broken cipher going unnamed is the opposite of what the inventory is for"},
    {"pattern": r"(?<![A-Za-z0-9])Fernet", "family": "Fernet",
     "why": "pseudo-family: a real construction the registry cannot express, 5 corpus rows"},

    # --- DSA last: ECDSA / EdDSA / ML-DSA / SLH-DSA all contain it --------------
    {"pattern": r"(?<![A-Za-z0-9])DSA(?![A-Za-z0-9])", "family": "DSA",
     "why": "must come after ECDSA, EdDSA, ML-DSA, SLH-DSA - all contain DSA"},

    # --- pseudo-families, last resort before 'no family' ------------------------
    {"pattern": r"(?<![A-Za-z0-9])RSA(?![A-Za-z0-9])", "family": "RSA",
     "why": "pseudo-family: padding scheme unknowable from a bare RSA key"},
    {"pattern": r"^RSA-?(?=\d)", "family": "RSA",
     "why": "RSA-2048 and the unseparated RSA2048/RSA3072/RSA4096 spellings"},
    {"pattern": r"^DSA-?(?=\d)", "family": "DSA", "why": "DSA1024 observed unseparated"},
    {"pattern": r"(?<![A-Za-z0-9])EC(?![A-Za-z0-9])", "family": "EC",
     "why": "pseudo-family; guard blocks ECB, ECDSA, ECDH, ECIES"},
]

# Tokens whose digits are NOT a key or digest size. Poly1305 is the measured case:
# without the stoplist it parses as size 1305, which is inside the whitelist.
SIZE_STOPLIST = [
    "3DES", "AES", "CBC", "CCM", "CFB", "CHACHA20", "CMAC", "CTR", "EAX", "ECB",
    "GCM", "GMAC", "HMAC", "KW", "KWP", "MD2", "MD4", "MD5", "MGF1", "OAEP",
    "OCB", "OFB", "P1363", "PKCS1", "PKCS5", "PKCS7", "PKCS8", "POLY1305",
    "PSS", "RC2", "RC4", "RC5", "RC6", "RFC8439", "SHA1", "SHA2", "SHA3",
    "SIV", "WRAP", "X931", "XTS",
]

# Synonym pairs that mean the same construction. Producers write both spellings, and
# without folding them `AES-256-KW` and `AES-256-WRAP` - the same RFC 3394 algorithm -
# land on different variants.
VARIANT_SYNONYMS = {
    "keywrappad": "wrappad", "keywrap": "wrap",
    "kwp": "wrappad", "wrappad": "wrappad",
    "kw": "wrap",
    "ede3": "ede3", "ede": "ede3",
}

# Families for which a trailing separator-delimited length is a TRUNCATION marker.
# Truncation is a digest concept: applying the rule to a signature scheme made
# `ECDSA-P-256-SHA-256` and `ECDSA-P-256-SHA256` disagree on nothing but a hyphen.
TRUNCATABLE_FAMILIES = ["SHA-2", "SHA-3", "BLAKE2", "BLAKE3", "SM3", "RIPEMD"]

# A cipher-suite name is NOT a single algorithm, and must never be reduced to one.
# Measured on unseen data: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and
# `TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256` both reduced to the AES/ARIA cipher alone,
# dropping key exchange and authentication, and 33 groups of distinct suites collapsed.
# Names matching these shapes bypass family derivation entirely and are keyed on the
# full normalized name, which keeps every suite distinct.
CIPHER_SUITE_NAME_PATTERNS = [
    r"^TLS[_-].+[_-]WITH[_-]",
    r"^TLS[_-](AES|CHACHA|GOST|SM4|ARIA|CAMELLIA)",
    # The bulk-cipher requirement is what separates an OpenSSL-style suite name from a
    # signature scheme that merely ends in a digest. Without it, `RSA-PSS-SHA256` and
    # `RSA-PKCS1-1.5-SHA512` were classified as cipher suites and left with no family —
    # invisible to every family-keyed rule. A suite names a key exchange, a bulk cipher
    # and a MAC; `RSA-PSS-SHA256` names no cipher.
    r"^(SSL|SRP|PSK|DHE|ECDHE|ECDH|RSA|ADH|AECDH)[-_].*(?<![A-Za-z0-9])"
    r"(AES|CHACHA20|CHACHA|ARIA|CAMELLIA|SEED|3DES|DES|RC4|RC2|SM4|GOST|IDEA|NULL)"
    r"(?![A-Za-z]).*[-_](SHA|MD5|GCM|CCM|CBC)",
    r"@(openssh\.com|libssh\.org)$",
]

# Tokens that are identity-bearing when they appear ALONGSIDE a winning family: the
# digest in a signature or MAC construction, the AEAD tag, the XOF marker. Scanned
# without a left word-guard because the real spellings run the words together
# (`CHACHA20POLY1305`, `SHA3-256`).
# `shake` and `poly1305` are guarded against a preceding LETTER only, so the digit-glued
# `CHACHA20POLY1305` still carries its tag while `TLS handshake key` no longer contributes
# a `shake` token. `sphincsshake128fsimple` loses the marker under this guard; its SHA-3
# secondary token survives through the grammar's loose form, and no corpus row or vector
# spells the name that way.
SECONDARY_MARKERS = [
    ("poly1305", r"(?<![A-Za-z])POLY1305"),
    ("shake", r"(?<![A-Za-z])SHAKE"),
    ("gcm", r"(?<![A-Za-z0-9])GCM(?![A-Za-z0-9])"),
    ("ccm8", r"CCM[_-]?8(?![0-9])"),
    # A capturing group appends its value to the label, so the DH group NUMBER is
    # identity-bearing: `DH-Group14` merged with bare `DH` because 14 sits below the
    # key-size floor and had nowhere else to go.
    ("dhgroup", r"group[-_ ]?(\d{1,3})"),
    ("ikegroup", r"(?<![A-Za-z0-9])modp[-_ ]?(\d{3,5})"),
]

# CLOSED vocabulary of construction discriminators admitted into the `variant` slot.
# L7: the slot was a free-text residue with 256 distinct values, 186 of them phrases or
# compounds, and it over-split badly — `AES-256-GCM`, `AES-256-GCM (TLS record
# protection)` and `AES/GCM/NoPadding` became three rows for one algorithm. A key must
# admit only closed vocabularies, so the residue is now filtered against this list and
# anything unrecognised is DROPPED from the key and recorded on the row instead.
#
# Every token here is a real construction difference observed in the corpus, not a
# description of one. Adding a token is a ratification act, which is the point.
VARIANT_VOCABULARY = [
    # key wrapping and its padded variant
    "wrap", "wrappad", "pad", "kw", "kwp",
    # modes with no CycloneDX enum value
    "xts", "siv", "ocb", "eax", "gmac", "cmac",
    # extendable output versus fixed digest
    "shake", "xof",
    # parameter-set suffixes that carry the security level
    "s", "f", "ph", "ctx",
    # unix password hashing constructions: `sha512crypt` is not SHA-512
    "crypt", "md5crypt", "bcrypt", "yescrypt",
    # random generation and derivation categories producers emit as algorithm names
    "csprng", "drbg", "prng", "kdf", "prf", "mgf",
    # triple-DES keying option
    "ede", "ede3", "ede2",
    # hybrid and KEM composition markers
    "kem", "hybrid", "prime",
]

# The CycloneDX `padding` enum. Stripped from the variant residue because padding has
# its own field and is not a tuple slot, so a producer naming it (`AES128-CBC-PKCS5`)
# must agree with one that puts it in the field.
PADDING_TOKENS = ["PKCS5", "PKCS7", "PKCS1V15", "PKCS1", "OAEP", "RAW", "PSS", "OTHER"]

# Padding aliases and the sentinel. `PKCS5` and `PKCS7` are the same scheme — PKCS#5 was
# specified for 8-byte blocks and PKCS#7 generalised it, so for every cipher in this
# vocabulary they are identical and splitting on the spelling is wrong. `PKCS1` is the
# short spelling of `PKCS1V15`. `RAW` means "no padding", which is what an omitted field
# also means, so it folds to absent rather than splitting a declaring producer from an
# omitting one — the same lesson the `primitive` slot taught.
# `RAW` deliberately does NOT fold to absent. Folding it was tried and reverted: `RAW`
# is a POSITIVE assertion — "this construction uses no padding" — whereas an absent field
# means "not stated". That is the same distinction the CBOM Profiles review established
# for `other`/`unknown`, and collapsing the two merges a declared-unpadded construction
# with an undisclosed one. The gold corpus pinned it (GOLD-ALG-15) and caught the
# inconsistency.
PADDING_ALIASES = {"PKCS5": "PKCS7", "PKCS1": "PKCS1V15"}

# The mode vocabulary is the CycloneDX `mode` enum minus `unknown`, which is a genuine
# placeholder. `other` STAYS: it is a legal value meaning "a real mode outside this
# list", and stripping it folded such an asset onto one that said nothing at all.
# It is deliberately SEPARATE from the size stoplist: WRAP, KW, KWP, POLY1305 and the
# PKCS paddings all belong in the stoplist so their digits are never read as a key
# size, but none of them is a legal `mode` value. Treating WRAP as a mode split
# `AES-256-WRAP-PAD` from `AES256WrapPad` - the same RFC 5649 algorithm - because the
# word-guarded mode match fires on one spelling and not the other.
MODE_TOKENS = ["GCM", "CBC", "ECB", "CCM", "CFB", "OFB", "CTR", "OTHER"]

# Values that mean "the producer had nothing to say". Treated as absent, because a
# stored sentinel splits the asset from every producer that simply omits the field.
# Ratified 2026-08-19: only genuine placeholders belong here. `none` and `other` were on
# this list and came off — both are legal CycloneDX values that carry meaning, and folding
# them onto "nothing said" throws a claim away: `padding: none` is explicitly unpadded,
# which is the finding an inventory exists to surface, and `mode: other` says the mode is
# real but outside the enum. `N/A` is redundant (it folds onto `n/a`) and `0.0.0.0` is a
# placeholder address, so both stay.
SENTINELS = ["", "unknown", "n/a", "N/A", "-", "0.0.0.0"]

# The 15 primitive values expressible in BOTH 1.6 and 1.7. key-wrap is 1.7-only and
# is deliberately excluded: primitive is in the identity tuple, so defaulting to a
# 1.7-only value would key the same asset differently under the two versions and
# break parity through the primitive slot.
PRIMITIVES_1_6 = [
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
    "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
]

# Per-family primitive defaults, restricted to families whose registry variants all
# agree on one primitive AND whose value is 1.6-expressible. Families with more than
# one primitive get no default: a wrong default is a wrong merge, and an empty slot
# is only a visible split.
PRIMITIVE_DEFAULTS = {
    "RSA": "pke",
    "RSAES-OAEP": "pke",
    "RSAES-PKCS1": "pke",
    "RSASSA-PKCS1": "signature",
    "RSASSA-PSS": "signature",
    "ECDSA": "signature",
    "EdDSA": "signature",
    "DSA": "signature",
    "ML-DSA": "signature",
    "SLH-DSA": "signature",
    "XMSS": "signature",
    "LMS": "signature",
    "ECDH": "key-agree",
    "FFDH": "key-agree",
    "EC": "key-agree",
    "ML-KEM": "kem",
    "SHA-1": "hash",
    "SHA-2": "hash",
    "MD2": "hash",
    "MD4": "hash",
    "MD5": "hash",
    "RIPEMD": "hash",
    "Skipjack": "block-cipher",
    "SP800-56C": "kdf",
    "Fernet": "ae",
    "BLAKE3": "hash",
    "HMAC": "mac",
    "CMAC": "mac",
    "Poly1305": "mac",
    "HKDF": "kdf",
    "PBKDF2": "kdf",
    "scrypt": "kdf",
    "yescrypt": "kdf",
    "Argon2": "kdf",
    "DES": "block-cipher",
    "3DES": "block-cipher",
    "CAMELLIA": "block-cipher",
    "ARIA": "block-cipher",
    "SEED": "block-cipher",
    "RC4": "stream-cipher",
    "ChaCha20": "stream-cipher",
    "ECIES": "pke",
    # Families whose registry variants disagree about the primitive still get a
    # default, because `primitive` is back in the identity tuple and a missing value
    # splits an omitting producer from a declaring one. The value chosen is the
    # registry's first-declared variant primitive for the family. This is a
    # deliberate normalization choice, not a claim of precision: where the
    # distinction matters it is already carried by `mode` (AES-CBC vs AES-GCM) or by
    # `variant` (SHA3-256 vs SHAKE-256).
    "AES": "block-cipher",
    "SHA-3": "hash",
    "BLAKE2": "hash",
    "GOST": "block-cipher",
    "SM2": "signature",
    "SM3": "hash",
    "SM4": "block-cipher",
    "SM9": "signature",
    "Salsa20": "stream-cipher",
    "Ascon": "ae",
    "MILENAGE": "mac",
    "TUAK": "mac",
    "ZUC": "stream-cipher",
    "SNOW3G": "stream-cipher",
    "3GPP-XOR": "stream-cipher",
    "PBES1": "other",
    "PBES2": "other",
    "PBMAC1": "mac",
    "RSA-X931": "signature",
    "bcrypt": "kdf",
    "RC2": "block-cipher", "RC5": "block-cipher", "RC6": "block-cipher",
    "MQV": "key-agree",
    "Blowfish": "block-cipher", "Twofish": "block-cipher", "Serpent": "block-cipher",
    "IDEA": "block-cipher", "CAST5": "block-cipher", "CAST6": "block-cipher",
    "Whirlpool": "hash", "ElGamal": "pke", "PBKDF1": "kdf",
    # PQC candidates. `kem` or `signature` per the family's actual role; the two
    # broken ones keep their role because the inventory must still classify them.
    "Kyber": "kem", "FrodoKEM": "kem", "Classic McEliece": "kem", "BIKE": "kem",
    "HQC": "kem", "NTRU": "kem", "NTRU-Prime": "kem", "SIKE": "kem", "X-Wing": "kem",
    "Dilithium": "signature", "Falcon": "signature", "SPHINCS+": "signature",
    "CROSS": "signature", "MQOM": "signature", "SNOVA": "signature", "UOV": "signature",
    "QR-UOV": "signature", "MAYO": "signature", "GeMSS": "signature",
    "Rainbow": "signature", "Picnic": "signature", "SQIsign": "signature",
    "HAWK": "signature", "Raccoon": "signature", "AIMer": "signature",
    "PERK": "signature", "RYDE": "signature", "MIRATH": "signature", "LESS": "signature",
}

# Both tables below were knowledge in the reference kernel rather than data until 2026-08-20:
# a third implementation could derive neither Ed448 = 456 nor Curve448 = 448 from any published
# artifact, and no artifact carried the attribute-name-to-OID map at all.
NAME_INTRINSIC_SIZES = {
    "ed25519": 256,
    "x25519": 256,
    "curve25519": 256,
    "ed448": 456,
    "x448": 448,
    "curve448": 448,
}

DN_SHORT_NAMES = {
    "cn": "2.5.4.3",
    "sn": "2.5.4.4",
    "serialnumber": "2.5.4.5",
    "c": "2.5.4.6",
    "l": "2.5.4.7",
    "st": "2.5.4.8",
    "street": "2.5.4.9",
    "o": "2.5.4.10",
    "ou": "2.5.4.11",
    "title": "2.5.4.12",
    "businesscategory": "2.5.4.15",
    "postalcode": "2.5.4.17",
    "name": "2.5.4.41",
    "pseudonym": "2.5.4.65",
    "organizationidentifier": "2.5.4.97",
    "dnqualifier": "2.5.4.46",
    "description": "2.5.4.13",
    "givenname": "2.5.4.42",
    "initials": "2.5.4.43",
    "generationqualifier": "2.5.4.44",
    "uniqueidentifier": "2.5.4.45",
    "dc": "0.9.2342.19200300.100.1.25",
    "uid": "0.9.2342.19200300.100.1.1",
    "e": "1.2.840.113549.1.9.1",
    "emailaddress": "1.2.840.113549.1.9.1",
    "mail": "0.9.2342.19200300.100.1.3",
    "commonname": "2.5.4.3",
    "surname": "2.5.4.4",
    "countryname": "2.5.4.6",
    "localityname": "2.5.4.7",
    "stateorprovincename": "2.5.4.8",
    "streetaddress": "2.5.4.9",
    "organizationname": "2.5.4.10",
    "organizationalunitname": "2.5.4.11",
    "domaincomponent": "0.9.2342.19200300.100.1.25",
    "userid": "0.9.2342.19200300.100.1.1",
    "distinguishednamequalifier": "2.5.4.46",
    "organizationidentifiername": "2.5.4.97",
}

# WITHDRAWN. A curated arc->variant-label table was tried and refuted: it made an
# asset key differently depending on whether its producer supplied the arc at all
# (`AES-256-WRAP` with and without 2.16.840.1.101.3.4.1.45). The variant residue must
# be derivable from the name alone, because the name is the one channel every producer
# populates. Kept here as a record of the rejected option.
_WITHDRAWN_OID_VARIANT_LABELS = {
    "2.16.840.1.101.3.4.2.5": "sha512-224",
    "2.16.840.1.101.3.4.2.6": "sha512-256",
    "2.16.840.1.101.3.4.1.5": "wrap",
    "2.16.840.1.101.3.4.1.8": "wrap-pad",
    "2.16.840.1.101.3.4.1.25": "wrap",
    "2.16.840.1.101.3.4.1.28": "wrap-pad",
    "2.16.840.1.101.3.4.1.45": "wrap",
    "2.16.840.1.101.3.4.1.48": "wrap-pad",
    "2.16.840.1.101.3.4.2.17": "shake128",
    "2.16.840.1.101.3.4.2.18": "shake256",
}


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """``json.load`` keeps the last of two equal keys and says nothing. In these inputs a
    repeated OID or alias silently replaces a ratified row, and the diff of the emitted table
    then shows an addition where a family was actually swapped."""
    mapping: dict = {}
    for key, value in pairs:
        if key in mapping:
            raise SystemExit(f"duplicate key {key!r} in a JSON input; every key is a ratified row")
        mapping[key] = value
    return mapping


def load_json(path: pathlib.Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=reject_duplicate_keys)


def load_registry() -> dict:
    return load_json(REGISTRY)


# Curve spellings the registry does not list in bare form but producers write anyway.
# Emitted rather than held in Java: this set decides which digit runs the parameter-set
# parser may read, so a change to it is key-affecting. Held in code it moved keys without
# moving the artifact, which left both guards -- the CI byte-diff and the two pinned
# hashes -- unable to see it. The order is ratified and is deliberately not sorted.
EXTRA_CURVE_SPELLINGS = [
    "P-224", "P-256", "P-384", "P-521", "P-192",
    "nistp256", "nistp384", "nistp521",
    "x25519", "x448", "ed25519", "ed448",
    "curve25519", "curve448", "prime256v1",
]

def curve_equivalence(registry: dict) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Fold the 246 registry curve tokens onto one representative per real curve.

    The registry names the same physical curve up to three times (nist/P-256,
    secg/secp256r1, x962/prime256v1 all carry OID 1.2.840.10045.3.1.7) and declares
    the equivalence itself via a symmetric `aliases` relation. Union-find over
    aliases plus shared OID recovers the real classes; the authority priority elects
    the stored representative.
    """
    tokens: dict[str, dict] = {}
    for group in registry["ellipticCurves"]:
        for curve in group["curves"]:
            tokens[f"{group['name']}/{curve['name']}"] = curve

    lowered = {token.lower(): token for token in tokens}
    parent = {token: token for token in tokens}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for token, curve in tokens.items():
        # Case-insensitive: the registry references nist/k-163 while the token is
        # nist/K-163. A case-sensitive match silently loses that edge and K-163
        # splits.
        for alias in curve.get("aliases") or []:
            key = f"{alias['category']}/{alias['name']}".lower()
            if key in lowered:
                union(token, lowered[key])

    by_oid: dict[str, list[str]] = collections.defaultdict(list)
    for token, curve in tokens.items():
        if curve.get("oid"):
            by_oid[curve["oid"]].append(token)
    for members in by_oid.values():
        for other in members[1:]:
            union(members[0], other)

    def rank(token: str) -> tuple[int, str]:
        authority = token.split("/", 1)[0]  # FIRST slash: mnt/mnt2/1 is 3 segments
        index = AUTHORITY_PRIORITY.index(authority) if authority in AUTHORITY_PRIORITY \
            else len(AUTHORITY_PRIORITY)
        return index, token

    classes: dict[str, list[str]] = collections.defaultdict(list)
    for token in tokens:
        classes[find(token)].append(token)

    canonical: dict[str, str] = {}
    multi: dict[str, list[str]] = {}
    for members in classes.values():
        representative = sorted(members, key=rank)[0]
        for member in members:
            canonical[member] = representative
        if len(members) > 1:
            multi[representative] = sorted(members)
    return canonical, multi


def curve_aliases(registry: dict, canonical: dict[str, str]) -> dict[str, str]:
    """Producer spellings -> canonical token.

    Keys are the bare forms producers actually write (`P-256`, `secp256r1`,
    `prime256v1`, `nistp256`, `Ed25519`, `x25519`), not the namespaced registry
    tokens, because producers overwhelmingly write the bare form. Namespaced values do
    occur -- 37 of them across 17 corpus documents, from sbom-tools, sbomify and
    ClaveQuantum as well as cbom-lens -- and one of them, sbomify's `nist/P-384`, is not
    even the canonical authority, so the alias table has to fold namespaced spellings too
    rather than assume they arrive canonical.
    """
    aliases: dict[str, str] = {}

    def offer(spelling: str, token: str) -> None:
        if spelling and token in canonical:
            aliases.setdefault(spelling, canonical[token])

    for group in registry["ellipticCurves"]:
        for curve in group["curves"]:
            token = f"{group['name']}/{curve['name']}"
            offer(token, token)
            offer(curve["name"], token)
            for alias in curve.get("aliases") or []:
                offer(alias["name"], token)
                offer(f"{alias['category']}/{alias['name']}", token)

    # Spellings the registry does not carry but producers do. cbom-lens's own
    # curveField17 / paramSet17 tables are the source for the SSH and TLS forms.
    for spelling, token in {
        "nistp256": "secg/secp256r1",
        "nistp384": "secg/secp384r1",
        "nistp521": "secg/secp521r1",
        "ecdh_x25519": "other/Curve25519",
        "ecdh_x448": "other/Curve448",
        "x25519": "other/Curve25519",
        "x448": "other/Curve448",
        "curve25519": "other/Curve25519",
        "curve448": "other/Curve448",
        "ed25519": "other/Ed25519",
        "ed448": "other/Ed448",
        "edwards25519": "other/Ed25519",
        "edwards448": "other/Ed448",
        "brainpoolP256r1tls13": "brainpool/brainpoolP256r1",
        "brainpoolP384r1tls13": "brainpool/brainpoolP384r1",
        "brainpoolP512r1tls13": "brainpool/brainpoolP512r1",
    }.items():
        offer(spelling, token)
    return aliases


# ``AsciiText.PYTHON_WHITESPACE`` and ``LOOKUP_SEPARATORS``, character for character. The alias
# table is folded through Java's ``lookupKey`` into a ``HashMap`` where the last writer wins,
# while ``offer`` above keeps the first spelling -- so two spellings the fold makes equal can
# disagree here without disagreeing in Python, and only a fold-faithful check can see it.
JAVA_LOOKUP_SEPARATORS = re.compile(
    "[ \t\n\u000B\f\r\u001C\u001D\u001E\u001F\u0085\u00A0"
    "\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029"
    "\u202F\u205F\u3000_\\-/]+")


def java_lookup_key(text: str) -> str:
    """``AsciiText.lookupKey``: drop separators, then lower-case ASCII letters only."""
    stripped = JAVA_LOOKUP_SEPARATORS.sub("", text)
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in stripped)


def alias_fold_collisions(aliases: dict[str, str], canonical: dict[str, str]) -> list[str]:
    """Alias spellings Java would fold onto one key with two different targets, plus any alias
    whose fold equals another class's representative -- either re-targets a curve with exit 0."""
    targets: dict[str, set[str]] = collections.defaultdict(set)
    for spelling, token in aliases.items():
        targets[java_lookup_key(spelling)].add(token)
    collisions = [f"{key} -> {sorted(tokens)}" for key, tokens in sorted(targets.items()) if len(tokens) > 1]

    representatives: dict[str, str] = {}
    for representative in set(canonical.values()):
        for spelling in (representative, representative.split("/", 1)[1]):
            representatives[java_lookup_key(spelling)] = representative
    for spelling, token in sorted(aliases.items()):
        owner = representatives.get(java_lookup_key(spelling))
        if owner is not None and owner != token:
            collisions.append(f"alias {spelling!r} -> {token} folds onto representative {owner}")
    return collisions


# The `(?` openers that Python `re` and `java.util.regex` define identically. Every other opener
# is one engine's own -- `(?P<n>`, `(?P=n)`, `(?#`, `(?(1)` and the `a`/`L`/`u` flags on the
# Python side -- and Java is the engine that compiles the shipped table. An unescaped `{` is
# refused unless it opens a well-formed `{n}`, `{n,}` or `{n,m}`: Python reads `AES{`, `x{a}` and
# `a{1,2` as literals and `{,n}` as `{0,n}`, and Java rejects all four with "Illegal repetition"
# -- the one error class the `re.compile` pass below cannot see. A literal brace is spelled `\{`
# (both engines), and a brace inside a character class is refused with the rest, fail-closed.
NON_PORTABLE_REGEX = re.compile(
    r"\\(?P<escape>.)|(?P<opener>\(\?(?!:|=|!|<=|<!))|(?P<brace>\{(?!\d+(?:,\d*)?\}))")

# The alphanumeric escapes both engines define identically; every other one is refused. An
# allowlist, because the denylist it replaced named `\A` and `\Z` and waved the rest through:
# `\0` is a null byte to Python and "Illegal octal escape" to Java, so it reached the artifact with
# exit 0 and killed every crypto asset at startup; `\v` is U+000B to Python and a vertical-whitespace
# class to Java, so both compiled and the two automata disagreed with nothing red anywhere. `\Z`
# admits a trailing terminator in Java and not in Python, `\A` goes with it, and `\1`..`\9` are
# back-references no table uses. `\x` and `\u` are here because `\xhh` and `\uhhhh` read alike in
# both and the guard-separator class is spelled with them. `\s`, `\d` and `\b` are NOT refused:
# both engines accept them, and where their meanings differ at the edges that is a key-moving
# decision the tables already carry. What Python cannot compile (`\h`, `\R`, `\z`, `\Q`, `\p{..}`,
# `\cA`) never reaches this list.
PORTABLE_ESCAPES = frozenset("dDsSwWbBntrfaxu")


def non_portable_constructs(pattern: str) -> list[str]:
    found = []
    for token in NON_PORTABLE_REGEX.finditer(pattern):
        escape = token.group("escape")
        if escape is not None:
            if escape.isalnum() and escape not in PORTABLE_ESCAPES:
                found.append("\\" + escape)
        else:
            found.append(pattern[token.start():token.start() + 3])
    found.extend(nested_character_classes(pattern))
    return found


def nested_character_classes(pattern: str) -> list[str]:
    """An unescaped `[` inside a character class. Java reads `[a-d[m-p]]` as a union and Python as the
    class `a-d[m-p` followed by a literal `]`, and Python warns about only the `[[`, `--`, `&&` and
    `~~` spellings -- so both engines compiled the shape and keyed a name differently. Refused with
    the rest, fail-closed, as the brace inside a class already is."""
    found = []
    opened_at = -1
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            index += 2
            continue
        if opened_at < 0:
            if character == "[":
                opened_at = index
        elif character == "[":
            found.append(pattern[opened_at:index + 1])
        elif character == "]" and index > opened_at + 1 and pattern[opened_at + 1:index] != "^":
            opened_at = -1
        index += 1
    return found


# The screen is proven able to fail before it judges the tables: a witness it should refuse that it
# accepts, or one it should accept that it refuses, fails the run like any other offender.
SCREEN_MUST_REFUSE = [r"AES\0", r"[\0]", r"AES\v", r"[a-d[m-p]]RC4", r"x\Z", r"\Ax", r"(?P<n>x)",
                      r"x{,3}", r"(x)\1"]
SCREEN_MUST_ACCEPT = [r"\d\s\b\w", r"[\x0B\u2028\xA0]*R?", r"(?<![A-Za-z0-9])AES(?![A-Za-z0-9])",
                      r"a{1,2}\.\-\(", r"[^]a]", r"(?:ake)?with"]


def screen_self_check() -> list[str]:
    offenders = [f"accepted {pattern!r}" for pattern in SCREEN_MUST_REFUSE if not non_portable_constructs(pattern)]
    offenders += [f"refused {pattern!r}: {non_portable_constructs(pattern)}" for pattern in SCREEN_MUST_ACCEPT
                  if non_portable_constructs(pattern)]
    return offenders


def unloadable_patterns(labelled: list[tuple[str, str]]) -> list[str]:
    """Patterns Java could not compile, or would compile to a different automaton.

    Java compiles every one of these in ``IdentityTables.load()``, so an unbalanced group written
    here reached the committed table with exit 0 and surfaced as a ``PatternSyntaxException`` in
    every identity test. Python's nested-set ``FutureWarning`` (``[[``, ``&&``, ``--`` inside a
    class) is promoted to an error: Java reads those as set operations and Python as literals.

    Compiled under ``re.ASCII`` as well as ``re.IGNORECASE``, because the flags have to match the
    engine that runs the table: Java's ``CASE_INSENSITIVE`` folds ASCII only unless
    ``UNICODE_CASE`` is set with it, and its ``\\s`` and ``\\d`` are ASCII, while Python's defaults
    are Unicode-aware for both. Compiling under Python's wider semantics would accept a pattern on
    terms Java never applies.

    What this establishes is that both engines *accept* the construct, not that they *match* the
    same strings -- the shorthands this deliberately permits still differ at the edges. A claim
    about matching needs behavioural vectors run under both engines, which the identity vectors
    give for the chain and nothing yet gives for the table's own patterns.
    """
    problems = []
    for label, pattern in labelled:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                re.compile(pattern, re.ASCII | re.IGNORECASE)
        except (re.error, Warning) as failure:
            problems.append(f"{label}: {pattern!r} does not compile: {failure}")
            continue
        foreign = non_portable_constructs(pattern)
        if foreign:
            problems.append(f"{label}: {pattern!r} uses {foreign}, which java.util.regex reads differently")
    return problems


def emitted_patterns() -> list[tuple[str, str]]:
    labelled = [(f"nameGrammar[{i}] {rule['family']}", rule["pattern"]) for i, rule in enumerate(NAME_GRAMMAR)]
    labelled += [(f"cipherSuiteNamePatterns[{i}]", p) for i, p in enumerate(CIPHER_SUITE_NAME_PATTERNS)]
    labelled += [(f"secondaryMarkers[{label}]", p) for label, p in SECONDARY_MARKERS]
    return labelled


OID_ARC = re.compile(r"[0-9]+(\.[0-9]+)+")


def strand_offenders(oid_strand: dict, canonical: dict[str, str], aliases: dict[str, str]) -> list[str]:
    """Enrichment the loader would accept and the pipeline would then key on unexamined.

    The family column has been checked against the vocabulary since the first cut; the other three
    enrichment columns were not, and one entry shipped ``"mode": "POLY1305"`` -- a value outside the
    ``modeTokens`` the same artifact declares, which the Java side wrote into the mode slot verbatim
    while a name-derived mode goes through that vocabulary. So a ChaCha20-Poly1305 asset keyed one way
    with the CMS arc and another without it. Every column an arc may contribute is held to the
    vocabulary its slot is keyed on, the arcs themselves to the dotted shape the loader walks, and a
    blocked prefix to having an entry beneath it, since a mistyped prefix blocks nothing and says so
    nowhere."""
    offenders = []
    modes = {m.upper() for m in MODE_TOKENS}
    curves = set(canonical) | set(canonical.values())
    entries = oid_strand["oidToFamily"]
    for oid, entry in entries.items():
        if not OID_ARC.fullmatch(oid):
            offenders.append(f"{oid}: not a dotted arc")
        mode = entry.get("mode")
        if mode is not None and mode.upper() not in modes:
            offenders.append(f"{oid}: mode {mode!r} is not a modeTokens value")
        curve = entry.get("curve")
        if curve is not None and curve not in curves and java_lookup_key(curve) not in {
                java_lookup_key(a) for a in aliases}:
            offenders.append(f"{oid}: curve {curve!r} is not a registry curve or alias")
        primitive = entry.get("primitive")
        if primitive is not None and primitive not in PRIMITIVES_1_6:
            offenders.append(f"{oid}: primitive {primitive!r} is not expressible in CycloneDX 1.6")
    seen = set()
    for blocked in oid_strand["blockedPrefixes"]:
        prefix = blocked["prefix"]
        if not OID_ARC.fullmatch(prefix):
            offenders.append(f"blocked prefix {prefix!r}: not a dotted arc")
        elif prefix in seen:
            offenders.append(f"blocked prefix {prefix!r}: listed twice")
        elif not any(oid.startswith(prefix + ".") for oid in entries):
            offenders.append(f"blocked prefix {prefix!r}: no table entry beneath it, so it blocks nothing")
        seen.add(prefix)
    return offenders


def blank_oid_families(oid_to_family: dict[str, dict]) -> list[str]:
    """A family of ``""`` or whitespace is not "no family": Java's ``text()`` hands it to
    ``setFamily`` unguarded and the row keys ``ALG||size||||`` instead of taking the name tier.
    ``null`` and an absent key are the ratified spellings of "the arc says nothing"."""
    return sorted(
        f"{oid}: {entry['family']!r}" for oid, entry in oid_to_family.items()
        if isinstance(entry.get("family"), str) and not entry["family"].strip())


# The shape of every top-level table, in the terms the Java loader reads it: ``str``,
# ``int``, ``str?``/``int?`` for a nullable value, ``[shape]`` for an array whose every
# element has that shape, and a dict for an object with named fields (``...`` allows other
# fields, each of which must still be ``str``).
#
# Declared per table rather than inferred from the emitted values, and a table with no
# declaration fails the check. Two weaker attempts came first and each missed something a
# reader would have to know to notice: a list of the tables to check omitted four tables and
# named one the loader never reads, and a leaf walk could not see a wrong-typed *container* at
# all -- neither ``{"paddingAliases": {"PKCS5": {}}}`` nor ``{"modeTokens": [[]]}`` -- because
# an empty list is a legitimate value here (31 ``pseudoFamilies`` entries are one).
TABLE_SHAPES = {
    "$comment": "str",
    "specId": "str",
    "registrySnapshot": {"familiesInData": "int", "familiesInShippedEnum": "int",
                         "curveTokens": "int", "curveClasses": "int",
                         "familiesDataOnly": ["str"], "...": True},
    "algorithmFamilies": ["str"],
    "pseudoFamilies": {"*": ["str"]},
    "ellipticCurves": ["str"],
    "curveCanonical": {"*": "str"},
    "curveClasses": {"*": ["str"]},
    "curveAliases": {"*": "str"},
    "extraCurveSpellings": ["str"],
    "oidToFamily": {"*": {"family": "str?", "curve": "str?", "mode": "str?",
                          "primitive": "str?", "parameterSet": "int?", "...": True}},
    "oidBlockedPrefixes": ["str"],
    "nameGrammar": [{"...": True}],
    "sizeStoplist": ["str"],
    "modeTokens": ["str"],
    "cipherSuiteNamePatterns": ["str"],
    "secondaryMarkers": [["str"]],
    "paddingTokens": ["str"],
    "paddingAliases": {"*": "str"},
    "variantVocabulary": ["str"],
    "variantSynonyms": {"*": "str"},
    "truncatableFamilies": ["str"],
    "sizeWhitelist": {"min": "int", "max": "int"},
    "sentinels": ["str"],
    "primitiveDefaults": {"*": "str"},
    "primitivesExpressibleIn16": ["str"],
    "nameIntrinsicSizes": {"*": "int"},
    "dnShortNames": {"*": "str"},
}

_SCALARS = {"str": str, "int": int}


def _shape_offenders(value: object, shape: object, path: str) -> list[str]:
    """Where ``value`` departs from ``shape``, named by the path that reached it."""
    if isinstance(shape, str):
        wanted = _SCALARS[shape.rstrip("?")]
        if shape.endswith("?") and value is None:
            return []
        # bool before int: Python's bool subclasses int, so `true` would pass an int slot here
        # while Jackson's `canConvertToInt` refuses it.
        if isinstance(value, bool) or not isinstance(value, wanted):
            return [f"{path}: {value!r} is {type(value).__name__}, wanted {shape}"]
        return []
    if isinstance(shape, list):
        if not isinstance(value, (list, tuple)):
            return [f"{path}: {type(value).__name__}, wanted an array"]
        return [o for i, v in enumerate(value)
                for o in _shape_offenders(v, shape[0], f"{path}[{i}]")]
    if not isinstance(value, dict):
        return [f"{path}: {type(value).__name__}, wanted an object"]
    offenders = []
    for key, member in value.items():
        member_shape = shape.get(key, shape.get("*", "str" if shape.get("...") else None))
        if member_shape is None:
            offenders.append(f"{path}.{key}: not a declared member")
        else:
            offenders.extend(_shape_offenders(member, member_shape, f"{path}.{key}"))
    return offenders


def non_string_table_values(tables: dict) -> list[str]:
    """Every table's shape, checked against what the loader will read, before anything is written.

    Java refuses a wrong node type, but a JSON ``null`` used to pass as a Java ``null``: a
    ``"paddingAliases": {"PKCS5": null}`` loaded, and the padding spelling it names then keyed
    with no canonical form instead of failing the load. The loader is strict now, so emitting
    such a table breaks every asset at startup -- a worse way to learn it than this line.

    Checked over the JSON round trip, not the Python objects, so what is judged is what lands
    on disk: a tuple and a list are one shape there, and only there."""
    artifact = json.loads(json.dumps(tables))
    offenders = [f"{name}: emitted but undeclared, so its shape is unchecked"
                 for name in artifact if name not in TABLE_SHAPES]
    offenders.extend(f"{name}: declared but not emitted" for name in TABLE_SHAPES
                     if name not in artifact)
    for name, shape in TABLE_SHAPES.items():
        if name in artifact:
            offenders.extend(_shape_offenders(artifact[name], shape, name))
    return sorted(offenders)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT,
                        help="where to write identity-tables.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = load_registry()
    canonical, multi = curve_equivalence(registry)
    aliases = curve_aliases(registry, canonical)

    schema = load_json(DEFS_SCHEMA)
    enum_families = schema["definitions"]["algorithmFamiliesEnum"]["enum"]
    data_families = [entry["family"] for entry in registry["algorithms"]]

    oid_strand = load_json(OID_STRAND)

    legal = set(enum_families) | set(data_families) | set(PSEUDO_FAMILIES)
    bad_grammar = sorted({r["family"] for r in NAME_GRAMMAR} - legal)
    bad_defaults = sorted(set(PRIMITIVE_DEFAULTS) - legal)
    bad_primitives = sorted(set(PRIMITIVE_DEFAULTS.values()) - set(PRIMITIVES_1_6))
    bad_oid = sorted({
        e["family"] for e in oid_strand["oidToFamily"].values() if e.get("family") is not None
    } - legal)

    tables = {
        "$comment": "Ratified identity + normalization decision tables for core#2070.",
        "specId": "otilm-crypto-identity-1",
        "registrySnapshot": {
            "source": "CycloneDX cryptography-defs.json",
            # `lastUpdated` is the registry's own last declared revision, which upstream stopped
            # advancing; the commit is the provenance. Both are stated so neither is read as the other.
            "upstreamCommit": REGISTRY_UPSTREAM_COMMIT,
            "lastUpdated": registry.get("lastUpdated"),
            "familiesInData": len(data_families),
            "familiesInShippedEnum": len(enum_families),
            "familiesDataOnly": sorted(set(data_families) - set(enum_families)),
            "curveTokens": len(canonical),
            "curveClasses": len(set(canonical.values())),
        },
        "algorithmFamilies": sorted(legal),
        "pseudoFamilies": PSEUDO_FAMILIES,
        "ellipticCurves": sorted(set(canonical.values())),
        "curveCanonical": canonical,
        "curveClasses": multi,
        "curveAliases": aliases,
        "extraCurveSpellings": EXTRA_CURVE_SPELLINGS,
        "oidToFamily": oid_strand["oidToFamily"],
        "oidBlockedPrefixes": [b["prefix"] for b in oid_strand["blockedPrefixes"]],
        "nameGrammar": NAME_GRAMMAR,
        "sizeStoplist": SIZE_STOPLIST,
        "modeTokens": MODE_TOKENS,
        "cipherSuiteNamePatterns": CIPHER_SUITE_NAME_PATTERNS,
        "secondaryMarkers": SECONDARY_MARKERS,
        "paddingTokens": PADDING_TOKENS,
        "paddingAliases": PADDING_ALIASES,
        "variantVocabulary": VARIANT_VOCABULARY,
        "variantSynonyms": VARIANT_SYNONYMS,
        "truncatableFamilies": TRUNCATABLE_FAMILIES,
        "sizeWhitelist": {"min": 64, "max": 16384},
        "sentinels": SENTINELS,
        "primitiveDefaults": PRIMITIVE_DEFAULTS,
        "primitivesExpressibleIn16": PRIMITIVES_1_6,
        "nameIntrinsicSizes": NAME_INTRINSIC_SIZES,
        "dnShortNames": DN_SHORT_NAMES,
    }

    print(f"  families legal        : {len(legal)} "
          f"(enum {len(enum_families)}, data {len(data_families)}, pseudo {len(PSEUDO_FAMILIES)})")
    print(f"  data-only families    : {tables['registrySnapshot']['familiesDataOnly']}")
    print(f"  curve tokens -> classes: {len(canonical)} -> {len(set(canonical.values()))}")
    print(f"  curve aliases         : {len(aliases)}")
    print(f"  oid entries / blocked : {len(tables['oidToFamily'])} / {len(tables['oidBlockedPrefixes'])}")
    print(f"  grammar rules         : {len(NAME_GRAMMAR)}")
    print(f"  primitive defaults    : {len(PRIMITIVE_DEFAULTS)}")
    # Closed-vocabulary tokens must be printable ASCII. Measured: all 129 families, 197
    # curves, 8 modes, 8 padding tokens and 41 stoplist tokens already are, so this
    # asserts an existing property rather than imposing a new one — and it means the
    # lookup path never needs a Unicode-dependent case operation.
    vocab_checks = {
        "algorithmFamilies": tables["algorithmFamilies"],
        "ellipticCurves": tables["ellipticCurves"],
        "modeTokens": MODE_TOKENS,
        "paddingTokens": PADDING_TOKENS,
        "paddingAliases": PADDING_ALIASES,
        "variantVocabulary": VARIANT_VOCABULARY,
        "sizeStoplist": SIZE_STOPLIST,
        "primitiveDefaults": list(PRIMITIVE_DEFAULTS) + list(PRIMITIVE_DEFAULTS.values()),
    }
    non_ascii = {
        name: [t for t in values if not all(32 <= ord(c) <= 126 for c in t)]
        for name, values in vocab_checks.items()
    }
    non_ascii = {k: v for k, v in non_ascii.items() if v}
    print(f"  non-ASCII vocabulary tokens : {non_ascii if non_ascii else 'none'}")
    if non_ascii:
        raise SystemExit(
            "closed-vocabulary tokens must be printable ASCII so the lookup path needs "
            f"no Unicode-dependent case operation; offenders: {non_ascii}")

    reachable = ({r["family"] for r in NAME_GRAMMAR}
                 | {e["family"] for e in tables["oidToFamily"].values() if e.get("family") is not None})
    missing_defaults = sorted(reachable - set(PRIMITIVE_DEFAULTS))
    # Every one of these fails the run, not just the last. Printing four of them and
    # exiting on the fifth meant an illegal grammar family, an illegal primitive default,
    # an illegal OID family or a primitive outside the 1.6 set all reported themselves
    # and then landed in the committed table anyway -- the self-check announced the
    # defect it was letting through.
    invalid = {
        "grammar": bad_grammar,
        "primitiveDefaults": bad_defaults,
        "oidToFamily": bad_oid,
        "oidToFamily-blank": blank_oid_families(tables["oidToFamily"]),
        "oidToFamily-enrichment": strand_offenders(oid_strand, canonical, aliases),
        "primitiveValues": bad_primitives,
        "reachable-without-default": missing_defaults,
        "patterns": unloadable_patterns(emitted_patterns()),
        "patterns-screen-self-check": screen_self_check(),
        "curveAliases-fold": alias_fold_collisions(aliases, canonical),
        "value-shape": non_string_table_values(tables),
    }
    for label, bad in invalid.items():
        print(f"  ILLEGAL in {label:26}: {bad if bad else 'none'}")
    offenders = {label: bad for label, bad in invalid.items() if bad}
    if offenders:
        raise SystemExit(
            "every family the grammar or the OID table can yield must be legal, spelled "
            "the way the family lookup spells it, and carry a primitive default in the "
            "1.6 set; every emitted pattern must compile the same way under java.util.regex; "
            "no two curve aliases may fold onto one lookup key; and every table the loader reads "
            f"as text must hold text; offenders: {offenders}")

    # Written only now. Opening the output before these checks truncated the committed
    # table on the way in, so a run that then exited non-zero had already replaced a good
    # artifact with a bad one -- and the documented guarantee is that it checks before it
    # writes.
    out = args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n": the byte-diff and the two pinned hashes are over LF bytes, and the default
    # would write CRLF on Windows.
    # indent=2 and a final newline are what `.editorconfig` asks of every JSON file here, so an
    # editorconfig-aware save of the artifact reproduces the generator's bytes instead of moving
    # the SHA pin and failing the drift gate.
    with out.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(tables, handle, indent=2, sort_keys=False, ensure_ascii=False)
        handle.write("\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

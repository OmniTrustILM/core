package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Replaces inlined key material with the contracted redaction envelope, in one pass, before anything else reads the
 * payload.
 *
 * <p>
 * <b>Ordering is the whole security property.</b> The digest is computed and the plaintext dropped before identity,
 * persistence, logging or metrics can observe the payload. The identity digest is carried out-of-band on the result so
 * the material identity chain can use it without any caller ever holding the plaintext. The stored payload carries no
 * digest, and the caller's input is never mutated.
 *
 * <p>
 * The value is hashed verbatim -- no base64 decode, no trim. Normalizing first would make identity depend on the
 * normalizer.
 */
public final class MaterialRedaction {

    /**
     * Material types whose plaintext is high-entropy by construction, so that publishing {@code sha256(value)}
     * discloses nothing: the CycloneDX vocabulary minus every entry a person could have typed.
     *
     * <p>
     * An allowlist, matched exactly on the lookup key, because the type vocabulary is open on the producer's side. The
     * predecessor was a denylist of five spellings -- {@code password}, {@code token}, {@code credential},
     * {@code other}, {@code unknown} -- and failed open on every other low-entropy spelling: {@code passphrase},
     * {@code pin}, {@code api-key}, {@code jwt}, {@code session-token} and {@code secret} each published an unsalted
     * SHA-256 of the value and kept the producer's own digest of it in the stored payload, with no finding raised. An
     * unsalted digest of a four-digit PIN is reversible in microseconds. A spelling outside this set is the case the
     * old set's Javadoc already described for {@code other} and {@code unknown} -- the platform cannot know what the
     * producer put there -- and it now takes the same branch they did.
     *
     * <p>
     * {@code additional-data} is deliberately absent: authenticated associated data is arbitrary producer content, not
     * material of any entropy. The 2026-08-18 corpus carries {@code symmetric-key} and {@code key-pair} on six rows,
     * spellings neither schema defines; they fail closed here, costing a withheld digest nothing reads and a finding.
     */
    private static final Set<String> HIGH_ENTROPY_TYPES = Set
            .of("privatekey", "publickey", "secretkey", "key", "ciphertext", "signature", "digest",
                    "initializationvector", "nonce", "seed", "salt", "sharedsecret", "tag");

    /**
     * Types that should never carry an inlined value at all, as lookup keys. A producer that does so has exfiltrated
     * key material into a document the platform then aggregates estate-wide, so it is raised as an ingest finding
     * rather than silently redacted.
     *
     * <p>
     * Compared through {@link AsciiText#lookupKey}, like every other producer-type comparison in this package, because
     * the hyphenated spellings need a separator drop: folding case alone raised the finding on {@code private-key} and
     * on {@code Private-Key} and lost it on {@code privateKey}, {@code private_key} and {@code PRIVATE KEY} -- the
     * camel-case and underscore spellings a JCA-call scanner emits. Not key-moving, since no keyed value reads this
     * set.
     */
    private static final Set<String> SECRET_TYPES = Set
            .of("privatekey", "secretkey", "sharedsecret", "password", "credential", "token", "seed", "key");

    private final ObjectNode keyedPayload;
    private final ObjectNode storedPayload;
    private final String materialType;
    private final String identityDigest;
    private final String publishedDigest;
    private final Integer valueLength;
    private final List<String> findings;

    private MaterialRedaction(ObjectNode keyedPayload, ObjectNode storedPayload, String materialType,
            String identityDigest, String publishedDigest, Integer valueLength, List<String> findings) {
        this.keyedPayload = keyedPayload;
        this.storedPayload = storedPayload;
        this.materialType = materialType;
        this.identityDigest = identityDigest;
        this.publishedDigest = publishedDigest;
        this.valueLength = valueLength;
        this.findings = List.copyOf(findings);
    }

    /**
     * Redacts a component's {@code cryptoProperties}, returning two copies. The argument is left untouched.
     *
     * <p>
     * <b>Two payloads, because storage and identity answer to different rules.</b> R2 enumerates exactly what is
     * stripped before any hash -- the five document-internal reference fields -- and R15 fixes the canonical form of
     * what remains, so a member this class chooses to withhold from storage cannot be allowed to move the key. Dropping
     * members from the single shared payload did exactly that: the hashed projection lost every uncontracted member,
     * which moved {@code mat:backstop} away from the reference for any material carrying one. Measured on the
     * 2026-08-31 corpus, that was 5 low-entropy rows and one ratified vector.
     *
     * @param cryptoProperties the raw properties block, which may be {@code null} for a component that carries none
     */
    public static MaterialRedaction of(JsonNode cryptoProperties) {
        ObjectNode payload = cryptoProperties == null || !cryptoProperties.isObject()
                ? com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode()
                : cryptoProperties.deepCopy();
        JsonNode material = payload.get(CbomNames.RELATED_CRYPTO_MATERIAL_PROPERTIES);
        if (material != null && !material.isObject()) {
            // Dropped from BOTH payloads, not passed through. A producer emitting the block as an array or a string
            // put key material somewhere no redaction step can reach, so there is no envelope to put in its place --
            // which is what separates this from an uncontracted member. Retaining it would carry the plaintext into
            // the stored payload and into the backstop pre-image.
            payload.remove(CbomNames.RELATED_CRYPTO_MATERIAL_PROPERTIES);
            return new MaterialRedaction(payload, payload.deepCopy(), null, null, null, null,
                    List.of("non-object material block dropped"));
        }
        if (material == null) {
            return new MaterialRedaction(payload, payload.deepCopy(), null, null, null, null, List.of());
        }
        ObjectNode materialNode = (ObjectNode) material;
        JsonNode typeNode = materialNode.get("type");
        String materialType = typeNode != null && typeNode.isTextual() ? typeNode.textValue() : null;

        List<String> findings = new ArrayList<>();
        String identityDigest = null;
        String publishedDigest = null;
        Integer valueLength = null;

        if (materialNode.has(CbomNames.VALUE)) {
            JsonNode raw = materialNode.get(CbomNames.VALUE);
            if (raw == null || !raw.isTextual()) {
                // A non-string value cannot be hashed meaningfully and must not survive.
                materialNode.remove(CbomNames.VALUE);
                findings.add("non-string material value dropped");
            } else {
                String value = raw.textValue();
                // Code points, not UTF-16 units. The reference counts characters, so a material value carrying
                // anything outside the basic multilingual plane would otherwise be reported one length here and
                // another there -- and the length is served back in the stored payload.
                valueLength = value.codePointCount(0, value.length());
                // The identity digest exists for EVERY value, including low-entropy ones: the identity key is a hash
                // of the whole pre-image and is never exposed on any API, so using it costs nothing and keeps two
                // different passwords at one source coordinate apart. What is withheld for low-entropy material is
                // the digest in the STORED payload, which is served back and would be a reversible password hash.
                identityDigest = IdentityDigests.sha256Hex(value);
                publishedDigest = digestPublishable(materialType) ? identityDigest : null;
                if (publishedDigest == null) {
                    // The envelope carries no digest for any type, so this gate no longer decides what is stored --
                    // it decides what publishedDigest() may hand an internal caller. An unsalted SHA-256 of a
                    // password or a token is rainbow-table reversible, so a caller that put one on an API would leak
                    // it one step removed, and producers really do emit generic-password and jwt-token material.
                    findings.add("digest withheld: " + materialType + " is not a high-entropy material type");
                }
                ObjectNode redacted = materialNode.objectNode();
                redacted.put("redacted", true);
                redacted.put("length", valueLength);
                materialNode.set(CbomNames.VALUE, redacted);
                inlinedSecretFinding(materialType, CbomNames.VALUE, findings);
            }
        }

        // The stored payload forks from the keyed one HERE, once the value carries an envelope rather than a
        // plaintext. Everything above is common to both; the member allowlist below is storage's alone.
        ObjectNode stored = payload.deepCopy();
        ObjectNode storedMaterial = (ObjectNode) stored.get(CbomNames.RELATED_CRYPTO_MATERIAL_PROPERTIES);
        // Read before the drop, because the severe finding needs the VALUE and not the member name. Raising it for
        // every dropped member reported a producer's benign metadata -- a number, a null, an object -- as confirmed
        // key-material exfiltration, which is a false positive on the loudest finding this class emits.
        List<String> inlined = storedMaterial == null ? List.of() : inlinedMemberNames(storedMaterial, materialType);
        dropUncontractedMembers(storedMaterial, materialType, findings);
        projectRelatedAssets(storedMaterial, findings);
        inlined.forEach(member -> inlinedSecretFinding(materialType, member, findings));
        return new MaterialRedaction(payload, stored, materialType, identityDigest, publishedDigest, valueLength,
                findings);
    }

    /**
     * The members storage drops that carry something which could be inlined material: a non-blank textual scalar.
     *
     * <p>
     * A predicate over the value rather than over the name, and deliberately a shape test rather than an entropy or
     * PEM-header test: the point is to separate "a producer put a string here" from "a producer put a flag, a count or
     * a nested object here", not to guess whether the string is a key. A digest of a secret is a string too, and is
     * exactly as worth reporting.
     *
     * <p>
     * Dropped here means dropped by {@link #dropUncontractedMembers}: both ask {@link #storageKeeps}, so the two cannot
     * disagree. They did, twice, in opposite directions. First the report tested {@link #CONTRACTED_MEMBERS} alone and
     * raised the finding on a member the drop kept; then the report took the drop's looser set, and a plaintext under
     * {@code fingerprint} or {@code relatedCryptoMaterialType} on a {@code private-key} was stored and unreported --
     * the exfiltration finding switched off for exactly the two members able to hold whatever a producer puts there.
     */
    private static List<String> inlinedMemberNames(ObjectNode materialNode, String materialType) {
        List<String> carrying = new ArrayList<>();
        materialNode.properties().forEach(member -> {
            JsonNode value = member.getValue();
            if (!storageKeeps(member.getKey(), value, materialType) && value.isTextual()
                    && !AsciiText.isBlank(value.textValue())) {
                carrying.add(member.getKey());
            }
        });
        carrying.sort(AsciiText.BY_CODE_POINT);
        return carrying;
    }

    /**
     * Raises the exfiltration finding when a type that should never carry an inlined value carried one.
     *
     * <p>
     * Separate from the generic uncontracted-members finding and deliberately louder: this one names the type, so a
     * consumer can tell "a producer put a private key in a document" from "a producer sent a field we do not contract
     * for".
     */
    private static void inlinedSecretFinding(String materialType, String member, List<String> findings) {
        if (isSecretType(materialType)) {
            findings.add("producer inlined a value on material type " + materialType + " under member " + member);
        }
    }

    private static boolean isSecretType(String materialType) {
        return materialType != null && SECRET_TYPES.contains(AsciiText.lookupKey(materialType));
    }

    /**
     * True only for an exact match on {@link #HIGH_ENTROPY_TYPES}; an absent, blank or unrecognised type fails closed.
     */
    private static boolean digestPublishable(String materialType) {
        // AsciiText, not the JDK. String.isBlank/strip consult Character.isWhitespace, which does not treat
        // U+0085, U+00A0 or U+202F as whitespace -- so a type pasted out of a document as "password" followed by U+00A0
        // kept it,
        // missed the type set, and published sha256 of the password. lookupKey deletes the
        // reference whitespace set wherever it sits, so the same spelling now resolves to its type.
        return materialType != null && HIGH_ENTROPY_TYPES.contains(AsciiText.lookupKey(materialType));
    }

    /**
     * The members of {@code relatedCryptoMaterialProperties} this pipeline stores.
     *
     * <p>
     * Everything else is a producer extension and is dropped rather than enumerated, because {@code value} is not the
     * only member that can carry the plaintext -- or the plaintext's digest -- and the set of names that can is open: a
     * secret scanner fingerprints what it found so it can dedupe findings across runs, and that digest is exactly as
     * reversible as the one {@link #digestPublishable} refuses to publish.
     *
     * <p>
     * These are the 1.6 schema's members exactly, plus 1.7's {@code relatedCryptographicAssets} -- the rename of
     * {@code algorithmRef}, whose omission dropped the 1.7 reference array from storage while its 1.6 spelling
     * survived. That is the parity hazard R2 exists to prevent, inverted onto storage.
     *
     * <p>
     * {@code relatedCryptoMaterialType} was in this set and is not any more -- {@link #RELATED_CRYPTO_MATERIAL_TYPE}
     * says why. It was added as a stopgap for a layer error rather than as a statement about the contract: dropping it
     * re-keyed a ratified row, because the backstop pre-image ends in a projection digest over this payload and vector
     * {@code gen-068-mat-backstop} expects the member present. Splitting the payloads retired that reason, and a review
     * pass then showed the exemption was not merely unjustified but unsafe. What this set as a whole still lacks is a
     * ratified source, which is open on core#2165 item 9.
     */
    private static final String RELATED_CRYPTOGRAPHIC_ASSETS = "relatedCryptographicAssets";

    private static final Set<String> CONTRACTED_MEMBERS = Set
            .of("type", "id", "state", "algorithmRef", RELATED_CRYPTOGRAPHIC_ASSETS, "creationDate", "activationDate",
                    "updateDate", "expirationDate", "value", "size", "format", "securedBy");

    /**
     * The members each {@code relatedCryptographicAssets} entry keeps.
     *
     * <p>
     * {@link #CONTRACTED_MEMBERS} admits the array by its top-level name and {@link #dropUncontractedMembers} iterates
     * top-level names only, so every entry was preserved whole: a producer emitting
     * {@code [{"ref":"a1","digest":"<hash of the secret>"}]} kept that digest in the stored payload. The argument for
     * an allowlist rather than a denylist does not stop at depth one -- the set of member names able to carry a
     * secret's digest is open at every depth -- so the entries are projected onto this shape instead of being filtered
     * against a list of names to fear.
     *
     * <p>
     * 724 corpus entries carry {@code ref} (724 of them) and {@code type} (144) and nothing else, so the projection
     * costs 0 stored payloads today. Whether 1.7 contracts a third member here is open on core#2165 item 9 with the
     * rest of this set's ratified source; until it is answered a new member fails closed and is reported, which is the
     * direction this class takes everywhere else.
     */
    private static final Set<String> CONTRACTED_RELATED_ASSET_MEMBERS = Set.of("ref", "type");

    /**
     * The fingerprint member, kept in storage only in its schema shape and only while the material's own digest may be
     * published.
     *
     * <p>
     * A producer fingerprint of high-entropy material is not reversible and is the discriminator the
     * {@code mat:fingerprint} tier keys on, so storage keeps it. On low-entropy material the same member is an unsalted
     * digest of a password, which is the thing {@link #digestPublishable} exists to withhold -- so storage drops it
     * there. And a fingerprint is an object of {@code alg} and {@code content} in both schemas: a textual scalar under
     * the name is not a fingerprint but an unrestricted string, which on a {@code private-key} was stored verbatim and
     * unreported while the same PEM under {@code pem} was dropped and raised as exfiltration. The shape decides, not
     * the name, because the name is the one thing the producer chose.
     *
     * <p>
     * <b>Dropping it no longer changes the tier.</b> While one payload served both purposes, a low-entropy asset's
     * fingerprint was gone before {@code material()} could read it, so the row reached {@code mat:backstop}; now the
     * keyed payload keeps it and the row keys on {@code mat:fingerprint} instead. That is a key move for that class,
     * and it is toward the reference: the specification's {@code MAT|<type>|F|...} carries no low-entropy exception and
     * the kernel keys the tier whatever the type. 0 corpus rows and 0 vectors -- all 453 fingerprints in the 2026-08-18
     * corpus are objects with content, 443 on {@code private-key} and 10 on {@code public-key}, so every one of them
     * stays stored.
     */
    private static final String FINGERPRINT = "fingerprint";

    /**
     * The long type spelling, kept in storage only for a publishable type that is not a secret type.
     *
     * <p>
     * It is not in {@link #CONTRACTED_MEMBERS} because it is an <em>unrestricted</em> extension -- absent from both
     * schemas, read by nothing, and able to hold whatever a producer puts there, including a digest of the very value
     * the withhold rule protects. Retaining it for every type defeated that rule through the exemption meant to
     * preserve fidelity: {@code type: "password"} carrying the password's digest under the long spelling was stored and
     * served. On the secret types that are publishable -- {@code private-key}, {@code secret-key},
     * {@code shared-secret}, {@code seed}, {@code key} -- it is dropped too: nothing reads it, so nothing is lost, and
     * keeping it left a plaintext under this one name stored and unreported on exactly the types the exfiltration
     * finding exists for. The single corpus component carrying the member states no type at all, which fails closed, so
     * 0 stored payloads move.
     */
    private static final String RELATED_CRYPTO_MATERIAL_TYPE = "relatedCryptoMaterialType";

    /**
     * Whether the stored payload keeps a member of {@code relatedCryptoMaterialProperties}. The one question both the
     * drop and the exfiltration report ask, so they cannot disagree about what is uncontracted.
     */
    private static boolean storageKeeps(String member, JsonNode value, String materialType) {
        if (CONTRACTED_MEMBERS.contains(member)) {
            return true;
        }
        if (!digestPublishable(materialType)) {
            return false;
        }
        if (FINGERPRINT.equals(member)) {
            return value.isObject();
        }
        return RELATED_CRYPTO_MATERIAL_TYPE.equals(member) && !isSecretType(materialType);
    }

    /**
     * Drops every uncontracted member from the stored payload, and says which.
     *
     * <p>
     * <b>An allowlist, because the hazard is open-ended.</b> The predecessor named {@code fingerprint} and
     * {@code digest} and withheld those two: {@code hash}, {@code hashes}, {@code sha256}, {@code checksum},
     * {@code thumbprint}, {@code md5}, {@code fingerprints} and even {@code Fingerprint} -- the match was
     * case-sensitive -- each carried an unsalted SHA-256 of a password into the served payload with no finding raised.
     * None of those is a CycloneDX field, which is what makes enumeration the wrong shape of defence: the next scanner
     * invents the eleventh name and it fails open again, silently, exactly as five of six spellings did before.
     *
     * <p>
     * <b>Every type, not only the low-entropy ones.</b> Gating the allowlist on {@link #digestPublishable} ran the
     * protection opposite to the severity of the exposure. The value redaction keys on the single exact member name
     * {@code value}, so for exactly the types in {@link #SECRET_TYPES} an inlined plaintext under any other name was
     * stored verbatim with no finding: {@code {"type":"password","Value":"hunter2"}} was dropped and reported, while
     * {@code {"type":"private-key","pem":"-----BEGIN PRIVATE KEY-----…"}} was kept -- and this class's own doc calls
     * that case the one where a producer "has exfiltrated key material into a document the platform then aggregates
     * estate-wide". The same members {@code fingerprint} and {@code relatedCryptographicAssets} that the corpus
     * actually carries are allowed by name, so on real data the widening costs nothing and closes the plaintext hole.
     *
     * <p>
     * The drops are storage's alone: {@link #keyedPayload()} keeps every member, so nothing here can move an identity
     * key. What that buys is a retained plaintext reaching the identity pre-image, and how far it reaches is worth
     * being exact about. A plaintext under an <em>uncontracted</em> member enters only
     * {@code CanonicalJson.projectionDigest}, so it sits inside a SHA-256 and is never spelled into a slot. The
     * cleartext case is {@code fingerprint.content}, which the {@code mat:fingerprint} claim spells literally -- a tier
     * this split newly makes reachable for low-entropy material. Either way it reaches no stored column, no wire
     * response and no log: the pre-image has no production caller, {@link #keyedPayload()} is package-private, and the
     * architecture fence covers both spellings. It is the same exposure the value tier already accepts by hashing the
     * plaintext, and R2/R15 leave no room to strip more before a hash.
     *
     * <p>
     * The finding names every member removed, so nothing disappears without a record.
     */
    private static List<String> dropUncontractedMembers(ObjectNode materialNode, String materialType,
            List<String> findings) {
        if (materialNode == null) {
            return List.of();
        }
        List<String> dropped = new ArrayList<>();
        materialNode.properties().forEach(member -> {
            if (!storageKeeps(member.getKey(), member.getValue(), materialType)) {
                dropped.add(member.getKey());
            }
        });
        if (dropped.isEmpty()) {
            return List.of();
        }
        dropped.sort(AsciiText.BY_CODE_POINT);
        dropped.forEach(materialNode::remove);
        findings
                .add("uncontracted members dropped from the stored payload, any of which may carry the plaintext or "
                        + "a reversible digest of it: " + String.join(", ", dropped));
        return List.copyOf(dropped);
    }

    /**
     * Projects each {@code relatedCryptographicAssets} entry onto {@link #CONTRACTED_RELATED_ASSET_MEMBERS}.
     *
     * <p>
     * Storage's alone, like the drop above -- {@link #keyedPayload()} keeps the array whole, so nothing here can move
     * an identity key. An entry that is not an object states no reference and is removed rather than projected; an
     * entry whose contracted members are all absent stays as an empty object, because how many related assets the
     * producer stated is itself part of what the row records.
     */
    private static void projectRelatedAssets(ObjectNode materialNode, List<String> findings) {
        if (materialNode == null || !materialNode.has(RELATED_CRYPTOGRAPHIC_ASSETS)) {
            return;
        }
        JsonNode assets = materialNode.get(RELATED_CRYPTOGRAPHIC_ASSETS);
        if (!assets.isArray()) {
            materialNode.remove(RELATED_CRYPTOGRAPHIC_ASSETS);
            findings.add("non-array relatedCryptographicAssets dropped from the stored payload");
            return;
        }
        List<String> removed = new ArrayList<>();
        ArrayNode projected = materialNode.arrayNode();
        assets.forEach(entry -> {
            if (!entry.isObject()) {
                removed.add("<non-object entry>");
                return;
            }
            ObjectNode kept = projected.addObject();
            entry.properties().forEach(member -> {
                if (CONTRACTED_RELATED_ASSET_MEMBERS.contains(member.getKey()) && member.getValue().isTextual()) {
                    kept.set(member.getKey(), member.getValue());
                } else {
                    removed.add(member.getKey());
                }
            });
        });
        materialNode.set(RELATED_CRYPTOGRAPHIC_ASSETS, projected);
        if (!removed.isEmpty()) {
            removed.sort(AsciiText.BY_CODE_POINT);
            findings
                    .add("uncontracted members dropped from relatedCryptographicAssets entries, any of which may "
                            + "carry a reversible digest of the plaintext: " + String.join(", ", removed));
        }
    }

    /**
     * The redacted properties as identity reads them: R2/R15's projection, with the value under its envelope.
     *
     * <p>
     * Every member the producer stated is present, because R2 names the five reference fields as the whole of what a
     * hash may strip. This is not a payload to store, serve or log -- an uncontracted member may carry a plaintext the
     * storage allowlist removes -- and the architecture fence keeps the identity pre-image built from it off every
     * client-facing surface.
     */
    ObjectNode keyedPayload() {
        return keyedPayload;
    }

    /** The redacted properties as storage reads them: contracted members only. This is what may be stored or served. */
    public ObjectNode storedPayload() {
        return storedPayload;
    }

    /**
     * The digest of the plaintext, for the material identity chain only.
     *
     * <p>
     * Present even when {@link #publishedDigest()} is withheld. It must never reach a stored payload or a wire response
     * -- it is a hash of a possibly low-entropy secret, and the identity key that consumes it is itself fenced from
     * every client-facing surface.
     */
    public String identityDigest() {
        return identityDigest;
    }

    /** The digest that may be used by internal callers, or {@code null} for low-entropy material. */
    public String publishedDigest() {
        return publishedDigest;
    }

    public Integer valueLength() {
        return valueLength;
    }

    public String materialType() {
        return materialType;
    }

    /** Ingest findings worth reporting: a dropped value, a withheld digest, or a producer leaking key material. */
    public List<String> findings() {
        return findings;
    }
}

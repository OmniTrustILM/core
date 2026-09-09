package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** The content digests a certificate claims, in preference order, reduced to one spelling. */
public final class CertificateDigests {

    /**
     * Preferred first, which is not strongest first: {@code SHA-256} leads because it is what producers actually emit,
     * and reordering would re-key every certificate claiming more than one digest. SHA-1 is last but still accepted --
     * a weak digest still identifies, and refusing it loses a row.
     */
    private static final List<String> PREFERENCE = List.of("SHA-256", "SHA-384", "SHA-512", "SHA-1");

    private CertificateDigests() {
    }

    /**
     * The 1.7 fingerprint field's digest, or {@code null} when the field is absent or carries no content.
     *
     * <p>
     * Named rather than inlined because the chain step is derived from it: labelling a key {@code crt:fingerprint} on
     * the mere presence of a {@code fingerprint} node reported that step for a key actually built from
     * {@code component.hashes[]}, whenever the node was present but unusable. Comparing against this value cannot drift
     * from the digest spelling the key used.
     */
    public static String fingerprintDigest(JsonNode certificateProperties) {
        JsonNode fingerprint = certificateProperties == null ? null : certificateProperties.get("fingerprint");
        if (fingerprint == null || !fingerprint.isObject()) {
            return null;
        }
        JsonNode contentNode = fingerprint.get(CbomNames.CONTENT);
        if (contentNode == null || !contentNode.isTextual()) {
            // Textual only, and blank-checked after the strip rather than before it. The predecessor tested asText()
            // on the raw node, so " " passed it and rendered the claim "sha-256:" -- and two unrelated certificates
            // then shared that first preference-order claim and merged onto one content-digest tier. A boolean or
            // numeric content passed it too, keying on "true".
            return null;
        }
        String content = AsciiText.fold(AsciiText.strip(contentNode.textValue()));
        if (content.isEmpty()) {
            return null;
        }
        // A container alg made the "sha-256" default unreachable and rendered the claim ":aa", because asText() on an
        // object or array yields the empty string rather than null. A blank textual alg reached the same claim by the
        // other side: isTextual() is true, so the default was skipped and the label folded to "" -- and one
        // certificate then forked between ":aa" and "sha-256:aa" on whether its alg was blank or absent, which are two
        // spellings of the same silence. Blank-checked after the fold, the way the content is twelve lines up.
        JsonNode algorithm = fingerprint.get("alg");
        String label = algorithm != null && algorithm.isTextual() ? canonicalLabel(algorithm.textValue()) : "";
        return claim(label.isEmpty() ? AsciiText.fold("sha-256") : label, content);
    }

    /**
     * The {@link #PREFERENCE} spelling of a digest label, or the producer's own folded spelling when it names no known
     * algorithm.
     *
     * <p>
     * Both channels route through here so one certificate cannot fork on how its label was written. A 1.7 producer
     * emitting {@code alg: "SHA256"} and a 1.6 producer emitting {@code alg: "SHA-256"} over the same certificate bytes
     * were keying two different assets, and an alias spelling inside {@code hashes[]} yielded no digest tier at all
     * because {@code PREFERENCE} holds only the canonical spellings.
     */
    private static String canonicalLabel(String label) {
        String lookup = AsciiText.lookupKey(label);
        for (String preferred : PREFERENCE) {
            if (AsciiText.lookupKey(preferred).equals(lookup)) {
                return AsciiText.fold(preferred);
            }
        }
        return AsciiText.fold(AsciiText.strip(label));
    }

    /**
     * Every digest this certificate claims, the 1.7 {@code fingerprint} field first and {@code component.hashes[]}
     * second.
     *
     * <p>
     * They collapse into <b>one</b> content-digest tier rather than two. Tagging the 1.7 field differently from an
     * identical {@code component.hashes[]} digest would fork the same certificate between a 1.6 and a 1.7 producer on
     * the strength of <em>where</em> the same bytes were written.
     */
    public static List<String> claimed(JsonNode component, JsonNode certificateProperties) {
        List<String> digests = new ArrayList<>();
        String fromFingerprint = fingerprintDigest(certificateProperties);
        if (fromFingerprint != null) {
            digests.add(fromFingerprint);
        }
        String fromComponent = componentHash(component);
        if (fromComponent != null) {
            digests.add(fromComponent);
        }
        return digests;
    }

    /**
     * The strongest available content hash from {@code component.hashes[]}.
     *
     * <p>
     * Measured present on 6 of 6 real certificates, and byte-identical to Core's own thumbprint convention -- SHA-256
     * over the full DER, lowercase hex -- which makes a future correlation a one-line equijoin instead of a backfill.
     */
    public static String componentHash(JsonNode component) {
        JsonNode hashes = component == null ? null : component.get("hashes");
        if (hashes == null || !hashes.isArray()) {
            return null;
        }
        Set<String> contradicted = new HashSet<>();
        Map<String, String> byAlgorithm = collectHashes(hashes, contradicted);
        for (String algorithm : PREFERENCE) {
            String content = byAlgorithm.get(algorithm);
            if (content != null && !contradicted.contains(algorithm)) {
                return claim(AsciiText.fold(algorithm), content);
            }
        }
        return null;
    }

    /**
     * The first non-empty content each algorithm claims, recording into {@code contradicted} any algorithm that claimed
     * two different ones.
     *
     * <p>
     * An entry with no content does not decide and does not shadow one that does, so a trailing empty entry cannot
     * demote an algorithm to the next preference and a leading one cannot suppress the real digest behind it. Empty is
     * not a contradiction either: a producer that said nothing has not said something different.
     */
    private static Map<String, String> collectHashes(JsonNode hashes, Set<String> contradicted) {
        Map<String, String> byAlgorithm = new LinkedHashMap<>();
        for (JsonNode hash : hashes) {
            String content = hash.isObject() ? textual(hash.get("content")) : "";
            if (content.isEmpty()) {
                continue;
            }
            String algorithm = AsciiText.upper(canonicalLabel(textual(hash.get("alg"))));
            String existing = byAlgorithm.putIfAbsent(algorithm, content);
            if (existing != null && !existing.equals(content)) {
                contradicted.add(algorithm);
            }
        }
        return byAlgorithm;
    }

    /**
     * One textual field of a hash entry, stripped and ASCII-folded, or the empty string when it is absent or not text.
     *
     * <p>
     * The algorithm is keyed through {@link #canonicalLabel} rather than on its own spelling. Keying it on
     * {@code upper(strip(alg))} let an alias escape the contradiction guard entirely: a certificate stating
     * {@code SHA256:aa} and {@code SHA-256:bb} produced two different map entries, so neither was recorded as
     * contradicted and the second silently won -- the exact case the guard exists to refuse.
     */
    private static String textual(JsonNode value) {
        return value == null || !value.isTextual() ? "" : AsciiText.fold(AsciiText.strip(value.textValue()));
    }

    /**
     * Joins an algorithm to its content so neither half can forge the boundary between them.
     *
     * <p>
     * {@code alg} is producer-controlled, so a bare join let {@code {"alg":"sha-256:aabbcc","content":"dd"}} and
     * {@code {"alg":"sha-256","content":"aabbcc:dd"}} render one string and collapse two certificates onto one key.
     *
     * <p>
     * The {@code :} belongs to this layer and not to {@link PreImageSlot}: the claim later enters a {@code |}-delimited
     * outer slot through {@link PreImageSlot#of}, and teaching that the {@code :} would escape this separator too,
     * erasing the distinction it exists to draw. The consequence is that the pre-image carries the doubly-escaped
     * spelling {@code %253A} rather than {@code %3A} -- see {@link PreImageSlot#escape}.
     */
    private static String claim(String algorithm, String content) {
        return PreImageSlot.escape(algorithm, CertificateDigests::digestEscapeFor) + ":"
                + PreImageSlot.escape(content, CertificateDigests::digestEscapeFor);
    }

    private static String digestEscapeFor(char character) {
        return switch (character) {
            case '%' -> "%25";
            case ':' -> "%3A";
            default -> null;
        };
    }

}

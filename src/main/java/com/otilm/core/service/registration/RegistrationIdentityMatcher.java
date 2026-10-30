package com.otilm.core.service.registration;

import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.PlatformX500NameStyle;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.encoders.Hex;

/**
 * Pure matching kernel binding a protocol enrolment to a pre-registered certificate. Subjects compare by their
 * {@link PlatformX500NameStyle#NORMALIZED} rendering, which neutralizes RDN order, attribute-name case and spacing but
 * deliberately preserves attribute-value case — the enrolment must present the identity exactly as registered. SAN sets
 * compare as maps of value lists canonicalized per type — IP addresses reduced to their octets (so the CSR's hex
 * rendering equals a registration's decoded text and equivalent forms agree), DNS names lowercased (they are
 * case-insensitive), duplicates dropped, order removed, and empty buckets dropped — so representation differences that
 * do not change the identity do not defeat the match.
 *
 * <p>
 * The kernel never checks the challenge — the caller verifies it against the single matched registration, keeping
 * failed-attempt accounting attributable to exactly one authorization.
 */
public final class RegistrationIdentityMatcher {

    /** A pre-registered candidate: the certificate row's UUID, subject DN and serialized SAN column. */
    public record Candidate(UUID certificateUuid, String subjectDn, String serializedSans) {
    }

    public enum Outcome {
        /** Exactly one registration matches subject and SANs; its UUID is in the result. */
        MATCHED,
        /** No registration matches the subject. */
        NO_MATCH,
        /** Several registrations match the subject and the SAN tiebreak does not single one out. */
        AMBIGUOUS,
        /**
         * Exactly one registration matches the subject but its SANs differ from the CSR's; the result carries its UUID
         * so the caller can record the failure against it.
         */
        SAN_MISMATCH
    }

    /** Result of a match: the outcome, and the involved certificate UUID for MATCHED and SAN_MISMATCH. */
    public record MatchResult(Outcome outcome, UUID certificateUuid) {

        private static MatchResult matched(UUID certificateUuid) {
            return new MatchResult(Outcome.MATCHED, certificateUuid);
        }

        private static MatchResult noMatch() {
            return new MatchResult(Outcome.NO_MATCH, null);
        }

        private static MatchResult ambiguous() {
            return new MatchResult(Outcome.AMBIGUOUS, null);
        }

        private static MatchResult sanMismatch(UUID certificateUuid) {
            return new MatchResult(Outcome.SAN_MISMATCH, certificateUuid);
        }
    }

    private RegistrationIdentityMatcher() {
    }

    /**
     * Matches the CSR identity against the candidates: candidates are filtered by normalized subject; a unique subject
     * match must then carry SANs equal to the CSR's; several subject matches narrow to the single candidate with SAN
     * equality. An absent (null or blank) subject on either side normalizes to the empty name, so a SAN-only
     * registration matches a SAN-only enrolment through SAN equality. A candidate whose stored DN is present but does
     * not parse is skipped — one malformed row must not block the others.
     */
    public static MatchResult match(X500Name csrSubject, Map<String, List<String>> csrSans,
            List<Candidate> candidates) {
        String normalizedCsrSubject = CertificateUtil.normalizeSubjectDn(csrSubject);
        Map<String, List<String>> normalizedCsrSans = normalizeSans(csrSans);

        List<Candidate> subjectMatches = new ArrayList<>();
        for (Candidate candidate : candidates) {
            String normalizedCandidateSubject;
            try {
                normalizedCandidateSubject = CertificateUtil.normalizeStoredSubjectDn(candidate.subjectDn());
            } catch (RuntimeException e) {
                continue;
            }
            if (normalizedCsrSubject.equals(normalizedCandidateSubject)) {
                subjectMatches.add(candidate);
            }
        }

        if (subjectMatches.isEmpty()) {
            return MatchResult.noMatch();
        }
        if (subjectMatches.size() == 1) {
            Candidate single = subjectMatches.getFirst();
            return sansEqual(normalizedCsrSans, single)
                    ? MatchResult.matched(single.certificateUuid())
                    : MatchResult.sanMismatch(single.certificateUuid());
        }
        List<Candidate> sanMatches = subjectMatches
                .stream()
                .filter(candidate -> sansEqual(normalizedCsrSans, candidate))
                .toList();
        return sanMatches.size() == 1
                ? MatchResult.matched(sanMatches.getFirst().certificateUuid())
                : MatchResult.ambiguous();
    }

    private static boolean sansEqual(Map<String, List<String>> normalizedCsrSans, Candidate candidate) {
        return normalizedCsrSans.equals(normalizeSans(CertificateUtil.deserializeSans(candidate.serializedSans())));
    }

    /** The serialized SAN type keys whose values carry a canonical form independent of their rendering. */
    private static final String DNS_NAME = "dNSName";
    private static final String IP_ADDRESS = "iPAddress";

    /**
     * Canonicalizes each value per type (see the class Javadoc), drops duplicates, sorts, and drops empty buckets, so
     * bucket presence, value order, duplicates and per-type representation carry no meaning.
     */
    private static Map<String, List<String>> normalizeSans(Map<String, List<String>> sans) {
        Map<String, List<String>> normalized = new TreeMap<>();
        if (sans == null) {
            return normalized;
        }
        sans.forEach((type, values) -> {
            if (values == null || values.isEmpty()) {
                return;
            }
            List<String> canonical = values
                    .stream()
                    .filter(Objects::nonNull)
                    .map(value -> canonicalizeSanValue(type, value))
                    .distinct()
                    .sorted()
                    .toList();
            if (!canonical.isEmpty()) {
                normalized.put(type, canonical);
            }
        });
        return normalized;
    }

    private static String canonicalizeSanValue(String type, String value) {
        return switch (type) {
            case IP_ADDRESS -> canonicalizeIp(value);
            case DNS_NAME -> value.toLowerCase(Locale.ROOT);
            default -> value;
        };
    }

    /**
     * Reduces an IP SAN to its octet hex, the form {@link CertificateUtil#getSAN} renders from a CSR, so a
     * registration's decoded text ({@code 192.168.1.1}) and equivalent forms collapse to the same value. An unparseable
     * value is left untouched, so a genuine mismatch still mismatches rather than throwing.
     */
    private static String canonicalizeIp(String value) {
        try {
            byte[] octets = value.startsWith("#")
                    ? Hex.decode(value.substring(1))
                    : ASN1OctetString.getInstance(new GeneralName(GeneralName.iPAddress, value).getName()).getOctets();
            return "#" + Hex.toHexString(octets);
        } catch (RuntimeException e) {
            return value;
        }
    }
}

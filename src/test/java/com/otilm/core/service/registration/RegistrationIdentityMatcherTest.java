package com.otilm.core.service.registration;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.Candidate;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.MatchResult;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.Outcome;
import com.otilm.core.util.CertificateUtil;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RegistrationIdentityMatcherTest {

    private static final UUID CANDIDATE_A = UUID.randomUUID();
    private static final UUID CANDIDATE_B = UUID.randomUUID();

    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void snapshotAndSeedRdnCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);

        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.10",
                        OidRecord.builder().displayName("Organization").code("O").build());
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler
                .cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                        savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    @Test
    void matchesUniqueSubjectWithEqualSans() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1, O=Acme",
                sans(Map.of("dNSName", List.of("a.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("O=Acme,cn=device-1"), Map.of("dNSName", List.of("a.example")), List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void subjectValueCaseIsSignificant() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=Device-1", null);

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of(), List.of(candidate));

        Assertions.assertEquals(Outcome.NO_MATCH, result.outcome());
    }

    @Test
    void subjectMatchWithDifferentSansIsSanMismatch() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1", sans(Map.of("dNSName", List.of("a.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of("dNSName", List.of("b.example")), List.of(candidate));

        Assertions.assertEquals(Outcome.SAN_MISMATCH, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void sanOrderAndEmptyBucketsAreInsensitive() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1",
                sans(Map.of("dNSName", List.of("a.example", "b.example"), "iPAddress", List.of())));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of("dNSName", List.of("b.example", "a.example")),
                        List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
    }

    @Test
    void emptySansMatchEmptySans() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1", null);

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of(), List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void sharedSubjectNarrowsBySans() {
        Candidate first = new Candidate(CANDIDATE_A, "CN=fleet", sans(Map.of("dNSName", List.of("a.example"))));
        Candidate second = new Candidate(CANDIDATE_B, "CN=fleet", sans(Map.of("dNSName", List.of("b.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=fleet"), Map.of("dNSName", List.of("b.example")), List.of(first, second));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_B, result.certificateUuid());
    }

    @Test
    void sharedSubjectWithNoSanWinnerIsAmbiguous() {
        Candidate first = new Candidate(CANDIDATE_A, "CN=fleet", sans(Map.of("dNSName", List.of("a.example"))));
        Candidate second = new Candidate(CANDIDATE_B, "CN=fleet", sans(Map.of("dNSName", List.of("b.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=fleet"), Map.of("dNSName", List.of("c.example")), List.of(first, second));

        Assertions.assertEquals(Outcome.AMBIGUOUS, result.outcome());
        Assertions.assertNull(result.certificateUuid());
    }

    @Test
    void sharedSubjectWithTwoSanWinnersIsAmbiguous() {
        Candidate first = new Candidate(CANDIDATE_A, "CN=fleet", sans(Map.of("dNSName", List.of("a.example"))));
        Candidate second = new Candidate(CANDIDATE_B, "CN=fleet", sans(Map.of("dNSName", List.of("a.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=fleet"), Map.of("dNSName", List.of("a.example")), List.of(first, second));

        Assertions.assertEquals(Outcome.AMBIGUOUS, result.outcome());
    }

    @Test
    void ipSanMatchesAcrossHexCsrAndDecodedRegistration() {
        // The CSR side renders an IP SAN as its octet hex (what getSAN produces); the registration stores the
        // decoded text. Both must canonicalize to the same identity.
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1",
                sans(Map.of("iPAddress", List.of("192.168.1.1"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of("iPAddress", List.of("#c0a80101")), List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void equivalentIpv6FormsMatch() {
        // Registration stores a compressed IPv6; the CSR presents the fully expanded octets. Same address.
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1",
                sans(Map.of("iPAddress", List.of("2001:db8::1"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of("iPAddress", List.of("#20010db8000000000000000000000001")),
                        List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void differentIpSansAreSanMismatch() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1",
                sans(Map.of("iPAddress", List.of("192.168.1.1"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of("iPAddress", List.of("#0a000001")), List.of(candidate));

        Assertions.assertEquals(Outcome.SAN_MISMATCH, result.outcome());
    }

    @Test
    void dnsNameCaseIsInsensitive() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1",
                sans(Map.of("dNSName", List.of("Device.Example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of("dNSName", List.of("device.example")), List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void duplicateSanValuesAreCollapsed() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=device-1", sans(Map.of("dNSName", List.of("a.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of("dNSName", List.of("a.example", "a.example")),
                        List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void subjectlessRegistrationMatchesBySans() {
        // A SAN-only registration carries no subject; it must still match a SAN-only enrolment (empty subject).
        Candidate candidate = new Candidate(CANDIDATE_A, null, sans(Map.of("dNSName", List.of("a.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name(new RDN[0]), Map.of("dNSName", List.of("a.example")), List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void blankSubjectRegistrationIsTreatedAsSubjectless() {
        Candidate candidate = new Candidate(CANDIDATE_A, "   ", sans(Map.of("dNSName", List.of("a.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name(new RDN[0]), Map.of("dNSName", List.of("a.example")), List.of(candidate));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void subjectlessRegistrationWithDifferentSansIsSanMismatch() {
        Candidate candidate = new Candidate(CANDIDATE_A, null, sans(Map.of("dNSName", List.of("a.example"))));

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name(new RDN[0]), Map.of("dNSName", List.of("b.example")), List.of(candidate));

        Assertions.assertEquals(Outcome.SAN_MISMATCH, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    @Test
    void noSubjectMatchIsNoMatch() {
        Candidate candidate = new Candidate(CANDIDATE_A, "CN=other-device", null);

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of(), List.of(candidate));

        Assertions.assertEquals(Outcome.NO_MATCH, result.outcome());
        Assertions.assertNull(result.certificateUuid());
    }

    @Test
    void unparseableCandidateDnIsSkipped() {
        Candidate malformed = new Candidate(CANDIDATE_B, "not-a-dn", null);
        Candidate valid = new Candidate(CANDIDATE_A, "CN=device-1", null);

        MatchResult result = RegistrationIdentityMatcher
                .match(new X500Name("CN=device-1"), Map.of(), List.of(malformed, valid));

        Assertions.assertEquals(Outcome.MATCHED, result.outcome());
        Assertions.assertEquals(CANDIDATE_A, result.certificateUuid());
    }

    private static String sans(Map<String, List<String>> sans) {
        return CertificateUtil.serializeSans(sans);
    }
}

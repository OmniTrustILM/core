package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.est.authentication.EstSourceCertificate;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.est.message.EstRequestDecoder;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EstReenrollmentRulesTest {

    private static final String SUBJECT = "CN=device-1";
    private static final String DNS_NAME = "device-1.example.com";
    private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

    private static Ca ca;
    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void registerBouncyCastleAndSeedRdnCache() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());
        ca = PkiFixtures.rootCa("EST rules CA");
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler
                .cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                        savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    // ── Kind ──────────────────────────────────────────────────────────────────

    @Nested
    class Kind {

        @Test
        void classifiesAsRenewal_whenCsrCarriesTheSourceKey() throws Exception {
            // given
            KeyPair sourceKeys = PkiFixtures.keyPair();
            EstSourceCertificate source = buildSourceOf(sourceKeys);
            Pkcs10CertificateRequest csrWithSourceKey = buildCsr(sourceKeys, SUBJECT, DNS_NAME);

            // when
            EstReenrollmentKind kind = EstReenrollmentRules.classify(source, csrWithSourceKey);

            // then
            assertThat(kind).isEqualTo(EstReenrollmentKind.RENEWAL);
        }

        @Test
        void classifiesAsRekey_whenCsrCarriesAnotherKey() throws Exception {
            // given
            EstSourceCertificate source = buildSourceOf(PkiFixtures.keyPair());
            Pkcs10CertificateRequest csrWithAnotherKey = buildCsr(PkiFixtures.keyPair(), SUBJECT, DNS_NAME);

            // when
            EstReenrollmentKind kind = EstReenrollmentRules.classify(source, csrWithAnotherKey);

            // then
            assertThat(kind).isEqualTo(EstReenrollmentKind.REKEY);
        }

        @Test
        void classifiesAsRenewal_whenCsrCarriesTheSourceKeyUnderAnotherAlgorithmIdentifier() throws Exception {
            // given
            KeyPair sourceKeys = generateRsaKeyPair();
            EstSourceCertificate source = buildSourceOf(sourceKeys);
            AlgorithmIdentifier pssIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS);
            SubjectPublicKeyInfo sourceKeyUnderPss = new SubjectPublicKeyInfo(pssIdentifier,
                    SubjectPublicKeyInfo.getInstance(sourceKeys.getPublic().getEncoded()).parsePublicKey());
            Pkcs10CertificateRequest csr = buildCsrCarrying(sourceKeyUnderPss, sourceKeys, "SHA256withRSA");

            // when
            EstReenrollmentKind kind = EstReenrollmentRules.classify(source, csr);

            // then
            assertThat(kind).isEqualTo(EstReenrollmentKind.RENEWAL);
        }

        @Test
        void classifiesAsRenewal_whenCsrCarriesTheSourceKeyWithACompressedPoint() throws Exception {
            // given
            KeyPair sourceKeys = PkiFixtures.keyPair();
            EstSourceCertificate source = buildSourceOf(sourceKeys);
            SubjectPublicKeyInfo uncompressed = SubjectPublicKeyInfo.getInstance(sourceKeys.getPublic().getEncoded());
            X9ECParameters curve = ECNamedCurveTable
                    .getByOID(ASN1ObjectIdentifier.getInstance(uncompressed.getAlgorithm().getParameters()));
            byte[] compressedPoint = curve
                    .getCurve()
                    .decodePoint(uncompressed.getPublicKeyData().getBytes())
                    .getEncoded(true);
            SubjectPublicKeyInfo sourceKeyCompressed = new SubjectPublicKeyInfo(uncompressed.getAlgorithm(),
                    compressedPoint);
            Pkcs10CertificateRequest csr = buildCsrCarrying(sourceKeyCompressed, sourceKeys, "SHA256withECDSA");

            // when
            EstReenrollmentKind kind = EstReenrollmentRules.classify(source, csr);

            // then
            assertThat(kind).isEqualTo(EstReenrollmentKind.RENEWAL);
        }
    }

    // ── Profile switches ──────────────────────────────────────────────────────

    @Nested
    class ProfileSwitches {

        @Test
        void refusesRenewal_whenProfileForbidsIt() {
            // given
            EstProfile profile = anEstProfile().withAllowRenewal(false).build();

            // when
            ThrowingCallable requireAllowed = () -> EstReenrollmentRules
                    .requireAllowed(EstReenrollmentKind.RENEWAL, profile);

            // then
            assertRefusedWith(requireAllowed, EstError.RENEWAL_NOT_ALLOWED);
        }

        @Test
        void refusesRekey_whenProfileForbidsIt() {
            // given
            EstProfile profile = anEstProfile().withAllowRekey(false).build();

            // when
            ThrowingCallable requireAllowed = () -> EstReenrollmentRules
                    .requireAllowed(EstReenrollmentKind.REKEY, profile);

            // then
            assertRefusedWith(requireAllowed, EstError.REKEY_NOT_ALLOWED);
        }

        @Test
        void allowsRenewal_whenProfileForbidsOnlyRekey() {
            // given
            EstProfile profile = anEstProfile().withAllowRekey(false).build();

            // when
            ThrowingCallable requireAllowed = () -> EstReenrollmentRules
                    .requireAllowed(EstReenrollmentKind.RENEWAL, profile);

            // then
            assertThatCode(requireAllowed).doesNotThrowAnyException();
        }

        @Test
        void allowsRekey_whenProfileForbidsOnlyRenewal() {
            // given
            EstProfile profile = anEstProfile().withAllowRenewal(false).build();

            // when
            ThrowingCallable requireAllowed = () -> EstReenrollmentRules
                    .requireAllowed(EstReenrollmentKind.REKEY, profile);

            // then
            assertThatCode(requireAllowed).doesNotThrowAnyException();
        }

        @Test
        void allowsBoth_whenProfileKeepsDefaults() {
            // given
            EstProfile profile = anEstProfile().build();

            // when
            ThrowingCallable requireAllowed = () -> {
                EstReenrollmentRules.requireAllowed(EstReenrollmentKind.RENEWAL, profile);
                EstReenrollmentRules.requireAllowed(EstReenrollmentKind.REKEY, profile);
            };

            // then
            assertThatCode(requireAllowed).doesNotThrowAnyException();
        }
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    @Nested
    class Identity {

        @Test
        void acceptsIdentity_whenSubjectAndSanEqualTheSource() throws Exception {
            // given
            EstSourceCertificate source = buildSourceOf(PkiFixtures.keyPair());
            String dnsNameInAnotherCase = DNS_NAME.toUpperCase(Locale.ROOT);
            Pkcs10CertificateRequest csr = buildCsr(PkiFixtures.keyPair(), SUBJECT, dnsNameInAnotherCase);

            // when
            ThrowingCallable requireSameIdentity = () -> EstReenrollmentRules.requireSameIdentity(source, csr);

            // then
            assertThatCode(requireSameIdentity).doesNotThrowAnyException();
        }

        @Test
        void refusesIdentity_whenSubjectDiffers() throws Exception {
            // given
            EstSourceCertificate source = buildSourceOf(PkiFixtures.keyPair());
            String anotherSubject = "CN=device-2";
            Pkcs10CertificateRequest csr = buildCsr(PkiFixtures.keyPair(), anotherSubject, DNS_NAME);

            // when
            ThrowingCallable requireSameIdentity = () -> EstReenrollmentRules.requireSameIdentity(source, csr);

            // then
            assertRefusedWith(requireSameIdentity, EstError.IDENTITY_MISMATCH);
        }

        @Test
        void refusesIdentity_whenSanDiffers() throws Exception {
            // given
            EstSourceCertificate source = buildSourceOf(PkiFixtures.keyPair());
            String anotherDnsName = "other.example.com";
            Pkcs10CertificateRequest csr = buildCsr(PkiFixtures.keyPair(), SUBJECT, anotherDnsName);

            // when
            ThrowingCallable requireSameIdentity = () -> EstReenrollmentRules.requireSameIdentity(source, csr);

            // then
            assertRefusedWith(requireSameIdentity, EstError.IDENTITY_MISMATCH);
        }

        @Test
        void refusesIdentity_whenCsrAddsAName() throws Exception {
            // given
            EstSourceCertificate source = buildSourceOf(PkiFixtures.keyPair());
            String addedDnsName = "extra.example.com";
            Pkcs10CertificateRequest csr = buildCsr(PkiFixtures.keyPair(), SUBJECT, DNS_NAME, addedDnsName);

            // when
            ThrowingCallable requireSameIdentity = () -> EstReenrollmentRules.requireSameIdentity(source, csr);

            // then
            assertRefusedWith(requireSameIdentity, EstError.IDENTITY_MISMATCH);
        }
    }

    // ── Subject change ────────────────────────────────────────────────────────

    @Nested
    class SubjectChange {

        @Test
        void refusesSubjectChange_whenCsrCarriesChangeSubjectName() throws Exception {
            // given
            Pkcs10CertificateRequest csr = EstRequestDecoder
                    .decode(EstCsrFixtures.signedRequestBodyWithChangeSubjectName(PkiFixtures.keyPair(), SUBJECT));

            // when
            ThrowingCallable refuseSubjectChange = () -> EstReenrollmentRules.refuseSubjectChange(csr);

            // then
            assertRefusedWith(refuseSubjectChange, EstError.SUBJECT_CHANGE_UNSUPPORTED);
        }

        @Test
        void acceptsRequest_whenCsrCarriesNoChangeSubjectName() throws Exception {
            // given
            Pkcs10CertificateRequest csr = buildCsr(PkiFixtures.keyPair(), SUBJECT, DNS_NAME);

            // when
            ThrowingCallable refuseSubjectChange = () -> EstReenrollmentRules.refuseSubjectChange(csr);

            // then
            assertThatCode(refuseSubjectChange).doesNotThrowAnyException();
        }
    }

    // ── Window ────────────────────────────────────────────────────────────────

    @Nested
    class Window {

        @Test
        void returnsDue_whenHalfOfTheValidityRemains() {
            // given — valid 10 days, 5 remain
            Date notBefore = buildDateInDays(-5);
            Date notAfter = buildDateInDays(5);

            // when
            boolean due = EstReenrollmentRules.isDue(notBefore, notAfter, null, NOW);

            // then
            assertThat(due).isTrue();
        }

        @Test
        void returnsNotDue_whenMoreThanHalfRemains() {
            // given — valid 10 days, 6 remain
            Date notBefore = buildDateInDays(-4);
            Date notAfter = buildDateInDays(6);

            // when
            boolean due = EstReenrollmentRules.isDue(notBefore, notAfter, null, NOW);

            // then
            assertThat(due).isFalse();
        }

        @Test
        void returnsDue_whenRemainingDaysEqualTheThreshold() {
            // given — valid 40 days, 30 remain, so half of the validity (20) does not say due
            int threshold = 30;
            Date notBefore = buildDateInDays(-10);
            Date notAfter = buildDateInDays(30);

            // when
            boolean due = EstReenrollmentRules.isDue(notBefore, notAfter, threshold, NOW);

            // then
            assertThat(due).isTrue();
        }

        @Test
        void returnsNotDue_whenRemainingDaysExceedTheThreshold() {
            // given — valid 331 days, 31 remain, so half of the validity (165) would say due
            int threshold = 30;
            Date notBefore = buildDateInDays(-300);
            Date notAfter = buildDateInDays(31);

            // when
            boolean due = EstReenrollmentRules.isDue(notBefore, notAfter, threshold, NOW);

            // then
            assertThat(due).isFalse();
        }

        @Test
        void treatsZeroThresholdAsHalfOfTheValidity_whenHalfRemains() {
            // given — valid 10 days, 5 remain: due only if zero means half of the validity
            int zeroThreshold = 0;
            Date notBefore = buildDateInDays(-5);
            Date notAfter = buildDateInDays(5);

            // when
            boolean due = EstReenrollmentRules.isDue(notBefore, notAfter, zeroThreshold, NOW);

            // then
            assertThat(due).isTrue();
        }

        @Test
        void returnsNotDue_whenZeroThresholdAndMoreThanHalfRemains() {
            // given — valid 10 days, 6 remain
            int zeroThreshold = 0;
            Date notBefore = buildDateInDays(-4);
            Date notAfter = buildDateInDays(6);

            // when
            boolean due = EstReenrollmentRules.isDue(notBefore, notAfter, zeroThreshold, NOW);

            // then
            assertThat(due).isFalse();
        }

        @Test
        void countsWholeDaysOnly_whenPartOfADayRemains() {
            // given — 5 days and 23 hours remain, which count as 5, against a threshold of 5
            int threshold = 5;
            Date notBefore = Date.from(NOW.minus(Duration.ofDays(4)).minus(Duration.ofHours(1)));
            Date notAfter = Date.from(NOW.plus(Duration.ofDays(5)).plus(Duration.ofHours(23)));

            // when
            boolean due = EstReenrollmentRules.isDue(notBefore, notAfter, threshold, NOW);

            // then
            assertThat(due).isTrue();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void assertRefusedWith(ThrowingCallable call, EstError expected) {
        assertThatThrownBy(call)
                .isInstanceOfSatisfying(EstException.class, e -> assertThat(e.error()).isEqualTo(expected));
    }

    private static Date buildDateInDays(int days) {
        return Date.from(NOW.plus(Duration.ofDays(days)));
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static Pkcs10CertificateRequest buildCsr(KeyPair keys, String subject, String... dnsNames)
            throws Exception {
        return EstRequestDecoder.decode(EstCsrFixtures.signedRequestBody(keys, subject, dnsNames));
    }

    private static Pkcs10CertificateRequest buildCsrCarrying(SubjectPublicKeyInfo keyInfo, KeyPair signingKeys,
            String signatureAlgorithm) throws Exception {
        var signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKeys.getPrivate());
        byte[] request = new PKCS10CertificationRequestBuilder(new X500Name(SUBJECT), keyInfo)
                .build(signer)
                .getEncoded();
        return new Pkcs10CertificateRequest(request);
    }

    private static EstSourceCertificate buildSourceOf(KeyPair keys) throws Exception {
        Instant notBefore = NOW.minus(Duration.ofDays(30));
        Instant notAfter = NOW.plus(Duration.ofDays(30));
        X509Certificate certificate = PkiFixtures
                .clientCertificateFor(ca, keys, notBefore, notAfter, SUBJECT,
                        new GeneralName(GeneralName.dNSName, DNS_NAME));
        X500Name subject = X500Name.getInstance(BCStyle.INSTANCE, certificate.getSubjectX500Principal().getEncoded());
        PublicKey publicKey = CryptographyUtil.decodePublicKey(keys.getPublic().getEncoded());
        return new EstSourceCertificate(UUID.randomUUID(), CertificateUtil.getThumbprint(certificate), publicKey,
                subject.toString(), CertificateUtil.serializeSans(CertificateUtil.getSAN(certificate)),
                Date.from(notBefore), Date.from(notAfter));
    }
}

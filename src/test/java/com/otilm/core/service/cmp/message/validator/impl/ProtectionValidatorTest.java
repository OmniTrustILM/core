package com.otilm.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.cmp.CmpEntityUtil;
import com.otilm.core.service.cmp.CmpTestUtil;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.protection.impl.SingatureBaseProtectionStrategy;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the protection-type consistency check in {@link ProtectionValidator}.
 *
 * <p>
 * Regression coverage: a message whose actual protection type contradicts the profile's configured
 * {@code Requested Protection Method} must be rejected with a proper CMP {@code badMessageCheck} rejection (RFC 4210
 * §5.2.7) rather than being allowed through to a strategy that assumes a different type.
 * </p>
 */
class ProtectionValidatorTest {

    private static final ASN1OctetString TID = new DEROctetString(new byte[]{1, 2, 3, 4});
    private static final AlgorithmIdentifier SIGNATURE_ALG = new AlgorithmIdentifier(
            new ASN1ObjectIdentifier("1.2.840.10045.4.3.3")); // ecdsa-with-SHA384
    private static final AlgorithmIdentifier PBM_ALG = new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac);
    private static final AlgorithmIdentifier PBMAC1_ALG = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1);

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void rejectsSignatureMessage_whenProfileRequiresSharedSecret() {
        assertThatThrownBy(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, SIGNATURE_ALG, ProtectionMethod.SHARED_SECRET))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badMessageCheck));
    }

    @Test
    void rejectsPbmMessage_whenProfileRequiresSignature() {
        assertThatThrownBy(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, PBM_ALG, ProtectionMethod.SIGNATURE))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.badMessageCheck));
    }

    @Test
    void acceptsPbmMessage_whenProfileRequiresSharedSecret() {
        assertThatCode(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, PBM_ALG, ProtectionMethod.SHARED_SECRET))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsPbmac1Message_whenProfileRequiresSharedSecret() {
        assertThatCode(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, PBMAC1_ALG, ProtectionMethod.SHARED_SECRET))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsSignatureMessage_whenProfileRequiresSignature() {
        assertThatCode(() -> ProtectionValidator
                .assertMessageProtectionMatchesProfile(TID, SIGNATURE_ALG, ProtectionMethod.SIGNATURE))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsAnyMessage_whenProfileDoesNotConstrainRequestMethod() {
        assertThatCode(() -> ProtectionValidator.assertMessageProtectionMatchesProfile(TID, SIGNATURE_ALG, null))
                .doesNotThrowAnyException();
    }

    /** A message with neither protection bits nor a protectionAlg; the body is irrelevant to the check under test. */
    private static PKIMessage unprotectedMessage() {
        PKIHeader header = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name("CN=user")),
                new GeneralName(new X500Name("CN=ca"))).setTransactionID(TID.getOctets()).build();
        return new PKIMessage(header, new PKIBody(PKIBody.TYPE_CONFIRM, new PKIConfirmContent()));
    }

    @Test
    void rejectsUnprotectedRequest_inRegistrationMode() {
        ConfigurationContext configuration = mock(ConfigurationContext.class);
        when(configuration.isRegistrationMode()).thenReturn(true);

        assertThatThrownBy(() -> new ProtectionValidator().validateIn(unprotectedMessage(), configuration))
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.notAuthorized));
    }

    @Test
    void rejectsUnprotectedRequest_whenNotInRegistrationMode() {
        // given
        ConfigurationContext configuration = mock(ConfigurationContext.class);
        when(configuration.isRegistrationMode()).thenReturn(false);

        // when
        ThrowingCallable validateIn = () -> new ProtectionValidator().validateIn(unprotectedMessage(), configuration);

        // then
        assertThatThrownBy(validateIn)
                .isInstanceOfSatisfying(CmpProcessingException.class,
                        e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.notAuthorized));
    }

    // ── SignatureProtection ───────────────────────────────────────────────────

    @Nested
    class SignatureProtection {

        private final CertificateRepository certificateRepository = mock(CertificateRepository.class);
        private final ConfigurationContext configuration = mock(ConfigurationContext.class);
        private final ProtectionValidator validator = new ProtectionValidator();
        private KeyPair signerKeys;
        private X509CertificateHolder signerCertificate;
        private Certificate protectionCertificate;

        @BeforeEach
        void issueProtectionCertificate() throws Exception {
            RaProfile raProfile = CmpEntityUtil.createRaProfile();
            signerKeys = CmpTestUtil.generateKeyPairEC();
            signerCertificate = CmpTestUtil
                    .makeV3Certificate(BigInteger.TWO, signerKeys, "CN=device", signerKeys, "CN=device");
            protectionCertificate = CmpEntityUtil.createProtectionCertificate(signerCertificate, raProfile.getUuid());
            when(certificateRepository.findByFingerprint(protectionCertificate.getFingerprint()))
                    .thenReturn(Optional.of(protectionCertificate));
            when(configuration.getProtectionMethod()).thenReturn(ProtectionMethod.SIGNATURE);
            when(configuration.getProtectionStrategy()).thenReturn(mock(SingatureBaseProtectionStrategy.class));
            when(configuration.getRaProfile()).thenReturn(raProfile);
            when(configuration.getCmpProfile()).thenReturn(mock(CmpProfile.class));
            validator.setCertificateRepository(certificateRepository);
        }

        @ParameterizedTest
        @EnumSource(value = CertificateValidationStatus.class, names = {"VALID", "EXPIRING"})
        void storesProtectionCertificate_whenIssuedForTheRaProfile(CertificateValidationStatus validationStatus)
                throws Exception {
            // given
            protectionCertificate.setValidationStatus(validationStatus);

            // when
            validator.validateIn(createSignedRequest(), configuration);

            // then
            verify(configuration).setProtectionCertificate(protectionCertificate);
        }

        @ParameterizedTest
        @MethodSource("untrustedProtectionCertificates")
        void rejectsWithSignerNotTrusted_whenProtectionCertificateIsNotTrusted(Consumer<Certificate> distrust)
                throws Exception {
            // given
            distrust.accept(protectionCertificate);
            PKIMessage request = createSignedRequest();

            // when
            ThrowingCallable validateIn = () -> validator.validateIn(request, configuration);

            // then
            assertThatThrownBy(validateIn)
                    .isInstanceOfSatisfying(CmpProcessingException.class,
                            e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.signerNotTrusted));
            verify(configuration, never()).setProtectionCertificate(any());
        }

        @Test
        void rejectsWithSignerNotTrusted_whenProtectionCertificateIsNotInTheInventory() throws Exception {
            // given
            when(certificateRepository.findByFingerprint(any())).thenReturn(Optional.empty());
            PKIMessage request = createSignedRequest();

            // when
            ThrowingCallable validateIn = () -> validator.validateIn(request, configuration);

            // then
            assertThatThrownBy(validateIn)
                    .isInstanceOfSatisfying(CmpProcessingException.class,
                            e -> assertThat(e.getFailureInfo()).isEqualTo(PKIFailureInfo.signerNotTrusted));
            verify(configuration, never()).setProtectionCertificate(any());
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        private PKIMessage createSignedRequest() throws Exception {
            return CmpTestUtil
                    .createSignatureBasedMessage("0102030405060708", signerKeys, signerCertificate,
                            CmpTestUtil.createRevocationBody(BigInteger.ONE))
                    .toASN1Structure();
        }

        static Stream<Named<Consumer<Certificate>>> untrustedProtectionCertificates() {
            Date yesterday = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
            Date tomorrow = Date.from(Instant.now().plus(1, ChronoUnit.DAYS));
            return Stream
                    .of(named("issued for another RA profile",
                            certificate -> certificate.setRaProfileUuid(UUID.randomUUID())),
                            named("issued for no RA profile", certificate -> certificate.setRaProfileUuid(null)),
                            named("archived", certificate -> certificate.setArchived(true)),
                            named("revoked", certificate -> certificate.setState(CertificateState.REVOKED)),
                            named("not validated yet",
                                    certificate -> certificate
                                            .setValidationStatus(CertificateValidationStatus.NOT_CHECKED)),
                            named("validation failed",
                                    certificate -> certificate.setValidationStatus(CertificateValidationStatus.FAILED)),
                            named("validated as revoked",
                                    certificate -> certificate
                                            .setValidationStatus(CertificateValidationStatus.REVOKED)),
                            named("expired", certificate -> certificate.setNotAfter(yesterday)),
                            named("not valid yet", certificate -> certificate.setNotBefore(tomorrow)));
        }
    }
}

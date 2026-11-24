package com.otilm.core.service.acme;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.Identifier;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReplacesValidatorTest {

    private static final String CERT_ID = "AQIDBA.AIdlQyE";
    private static final String SANS = "{\"dNSName\":[\"www.example.com\"],\"iPAddress\":[\"192.0.2.7\"]}";

    @Mock
    private AriCertificateLookup ariCertificateLookup;
    @Mock
    private AcmeOrderRepository acmeOrderRepository;
    @Mock
    private CertificateRelationRepository certificateRelationRepository;
    @Mock
    private CertificateRepository certificateRepository;

    private ReplacesValidator validator;
    private AcmeAccount account;
    private RaProfile raProfile;
    private Certificate predecessor;

    @BeforeEach
    void createValidator() {
        validator = new ReplacesValidator();
        validator.setAriCertificateLookup(ariCertificateLookup);
        validator.setAcmeOrderRepository(acmeOrderRepository);
        validator.setCertificateRelationRepository(certificateRelationRepository);
        validator.setCertificateRepository(certificateRepository);
        account = new AcmeAccount();
        account.setUuid(UUID.randomUUID());
        account.setAccountId("account");
        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        predecessor = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCommonName("example.com")
                .withSubjectAlternativeNames(SANS)
                .build();
        lenient().when(ariCertificateLookup.find(any(), any())).thenReturn(Optional.of(predecessor));
        lenient()
                .when(acmeOrderRepository
                        .existsByCertificateReferenceUuidAndAcmeAccountUuid(predecessor.getUuid(), account.getUuid()))
                .thenReturn(true);
    }

    @Test
    void returnsThePredecessor_whenEveryCheckPasses() throws Exception {
        // given — a certificate of the account sharing www.example.com with the order

        // when
        Certificate validated = validator.validate(CERT_ID, account, List.of(dns("WWW.example.com")), raProfile);

        // then
        assertThat(validated).isSameAs(predecessor);
        InOrder lockThenCheck = inOrder(certificateRepository, acmeOrderRepository, certificateRelationRepository);
        lockThenCheck.verify(certificateRepository).findAndLockFreshByUuid(predecessor.getUuid());
        lockThenCheck.verify(acmeOrderRepository).existsLiveOrderReplacing(eq(predecessor.getUuid()), any(Date.class));
        lockThenCheck
                .verify(certificateRelationRepository)
                .existsByIdPredecessorCertificateUuidAndSuccessorCertificateState(predecessor.getUuid(),
                        CertificateState.ISSUED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "www.example.com"})
    void acceptsADnsIdentifier_whenItIsTheCommonNameOrASubjectAlternativeName(String sharedName) throws Exception {
        // when
        Certificate validated = validator.validate(CERT_ID, account, List.of(dns(sharedName)), raProfile);

        // then
        assertThat(validated).isSameAs(predecessor);
    }

    @Test
    void acceptsAnIpIdentifier_whenItIsAnAddressSubjectAlternativeName() throws Exception {
        // when
        Certificate validated = validator.validate(CERT_ID, account, List.of(ip("192.0.2.7")), raProfile);

        // then
        assertThat(validated).isSameAs(predecessor);
    }

    @ParameterizedTest
    @ValueSource(strings = {"nodot", "AQ+D.AQID", "A.B.C", ""})
    void refusesAsMalformed_whenTheIdentifierIsMalformed(String malformed) {
        // when
        ThrowingCallable validate = () -> validator
                .validate(malformed, account, List.of(dns("example.com")), raProfile);

        // then
        assertRefused(validate);
    }

    @Test
    void refusesAsMalformed_whenTheCertificateIsUnknown() {
        // given
        when(ariCertificateLookup.find(eq(raProfile.getUuid()), any())).thenReturn(Optional.empty());

        // when
        ThrowingCallable validate = () -> validator.validate(CERT_ID, account, List.of(dns("example.com")), raProfile);

        // then
        assertRefused(validate);
    }

    @Test
    void refusesAsMalformed_whenAnotherAccountOrderedTheCertificate() {
        // given
        when(acmeOrderRepository
                .existsByCertificateReferenceUuidAndAcmeAccountUuid(predecessor.getUuid(), account.getUuid()))
                .thenReturn(false);

        // when
        ThrowingCallable validate = () -> validator.validate(CERT_ID, account, List.of(dns("example.com")), raProfile);

        // then
        assertRefused(validate);
    }

    @Test
    void refusesAsMalformed_whenNoIdentifierIsShared() {
        // given
        var unrelated = List.of(dns("other.example.com"), ip("192.0.2.8"));

        // when
        ThrowingCallable validate = () -> validator.validate(CERT_ID, account, unrelated, raProfile);

        // then
        assertRefused(validate);
    }

    @Test
    void refusesAsAlreadyReplaced_whenALiveOrderReplacesIt() {
        // given
        when(acmeOrderRepository.existsLiveOrderReplacing(eq(predecessor.getUuid()), any(Date.class))).thenReturn(true);

        // when
        ThrowingCallable validate = () -> validator.validate(CERT_ID, account, List.of(dns("example.com")), raProfile);

        // then
        assertAlreadyReplaced(validate);
    }

    @Test
    void refusesAsAlreadyReplaced_whenItHasAnIssuedSuccessor() {
        // given
        when(certificateRelationRepository
                .existsByIdPredecessorCertificateUuidAndSuccessorCertificateState(predecessor.getUuid(),
                        CertificateState.ISSUED))
                .thenReturn(true);

        // when
        ThrowingCallable validate = () -> validator.validate(CERT_ID, account, List.of(dns("example.com")), raProfile);

        // then
        assertAlreadyReplaced(validate);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Identifier dns(String value) {
        return identifier("dns", value);
    }

    private static Identifier ip(String value) {
        return identifier("ip", value);
    }

    private static Identifier identifier(String type, String value) {
        Identifier identifier = new Identifier();
        identifier.setType(type);
        identifier.setValue(value);
        return identifier;
    }

    private static void assertRefused(ThrowingCallable validate) {
        assertThatThrownBy(validate).isInstanceOfSatisfying(AcmeProblemDocumentException.class, e -> {
            assertThat(e.getHttpStatusCode()).isEqualTo(400);
            assertThat(e.getProblemDocument().getType()).isEqualTo(Problem.MALFORMED.getType());
            assertThat(e.getProblemDocument().getDetail()).isEqualTo(ReplacesValidator.REFUSAL_DETAIL);
        });
    }

    private static void assertAlreadyReplaced(ThrowingCallable validate) {
        assertThatThrownBy(validate).isInstanceOfSatisfying(AcmeProblemDocumentException.class, e -> {
            assertThat(e.getHttpStatusCode()).isEqualTo(409);
            assertThat(e.getProblemDocument().getType()).isEqualTo(Problem.ALREADY_REPLACED.getType());
        });
    }
}

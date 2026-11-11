package com.otilm.core.certificate.type.stub;

import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.core.certificate.type.CertificateTypeHandlerException;
import com.otilm.core.certificate.type.ParsedCertificate;
import com.otilm.core.certificate.type.ParsedRequest;
import com.otilm.core.certificate.type.UnsupportedCertificateTypeException;
import com.otilm.core.certificate.type.ValidityPrecision;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static com.otilm.core.certificate.type.stub.StubCertificateFixtures.STUB_NOT_AFTER;
import static com.otilm.core.certificate.type.stub.StubCertificateFixtures.STUB_NOT_BEFORE;
import static com.otilm.core.certificate.type.stub.StubCertificateFixtures.certificate;
import static com.otilm.core.certificate.type.stub.StubCertificateFixtures.keyPair;
import static com.otilm.core.certificate.type.stub.StubCertificateFixtures.request;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StubCertificateTypeHandlerTest {

    private final StubCertificateTypeHandler handler = new StubCertificateTypeHandler();

    @Test
    void readsTheCommonProperties_whenParsingACertificate() {
        // given
        byte[] stubCertificate = certificate("42", "holder-one");

        // when
        ParsedCertificate parsed = handler.parseCertificate(stubCertificate).orElseThrow();

        // then
        assertThat(parsed.properties().identifier()).isEqualTo("42");
        assertThat(parsed.properties().holder()).isEqualTo("holder-one");
        assertThat(parsed.properties().publicKey()).isEqualTo(keyPair().getPublic());
        assertThat(parsed.properties().issuerReference()).isNull();
    }

    @Test
    void reportsValidityInWholeDays_whenParsingACertificate() {
        // given
        byte[] stubCertificate = certificate("42", "holder-one");

        // when
        ParsedCertificate parsed = handler.parseCertificate(stubCertificate).orElseThrow();

        // then
        assertThat(parsed.properties().validity().precision()).isEqualTo(ValidityPrecision.DATE);
        assertThat(parsed.properties().validity().notBefore()).isEqualTo(Instant.parse(STUB_NOT_BEFORE + "T00:00:00Z"));
        assertThat(parsed.properties().validity().notAfter()).isEqualTo(Instant.parse(STUB_NOT_AFTER + "T00:00:00Z"));
    }

    @Test
    void returnsEmpty_whenTheContentIsNotAStubCertificate() {
        // given
        byte[] otherContent = "-----BEGIN CERTIFICATE-----".getBytes(StandardCharsets.UTF_8);

        // when
        var parsed = handler.parseCertificate(otherContent);

        // then
        assertThat(parsed).isEmpty();
    }

    @Test
    void throwsHandlerException_whenAStubCertificateIsIncomplete() {
        // given
        byte[] incomplete = "STUB-CERT|42|holder-one".getBytes(StandardCharsets.UTF_8);

        // when
        ThrowingCallable parse = () -> handler.parseCertificate(incomplete);

        // then
        assertThatThrownBy(parse)
                .isInstanceOf(CertificateTypeHandlerException.class)
                .hasMessageContaining("six fields");
    }

    @Test
    void doesNotSupportRevocationOrChainValidation() {
        // given — the stub declares only renewal and compliance

        // when
        boolean revoke = handler.supports(CertificateOperation.REVOKE);
        boolean chainValidation = handler.supports(CertificateOperation.VALIDATE_CHAIN);

        // then
        assertThat(revoke).isFalse();
        assertThat(chainValidation).isFalse();
    }

    @Test
    void throwsUnsupportedNamingTypeAndOperation_whenRequiringAnOperationItLacks() {
        // given
        CertificateOperation unsupported = CertificateOperation.REVOKE;

        // when
        ThrowingCallable requireRevoke = () -> handler.requireSupport(unsupported);

        // then
        assertThatThrownBy(requireRevoke)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .hasMessageContaining(StubCertificateTypeHandler.TYPE_CODE)
                .hasMessageContaining(unsupported.name());
    }

    @Test
    void linksNoIssuer_whenAskingWhetherACertificateWasIssuedByAnother() {
        // given
        ParsedCertificate certificate = handler.parseCertificate(certificate("1", "holder-one")).orElseThrow();
        ParsedCertificate other = handler.parseCertificate(certificate("2", "holder-two")).orElseThrow();

        // when
        boolean issuedBy = handler.isIssuedBy(certificate, other);

        // then
        assertThat(issuedBy).isFalse();
    }

    @Test
    void acceptsTheRequest_whenItIsSignedAndNoCertificateIsReplaced() {
        // given
        ParsedRequest signed = handler.parseRequest(request("holder-one", true, "")).orElseThrow();

        // when
        boolean valid = handler.verifySignature(signed, null);

        // then
        assertThat(valid).isTrue();
    }

    @Test
    void rejectsTheRequest_whenItIsNotSigned() {
        // given
        ParsedRequest unsigned = handler.parseRequest(request("holder-one", false, "")).orElseThrow();

        // when
        boolean valid = handler.verifySignature(unsigned, null);

        // then
        assertThat(valid).isFalse();
    }

    @Test
    void acceptsTheRequest_whenItIsCountersignedForTheCurrentCertificate() {
        // given
        ParsedCertificate current = handler.parseCertificate(certificate("42", "holder-one")).orElseThrow();
        ParsedRequest renewal = handler.parseRequest(request("holder-one", true, "42")).orElseThrow();

        // when
        boolean valid = handler.verifySignature(renewal, current);

        // then
        assertThat(valid).isTrue();
    }

    @Test
    void rejectsTheRequest_whenItIsCountersignedForAnotherCertificate() {
        // given
        ParsedCertificate current = handler.parseCertificate(certificate("42", "holder-one")).orElseThrow();
        ParsedRequest renewal = handler.parseRequest(request("holder-one", true, "99")).orElseThrow();

        // when
        boolean valid = handler.verifySignature(renewal, current);

        // then
        assertThat(valid).isFalse();
    }

    @Test
    void findsNoViolation_whenCheckingProfileLimitsByDefault() {
        // given
        ParsedRequest renewal = handler.parseRequest(request("holder-one", true, "")).orElseThrow();

        // when
        var violations = handler.checkProfileLimits(renewal, null);

        // then
        assertThat(violations).isEmpty();
    }
}

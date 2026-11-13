package com.otilm.core.service.est.message;

import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.util.EstCsrFixtures;
import java.security.Security;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EstServerKeyGenerationRequestTest {

    private static final String SUBJECT = "CN=device-1,O=Example";
    private static final String DNS_NAME = "device-1.example.com";

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"1.2.840.113549.1.9.16.2.37", "1.2.840.113549.1.9.16.2.54"})
    void refusesEncryptedKeyDelivery_whenTheRequestCarriesAKeyIdentifierAttribute(String attributeOid)
            throws Exception {
        // given
        PKCS10CertificationRequest request = decode(EstCsrFixtures
                .signedRequestBodyWithAttribute(SUBJECT, DNS_NAME, new ASN1ObjectIdentifier(attributeOid),
                        new DEROctetString(new byte[]{1, 2, 3})));

        // when
        ThrowingCallable check = () -> EstServerKeyGenerationRequest.requireUnprotectedDelivery(request);

        // then
        assertThatThrownBy(check)
                .isInstanceOfSatisfying(EstException.class,
                        e -> assertThat(e.error()).isEqualTo(EstError.ENCRYPTED_KEY_DELIVERY_UNSUPPORTED));
    }

    @Test
    void acceptsTheRequest_whenItCarriesNeitherKeyIdentifierAttribute() throws Exception {
        // given
        PKCS10CertificationRequest request = decode(EstCsrFixtures.signedRequestBody(SUBJECT, DNS_NAME));

        // when
        ThrowingCallable check = () -> EstServerKeyGenerationRequest.requireUnprotectedDelivery(request);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    @Test
    void keepsSubjectAndRequestedExtensions() throws Exception {
        // given
        PKCS10CertificationRequest request = decode(EstCsrFixtures.signedRequestBody(SUBJECT, DNS_NAME));

        // when
        EstServerKeyGenerationRequest.Content content = EstServerKeyGenerationRequest.contentOf(request);

        // then
        assertThat(content.subject()).isEqualTo(new X500Name(SUBJECT));
        assertThat(content.extensions().getExtensionOIDs()).containsExactly(Extension.subjectAlternativeName);
    }

    @Test
    void keepsSubjectAndExtensionsOnly_whenTheRequestAlsoCarriesAChallengePassword() throws Exception {
        // given
        PKCS10CertificationRequest request = decode(EstCsrFixtures
                .signedRequestBodyWithAttribute(SUBJECT, DNS_NAME, PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                        new DERPrintableString("secret")));

        // when
        EstServerKeyGenerationRequest.Content content = EstServerKeyGenerationRequest.contentOf(request);

        // then
        assertThat(content.subject()).isEqualTo(new X500Name(SUBJECT));
        assertThat(content.extensions().getExtensionOIDs()).containsExactly(Extension.subjectAlternativeName);
    }

    @Test
    void returnsNoExtensions_whenTheRequestAsksForNone() throws Exception {
        // given
        PKCS10CertificationRequest request = decode(EstCsrFixtures.signedRequestBody(SUBJECT));

        // when
        EstServerKeyGenerationRequest.Content content = EstServerKeyGenerationRequest.contentOf(request);

        // then
        assertThat(content.extensions()).isNull();
    }

    @Test
    void dropsTheSubjectKeyIdentifierAndKeepsTheOtherExtensions_whenTheRequestAsksForOne() throws Exception {
        // given
        var clientKeyIdentifier = new Extension(Extension.subjectKeyIdentifier, false,
                new DEROctetString(new SubjectKeyIdentifier(new byte[]{1, 2, 3})));
        var subjectAlternativeName = new Extension(Extension.subjectAlternativeName, false,
                new DEROctetString(new GeneralNames(new GeneralName(GeneralName.dNSName, DNS_NAME))));
        PKCS10CertificationRequest request = decode(EstCsrFixtures
                .signedRequestBodyWithExtensions(SUBJECT,
                        new Extensions(new Extension[]{clientKeyIdentifier, subjectAlternativeName})));

        // when
        EstServerKeyGenerationRequest.Content content = EstServerKeyGenerationRequest.contentOf(request);

        // then
        assertThat(content.extensions().getExtensionOIDs()).containsExactly(Extension.subjectAlternativeName);
    }

    @Test
    void returnsNoExtensions_whenTheRequestAsksOnlyForASubjectKeyIdentifier() throws Exception {
        // given
        var clientKeyIdentifier = new Extension(Extension.subjectKeyIdentifier, false,
                new DEROctetString(new SubjectKeyIdentifier(new byte[]{1, 2, 3})));
        PKCS10CertificationRequest request = decode(
                EstCsrFixtures.signedRequestBodyWithExtensions(SUBJECT, new Extensions(clientKeyIdentifier)));

        // when
        EstServerKeyGenerationRequest.Content content = EstServerKeyGenerationRequest.contentOf(request);

        // then
        assertThat(content.extensions()).isNull();
    }

    private static PKCS10CertificationRequest decode(byte[] body) {
        Pkcs10CertificateRequest decoded = EstRequestDecoder.decode(body);
        return decoded.getJcaObject();
    }
}

package com.otilm.core.service.v2;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.api.model.core.raprofile.RaProfileCertificateRequestAttributesUpdateDto;
import com.otilm.api.model.core.v2.ClientCertificateRequestDto;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import com.otilm.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import com.otilm.api.exception.ValidationException;

import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A strict RA Profile whose resolved set requires a CN rejects an uploaded CSR missing CN; a lenient profile accepts the same CSR.
 */
class CertificateRequestModeBValidationTest extends BaseSpringBootTest {

    @Autowired
    private ClientOperationExternalService clientOperationService;

    @Autowired
    private RaProfileCertificateRequestAttributeService requestAttributeService;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    private WireMockServer mockServer;
    private RaProfile raProfile;
    private String csrMissingCommonName;

    @BeforeEach
    void wireStrictRaProfileRequiringCommonName() throws Exception {
        // given — a strict RA profile backed by a mock authority connector that serves the request-attribute set
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        Connector connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("modeb-authority-1");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        raProfile = new RaProfile();
        raProfile.setName("modeBTestRaProfile");
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile.setAuthorityInstanceReferenceUuid(authorityInstanceReference.getUuid());
        raProfile.setEnabled(true);
        raProfile = raProfileRepository.save(raProfile);

        stubIssueAttributesAndSigning();

        RaProfileCertificateRequestAttributesUpdateDto config = new RaProfileCertificateRequestAttributesUpdateDto();
        config.setRequestAttributes(List.of(CsrAttributes.commonNameAttribute()));
        config.setMergeMode(AttributeSetMergeMode.STATIC_ONLY);
        config.setExternalCsrValidationStrict(Boolean.TRUE);
        requestAttributeService.updateConfiguration(raProfile, config);

        csrMissingCommonName = pemEncodedCsrWithSubject("O=Acme,C=US");
    }

    @AfterEach
    void stopMockServer() {
        if (mockServer != null) {
            mockServer.stop();
        }
    }

    @Test
    void rejectsUploadedCsr_whenStrictProfileAndRequiredRdnMissing() {
        // given — the strict RA profile from @BeforeEach and an uploaded PKCS#10 whose subject has no CommonName
        ClientCertificateRequestDto request = uploadRequest(csrMissingCommonName);

        // when / then — a policy failure surfaces as a 422 ValidationException carrying the shaped details
        assertThatThrownBy(() -> clientOperationService.submitCertificateRequest(request, null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("request-attribute policy");

        // and — no row reaches PENDING_ISSUE; nothing beyond the pre-seeded fixtures is persisted
        assertThat(certificateRepository.findAll())
                .noneMatch(c -> c.getRaProfileUuid() != null && c.getRaProfileUuid().equals(raProfile.getUuid()));
    }

    @Test
    void acceptsUploadedCsr_whenLenientProfileAndRequiredRdnMissing() throws Exception {
        // given — same CSR, RA profile reconfigured with externalCsrValidationStrict=false
        RaProfileCertificateRequestAttributesUpdateDto lenientConfig = new RaProfileCertificateRequestAttributesUpdateDto();
        lenientConfig.setRequestAttributes(List.of(CsrAttributes.commonNameAttribute()));
        lenientConfig.setMergeMode(AttributeSetMergeMode.STATIC_ONLY);
        lenientConfig.setExternalCsrValidationStrict(Boolean.FALSE);
        requestAttributeService.updateConfiguration(raProfile, lenientConfig);

        ClientCertificateRequestDto request = uploadRequest(csrMissingCommonName);

        // when
        CertificateDetailDto certificate = clientOperationService.submitCertificateRequest(request, null);

        // then — issuance proceeds; no validation exception
        assertThat(certificate).isNotNull();
    }

    @Test
    void rejectsMalformedUploadedCsr_asValidationError_notServerFault() throws Exception {
        // given — a structurally valid PKCS#10 whose extensionRequest attribute carries an EMPTY value
        // set: parsing it explodes with an unchecked exception rather than a typed parse exception
        ClientCertificateRequestDto request = uploadRequest(pemEncodedCsrWithEmptyExtensionRequest());

        // when / then — shaped 422 client error, not an unhandled 500
        assertThatThrownBy(() -> clientOperationService.submitCertificateRequest(request, null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("could not be processed for validation");
    }

    @Test
    void rejectsUploadedCsr_whenStrictProfileAndAttributeSetCannotBeResolved() {
        // given — a strict profile whose merge mode consults the authority connector, and that connector errors
        RaProfileCertificateRequestAttributesUpdateDto config = new RaProfileCertificateRequestAttributesUpdateDto();
        config.setRequestAttributes(List.of(CsrAttributes.commonNameAttribute()));
        config.setMergeMode(AttributeSetMergeMode.MERGE);
        config.setExternalCsrValidationStrict(Boolean.TRUE);
        requestAttributeService.updateConfiguration(raProfile, config);

        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.serverError().withBody("authority connector is unavailable")));

        ClientCertificateRequestDto request = uploadRequest(csrMissingCommonName);

        // when / then — strict policy fails closed: an unavailable attribute set blocks issuance
        assertThatThrownBy(() -> clientOperationService.submitCertificateRequest(request, null))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("unavailable");

        // and — nothing is persisted for the profile
        assertThat(certificateRepository.findAll())
                .noneMatch(c -> c.getRaProfileUuid() != null && c.getRaProfileUuid().equals(raProfile.getUuid()));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private ClientCertificateRequestDto uploadRequest(String pemCsr) {
        ClientCertificateRequestDto request = new ClientCertificateRequestDto();
        request.setRaProfileUuid(raProfile.getUuid());
        request.setFormat(CertificateRequestFormat.PKCS10);
        request.setRequest(pemCsr);
        return request;
    }

    private void stubIssueAttributesAndSigning() throws Exception {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair issuerKeyPair = kpg.generateKeyPair();
        X500Name issuerDn = new X500Name("CN=Mode B Test CA");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeyPair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerDn, BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() - 60_000L),
                new Date(System.currentTimeMillis() + 3_600_000L),
                issuerDn, issuerKeyPair.getPublic());
        var issuedCert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        String certificateData = Base64.getEncoder().encodeToString(issuedCert.getEncoded());

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue"))
                .willReturn(WireMock.okJson("{ \"certificateData\": \"" + certificateData + "\" }")));
    }

    /**
     * Hand-assembles a PKCS#10 whose {@code extensionRequest} attribute has an empty value set —
     * legal ASN.1 that no BC builder produces, and that fails extension extraction with an unchecked
     * exception. The signature is a placeholder: Mode B validation runs before any signature check.
     */
    private static String pemEncodedCsrWithEmptyExtensionRequest() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        Attribute emptyExtensionRequest = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet());
        CertificationRequestInfo info = new CertificationRequestInfo(
                new X500Name("O=Acme"),
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()),
                new DERSet(emptyExtensionRequest));
        CertificationRequest csr = new CertificationRequest(info,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE),
                new DERBitString(new byte[]{0}));

        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        }
        return stringWriter.toString();
    }

    /** Builds a self-signed PKCS#10 request over the given subject DN and PEM-encodes it. */
    private static String pemEncodedCsrWithSubject(String subjectDn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = builder.build(signer);

        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        }
        return stringWriter.toString();
    }
}

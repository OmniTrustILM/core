package com.otilm.core.integration.service.v2.impl;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Proves that a request-attribute policy violation raised on the v2 issue path reaches the caller as {@link RequestAttributePolicyViolationException}.
 */
class ClientOperationRequestAttributePropagationITest extends BaseSpringBootTest {

    @Autowired
    private ClientOperationExternalService clientOperationService;

    @MockitoBean
    private RaProfileCertificateRequestAttributeService requestAttributeService;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    private RaProfile raProfile;
    private AuthorityInstanceReference authorityInstanceReference;

    private WireMockServer mockServer;

    @BeforeEach
    void startMockAuthorityAndWireV2Profile() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        AuthorityFixtures.Repos fixtureRepos = new AuthorityFixtures.Repos(
                connectorRepository, functionGroupRepository, connector2FunctionGroupRepository,
                authorityInstanceReferenceRepository, raProfileRepository, connectorInterfaceRepository);
        AuthorityFixtures.Fixture fixture = AuthorityFixtures.v2Authority(fixtureRepos, mockServer, null);
        authorityInstanceReference = fixture.authority();
        raProfile = fixture.raProfile();
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void propagatesSubtypeNotWrapped_whenPolicyViolated() throws Exception {
        // given — a strict RA profile whose resolved set requires a CN, and an uploaded CSR that omits it:
        // a genuine policy violation (a client fault), distinct from an availability failure
        when(requestAttributeService.resolveIssueAttributeSet(any())).thenReturn(List.of(CsrAttributes.commonNameAttribute()));
        when(requestAttributeService.resolveExternalCsrValidationStrict(any())).thenReturn(true);
        ClientCertificateSignRequestDto request = new ClientCertificateSignRequestDto();
        request.setRequest(pemEncodedCsrWithSubject("O=Acme,C=US"));
        request.setFormat(CertificateRequestFormat.PKCS10);
        request.setAttributes(List.of());

        // when / then — the typed subtype reaches the caller un-wrapped (not a CertificateOperationException),
        // carrying the shaped policy message and no internal identifiers
        var authorityUuid = authorityInstanceReference.getSecuredParentUuid();
        var raProfileUuid = raProfile.getSecuredUuid();
        assertThatThrownBy(() -> clientOperationService.issueCertificate(authorityUuid, raProfileUuid, request, null))
                .isInstanceOf(RequestAttributePolicyViolationException.class)
                .satisfies(ex -> assertThat(ex.getMessage())
                        .as("message should identify the RA profile")
                        .contains("'" + raProfile.getName() + "'")
                        .as("message must not leak SQL or an internal exception type name")
                        .doesNotContainIgnoringCase("select ")
                        .doesNotContain("NotFoundException"));
    }

    /** Builds a self-signed PKCS#10 request over the given subject DN (no CommonName) and PEM-encodes it. */
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

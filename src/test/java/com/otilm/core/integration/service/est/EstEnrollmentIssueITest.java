package com.otilm.core.integration.service.est;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.est.EstMediaTypes;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.IssueActionData;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.CertificateRequestPolicySeeder;
import com.otilm.core.util.seeders.EstRouteSeeder;
import com.otilm.core.util.seeders.SecretSeeder;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicCredentials;
import static com.otilm.core.util.EstClientCredentialsFixtures.certificateCredentials;
import static com.otilm.core.util.mocks.AuthorityV2ConnectorStubs.ISSUE_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.doThrow;

/**
 * An authenticated {@code /simpleenroll} through the service, against a connector double that issues at once. The
 * mocked {@link ActionProducer} runs the queued issue synchronously, as the broker consumer would.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class EstEnrollmentIssueITest extends BaseSpringBootTest {

    private static final String ESTPROFILE_NAME = "devices-profile";
    private static final String RA_PROFILE_NAME = "devices-ra";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "s3cret";
    private static final String CLIENT_SUBJECT = "CN=device-1,O=Acme";
    private static final String CLIENT_DNS_NAME = "device-1.example";
    private static final String ESTPROFILE_ATTRIBUTE_VALUE = "value-of-the-est-profile";
    private static final String RA_ATTRIBUTE_VALUE = "value-of-the-ra-activation";

    @Autowired
    private EstExternalService estService;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private SecretSeeder secrets;

    @Autowired
    private ClientOperationInternalService clientOperationService;

    @Autowired
    private ActionProducer actionProducer;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateProtocolAssociationRepository protocolAssociationRepository;

    @Autowired
    private ProtocolCertificateAssociationsRepository certificateAssociationsRepository;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private CertificateRequestPolicySeeder requestPolicies;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private CertificateExternalService certificateService;

    private WireMockServer authService;
    private WireMockServer connector;
    private RaProfile raProfile;
    private X509Certificate issued;

    @BeforeEach
    void startConnectorThatIssuesAtOnceAndAuthService() throws Exception {
        authService = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authService.start();
        connector = LoopbackWireMock.start();
        issued = PkiFixtures.clientCertificate(PkiFixtures.rootCa("EST Issuing Root"));
        stubConnector(List.of(), "{ \"certificateData\": \"" + base64(issued) + "\" }");
        raProfile = routes.seedRaProfile(connector, RA_PROFILE_NAME);
        Mockito.doAnswer(invocation -> {
            ActionMessage message = invocation.getArgument(0);
            if (message.getResourceAction() == ResourceAction.ISSUE) {
                clientOperationService
                        .issueCertificateAction(message.getResourceUuid(),
                                IssueActionData.certificateRequestUuidOf(message.getData()), false);
            }
            return null;
        }).when(actionProducer).produceMessage(Mockito.any());
    }

    @AfterEach
    void stopConnector() {
        authService.stop();
        connector.stop();
    }

    // ── raBasic ───────────────────────────────────────────────────────────────

    @Test
    void answersIssuedCertificate_whenConnectorIssuesAtOnce() throws Exception {
        // given
        Group group = saveGroup("device-operators");
        UUID owner = UUID.randomUUID();
        stubOwner(owner);
        EstProfile estProfile = seedRaBasicProfile();
        applyAssociations(estProfile, owner, group);

        // when
        ResponseEntity<byte[]> response = estService
                .simpleEnroll(estProfile.getName(), EstCsrFixtures.signedRequestBody(),
                        basicCredentials(USERNAME, PASSWORD));

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateOf(response)).isEqualTo(issued);
        Certificate inventory = theOnlyCertificate();
        assertThat(inventory.getState()).isEqualTo(CertificateState.ISSUED);
        assertThat(inventory.getFingerprint()).isEqualTo(CertificateUtil.getThumbprint(issued));
        CertificateProtocolAssociation attribution = protocolAssociationRepository
                .findAll()
                .stream()
                .filter(association -> association.getCertificateUuid().equals(inventory.getUuid()))
                .findFirst()
                .orElseThrow();
        assertThat(attribution.getProtocol()).isEqualTo(CertificateProtocol.EST);
        assertThat(attribution.getProtocolProfileUuid()).isEqualTo(estProfile.getUuid());
        assertThat(certificateRepository.findWithAssociationsByUuid(inventory.getUuid()).orElseThrow().getGroups())
                .extracting(Group::getUuid)
                .containsExactly(group.getUuid());
        assertThat(certificateService.getCertificate(inventory.getSecuredUuid()).getOwnerUuid())
                .isEqualTo(owner.toString());
    }

    @Test
    void sendsEstProfileIssueAttributes_whenRouteNamesEstProfile() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile();
        storeEstProfileIssueAttribute(estProfile);

        // when
        estService
                .simpleEnroll(estProfile.getName(), EstCsrFixtures.signedRequestBody(),
                        basicCredentials(USERNAME, PASSWORD));

        // then
        connector
                .verify(1,
                        WireMock
                                .postRequestedFor(WireMock.urlPathMatching(ISSUE_PATH))
                                .withRequestBody(WireMock.containing(ESTPROFILE_ATTRIBUTE_VALUE)));
    }

    @Test
    void sendsRaActivationIssueAttributes_whenRouteNamesRaProfile() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile();
        routes.activateEst(raProfile, estProfile);
        storeRaActivationIssueAttribute();

        // when
        estService
                .simpleEnroll(raProfile.getName(), EstCsrFixtures.signedRequestBody(),
                        basicCredentials(USERNAME, PASSWORD));

        // then
        connector
                .verify(1,
                        WireMock
                                .postRequestedFor(WireMock.urlPathMatching(ISSUE_PATH))
                                .withRequestBody(WireMock.containing(RA_ATTRIBUTE_VALUE)));
    }

    // ── Certificate policies ──────────────────────────────────────────────────

    @Test
    void answersIssuedCertificate_whenClientIsVendorDevice() throws Exception {
        // given
        Ca root = PkiFixtures.rootCa("EST Root CA");
        Ca issuingCa = PkiFixtures.intermediateCa(root, "EST Issuing CA");
        EstProfile estProfile = routes
                .seedEstProfile(ESTPROFILE_NAME, EstAuthenticationPolicy.VENDOR_MTLS, raProfile, List.of(),
                        List.of(routes.seedCertificate(root.certificate())));
        X509Certificate device = PkiFixtures
                .clientCertificateFor(issuingCa, CLIENT_SUBJECT, new GeneralName(GeneralName.dNSName, CLIENT_DNS_NAME));
        EstClientCredentials credentials = certificateCredentials(device, issuingCa.certificate());

        // when
        ResponseEntity<byte[]> response = estService
                .simpleEnroll(estProfile.getName(), EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT, CLIENT_DNS_NAME),
                        credentials);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateOf(response)).isEqualTo(issued);
    }

    @Test
    void answersIssuedCertificate_whenClientIsRegistrationAuthority() throws Exception {
        // given
        Ca root = PkiFixtures.rootCa("EST Root CA");
        Ca issuingCa = PkiFixtures.intermediateCa(root, "EST Issuing CA");
        EstProfile estProfile = routes
                .seedEstProfile(ESTPROFILE_NAME, EstAuthenticationPolicy.RA_MTLS, raProfile, List.of(),
                        List.of(routes.seedCertificate(root.certificate())));
        EstClientCredentials credentials = certificateCredentials(PkiFixtures.raCertificate(issuingCa),
                issuingCa.certificate());

        // when
        ResponseEntity<byte[]> response = estService
                .simpleEnroll(estProfile.getName(), EstCsrFixtures.signedRequestBody(), credentials);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(certificateOf(response)).isEqualTo(issued);
    }

    // ── Refusals ──────────────────────────────────────────────────────────────

    @Test
    void refusesWithPolicyText_whenRequestAttributePolicyIsViolated() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile();
        requestPolicies.requireStrictRequestAttributes();
        byte[] requestWithoutCommonName = EstCsrFixtures.signedRequestBody("O=Acme");

        // when
        ThrowingCallable enroll = () -> estService
                .simpleEnroll(estProfile.getName(), requestWithoutCommonName, basicCredentials(USERNAME, PASSWORD));

        // then
        assertThatThrownBy(enroll).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.POLICY_VIOLATION);
            assertThat(refusal.realm()).contains(estProfile.getName());
            assertThat(refusal.detail()).hasValueSatisfying(detail -> assertThat(detail).contains(RA_PROFILE_NAME));
        });
        assertThat(certificateRepository.count()).isZero();
    }

    @Test
    void answersRejected_whenComplianceRejectsTheRequest_andForTheRetry() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile();
        requestPolicies.requireRsaRequests(raProfile);
        byte[] request = EstCsrFixtures.signedRequestBody();
        EstClientCredentials credentials = basicCredentials(USERNAME, PASSWORD);
        Throwable first = catchThrowable(() -> estService.simpleEnroll(estProfile.getName(), request, credentials));

        // when
        ThrowingCallable retry = () -> estService.simpleEnroll(estProfile.getName(), request, credentials);

        // then
        assertThat(first)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.REQUEST_REJECTED));
        assertThatThrownBy(retry)
                .isInstanceOfSatisfying(EstException.class,
                        refusal -> assertThat(refusal.error()).isEqualTo(EstError.REQUEST_REJECTED));
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.REJECTED);
    }

    @Test
    void answersIssuanceFailed_whenQueueingFails() throws Exception {
        // given
        EstProfile estProfile = seedRaBasicProfile();
        doThrow(new IllegalStateException("broker down")).when(actionProducer).produceMessage(Mockito.any());

        // when
        ThrowingCallable enroll = () -> estService
                .simpleEnroll(estProfile.getName(), EstCsrFixtures.signedRequestBody(),
                        basicCredentials(USERNAME, PASSWORD));

        // then
        assertThatThrownBy(enroll).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(EstError.ISSUANCE_FAILED);
            assertThat(refusal.realm()).contains(estProfile.getName());
        });
        assertThat(theOnlyCertificate().getState()).isEqualTo(CertificateState.FAILED);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private EstProfile seedRaBasicProfile() {
        Secret credential = secrets.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
        return routes.seedRaBasicEstProfile(ESTPROFILE_NAME, raProfile, credential);
    }

    private Certificate theOnlyCertificate() {
        List<Certificate> all = certificateRepository.findAll();
        assertThat(all).hasSize(1);
        return all.getFirst();
    }

    private void stubConnector(List<DataAttributeV2> issueAttributes, String issueAnswer) {
        connector.stubFor(WireMock.post(WireMock.urlPathMatching(ISSUE_PATH)).willReturn(WireMock.okJson(issueAnswer)));
        connector
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching(ISSUE_PATH + "/attributes"))
                        .willReturn(WireMock.okJson(AttributeDefinitionUtils.serialize(issueAttributes))));
        connector
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching(ISSUE_PATH + "/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
    }

    private Group saveGroup(String name) {
        Group group = new Group();
        group.setName(name);
        return groupRepository.save(group);
    }

    private void stubOwner(UUID owner) {
        authService
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/auth/users/" + owner))
                        .willReturn(WireMock
                                .okJson("{\"uuid\": \"%s\", \"username\": \"device-owner\"}".formatted(owner))));
    }

    private void applyAssociations(EstProfile estProfile, UUID owner, Group group) {
        ProtocolCertificateAssociations associations = new ProtocolCertificateAssociations();
        associations.setOwnerUuid(owner);
        associations.setGroupUuids(List.of(group.getUuid()));
        estProfile.setCertificateAssociations(certificateAssociationsRepository.save(associations));
        estProfileRepository.save(estProfile);
    }

    private static DataAttributeV2 issueAttributeDefinition(UUID uuid) {
        DataAttributeV2 definition = new DataAttributeV2();
        definition.setUuid(uuid.toString());
        definition.setName("profileName");
        definition.setType(AttributeType.DATA);
        definition.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Profile name");
        definition.setProperties(properties);
        return definition;
    }

    private void storeEstProfileIssueAttribute(EstProfile estProfile) throws Exception {
        UUID attributeUuid = UUID.randomUUID();
        DataAttributeV2 definition = issueAttributeDefinition(attributeUuid);
        stubConnector(List.of(definition), "{ \"certificateData\": \"" + base64(issued) + "\" }");
        UUID connectorUuid = connectorRepository.findAll().getFirst().getUuid();
        attributeEngine
                .updateDataAttributeDefinitions(connectorUuid, AttributeOperation.CERTIFICATE_ISSUE,
                        List.of(definition));
        attributeEngine
                .updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo
                                .builder(Resource.EST_PROFILE, estProfile.getUuid())
                                .connector(connectorUuid)
                                .operation(AttributeOperation.CERTIFICATE_ISSUE)
                                .build(),
                        List
                                .of(new RequestAttributeV2(attributeUuid, "profileName", AttributeContentType.STRING,
                                        List.of(new StringAttributeContentV2(ESTPROFILE_ATTRIBUTE_VALUE)),
                                        AttributeVersion.V2)));
    }

    private void storeRaActivationIssueAttribute() {
        DataAttributeV2 attribute = issueAttributeDefinition(UUID.randomUUID());
        attribute.setContent(List.of(new StringAttributeContentV2(RA_ATTRIBUTE_VALUE)));
        stubConnector(List.of(issueAttributeDefinition(UUID.fromString(attribute.getUuid()))),
                "{ \"certificateData\": \"" + base64(issued) + "\" }");
        jdbcTemplate
                .update("INSERT INTO " + dbSchema
                        + ".ra_profile_protocol_attribute (uuid, ra_profile_uuid, est_issue_certificate_attributes) "
                        + "VALUES (?, ?, ?)", UUID.randomUUID(), raProfile.getUuid(),
                        AttributeDefinitionUtils.serialize(List.of(attribute)));
    }

    private static String base64(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate certificateOf(ResponseEntity<byte[]> response) throws Exception {
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE)).isEqualTo(EstMediaTypes.PKCS7_CERTS_ONLY);
        byte[] der = Base64.getMimeDecoder().decode(response.getBody());
        CMSSignedData signedData = new CMSSignedData(der);
        var held = signedData.getCertificates().getMatches(null);
        assertThat(held).hasSize(1);
        return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) held.iterator().next());
    }

}

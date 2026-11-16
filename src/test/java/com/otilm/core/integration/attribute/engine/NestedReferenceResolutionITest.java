package com.otilm.core.integration.attribute.engine;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ObjectAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceCertificateContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.connector.secrets.SecretContentResponseDto;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeReferenceExpander;
import com.otilm.core.attribute.engine.ReferenceAccessDeniedException;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.CallbackExternalService;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.handler.OwnConnectorReferenceLending;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.SecretsUtil;
import com.otilm.core.util.mockbeans.ManagementApiMocks;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A discovery that refers to an existing authority, where the authority's OAuth client secret and TLS trust certificate
 * are references of their own. Each path that sends the authority to a connector has to send those two resolved, in the
 * shape the authority's own operations send them, and with the same rule on who may use them.
 */
@Import(ManagementApiMocks.class)
class NestedReferenceResolutionITest extends BaseSpringBootTest {

    private static final String AUTHORITY_DEFINITION_UUID = "7f7f0000-0000-4000-8000-0000000000a1";
    private static final String CLIENT_SECRET = "client-secret-v1";
    private static final String ROTATED_CLIENT_SECRET = "client-secret-v2";
    private static final String TRUST_ANCHOR = "dHJ1c3QtYW5jaG9yLWNlcnRpZmljYXRl";
    private static final String STATUS_PATH = "/v2/discoveryProvider/discoveries/status";
    private static final String CALLBACK_PATH = "/v2/attributes/callback";
    private static final String CA_PICKER_DEFINITION_UUID = "7f7f0000-0000-4000-8000-0000000000a2";
    private static final String ISSUER_PICKER_DEFINITION_UUID = "7f7f0000-0000-4000-8000-0000000000a3";

    @Autowired
    private AttributeReferenceExpander expander;
    @Autowired
    private OperationAttributeResolver operationAttributeResolver;
    @Autowired
    private OwnConnectorReferenceLending referenceLending;
    @Autowired
    private DiscoveryV2Client discoveryV2Client;
    @Autowired
    private DiscoveryExternalService discoveryService;
    @Autowired
    private CallbackExternalService callbackService;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private PlatformAuthenticationClient authenticationClient;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;
    @Autowired
    private VaultProfileRepository vaultProfileRepository;
    @Autowired
    private SecretRepository secretRepository;
    @Autowired
    private SecretVersionRepository secretVersionRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private DiscoveryRepository discoveryRepository;

    private WireMockServer connectors;
    private Connector discoveryConnector;
    private ConnectorInterfaceEntity discoveryInterface;
    private AuthorityInstanceReference authority;
    private Secret oauthClient;
    private X509CertificateEntity trust;

    @BeforeEach
    void seedAnAuthorityWhoseCredentialsAreReferences() throws Exception {
        connectors = LoopbackWireMock.start();
        WireMock.configureFor(LoopbackWireMock.HOST, connectors.port());
        stubTheVault(CLIENT_SECRET);
        oauthClient = seedASecret(CLIENT_SECRET);
        trust = seedATrustCertificate();
        discoveryConnector = seedADiscoveryConnector();
        authority = seedAnAuthority(discoveryConnector, "otpki-production");
        when(authenticationClient.authenticateSystemUser(any()))
                .thenReturn(new AuthenticationInfo(AuthMethod.USER_PROXY, UUID.randomUUID().toString(),
                        AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME, List.of()));
    }

    @AfterEach
    void stopConnectors() {
        connectors.stop();
    }

    // ── CallbackMode ──────────────────────────────────────────────────────────

    @Nested
    class CallbackMode {

        @Test
        void resolvesTheAuthoritysSecretAndTrust_whenTheAuthorityBelongsToTheCallbacksConnector() throws Exception {
            // given
            denyTheCaller(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);
            denyTheCaller(Resource.CERTIFICATE, ResourceAction.DETAIL);
            RequestAttribute authorityReference = authorityReference();
            Set<String> expandedSecrets = new HashSet<>();

            // when
            expander
                    .expandForCaller(List.of(authorityReference), expandedSecrets,
                            referenceLending.forConnector(discoveryConnector.getUuid()));

            // then
            ResourceSimpleContentData sent = (ResourceSimpleContentData) firstData(authorityReference.getContent());
            assertTheCredentialsAreResolved(sent, CLIENT_SECRET);
            assertThat(expandedSecrets).contains(CLIENT_SECRET);
        }

        @Test
        void leavesTheAuthoritysCredentialsAsReferences_whenTheAuthorityBelongsToAnotherConnector() throws Exception {
            // given
            RequestAttribute foreignAuthorityReference = authorityReference(anAuthorityOfAnotherConnector());

            // when
            expander
                    .expandForCaller(List.of(foreignAuthorityReference), new HashSet<>(),
                            referenceLending.forConnector(discoveryConnector.getUuid()));

            // then
            assertTheCredentialsAreReferences(
                    (ResourceSimpleContentData) firstData(foreignAuthorityReference.getContent()));
        }

        @Test
        void failsClosedNamingTheAuthority_whenTheCallerMayNotSeeIt() {
            // given
            denyResourceAccess(Resource.AUTHORITY, ResourceAction.DETAIL);
            List<RequestAttribute> attributes = List.of(authorityReference());
            Set<String> expandedSecrets = new HashSet<>();

            // when
            ThrowingCallable expand = () -> expander
                    .expandForCaller(attributes, expandedSecrets,
                            referenceLending.forConnector(discoveryConnector.getUuid()));

            // then
            assertThatThrownBy(expand)
                    .isInstanceOfSatisfying(ReferenceAccessDeniedException.class,
                            refused -> assertThat(refused.getReference())
                                    .isEqualTo("Authority '%s'".formatted(authority.getName())));
            assertThat(expandedSecrets).isEmpty();
        }
    }

    // ── SystemMode ────────────────────────────────────────────────────────────

    @Nested
    class SystemMode {

        @Test
        void resolvesTheAuthoritysSecretAndTrust_asTheContentResolver_whenNestedReferencesAreAskedFor()
                throws Exception {
            // given
            attributeEngine
                    .updateDataAttributeDefinitions(discoveryConnector.getUuid(), null, List.of(authorityDefinition()));

            // when
            List<RequestAttribute> sent = operationAttributeResolver
                    .resolveWithNestedReferencesAsSystem(discoveryConnector.getUuid(), List.of(authorityReference()));

            // then
            assertTheCredentialsAreResolved((ResourceSimpleContentData) firstData(sent.getFirst().getContent()),
                    CLIENT_SECRET);
            verify(authenticationClient).authenticateSystemUser(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME);
        }

        @Test
        void leavesTheAuthoritysCredentialsAsReferences_whenTheAuthorityBelongsToAnotherConnector() throws Exception {
            // given
            attributeEngine
                    .updateDataAttributeDefinitions(discoveryConnector.getUuid(), null, List.of(authorityDefinition()));
            RequestAttribute foreignAuthorityReference = authorityReference(anAuthorityOfAnotherConnector());

            // when
            List<RequestAttribute> sent = operationAttributeResolver
                    .resolveWithNestedReferencesAsSystem(discoveryConnector.getUuid(),
                            List.of(foreignAuthorityReference));

            // then
            assertTheCredentialsAreReferences((ResourceSimpleContentData) firstData(sent.getFirst().getContent()));
        }

        @Test
        void leavesTheAuthoritysSecretAReference_whenResolvingOneLevelForAnOperation() throws Exception {
            // given
            attributeEngine
                    .updateDataAttributeDefinitions(discoveryConnector.getUuid(), null, List.of(authorityDefinition()));

            // when
            List<RequestAttribute> sent = operationAttributeResolver
                    .resolveForConnectorRequestAsSystem(discoveryConnector.getUuid(), List.of(authorityReference()));

            // then
            ResourceSimpleContentData resolvedAuthority = (ResourceSimpleContentData) firstData(
                    sent.getFirst().getContent());
            assertThat(contentOf(resolvedAuthority, "oauthClient"))
                    .isInstanceOfSatisfying(ResourceSecretContentData.class,
                            secret -> assertThat(secret.getContent()).isNull());
        }
    }

    // ── DiscoveryV2Run ────────────────────────────────────────────────────────

    @Nested
    class DiscoveryV2Run {

        @Test
        void sendsTheAuthoritysSecretAndTrust_whenCallingTheConnector() throws Exception {
            // given
            Discovery run = aCreatedRunReferringToTheAuthority();

            // when
            discoveryV2Client.status(run);

            // then
            String sent = lastStatusRequestBody();
            assertThat(sent).contains("\"password\":\"%s\"".formatted(CLIENT_SECRET)).contains(TRUST_ANCHOR);
        }

        @Test
        void sendsTheRotatedSecret_onTheCallAfterTheSecretChanged() throws Exception {
            // given
            Discovery run = aCreatedRunReferringToTheAuthority();
            discoveryV2Client.status(run);
            stubTheVault(ROTATED_CLIENT_SECRET);

            // when
            discoveryV2Client.status(run);

            // then
            assertThat(lastStatusRequestBody())
                    .contains("\"password\":\"%s\"".formatted(ROTATED_CLIENT_SECRET))
                    .doesNotContain(CLIENT_SECRET);
        }

        // ── Helpers ────────────────────────────────────────────────────────────

        private Discovery aCreatedRunReferringToTheAuthority() throws Exception {
            stubTheDiscoveryConnectorsSchema();
            WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo(STATUS_PATH)).willReturn(WireMock.okJson("""
                    {"state":"running","highestSequence":0}""")));
            DiscoveryDto request = aRequestReferringToTheAuthority();
            discoveryService.createDiscovery(request, true);
            return discoveryRepository.findByName(request.getName()).orElseThrow();
        }

        private String lastStatusRequestBody() {
            List<LoggedRequest> requests = connectors
                    .findAll(WireMock.postRequestedFor(WireMock.urlPathEqualTo(STATUS_PATH)));
            return requests.getLast().getBodyAsString();
        }
    }

    // ── DiscoveryCreation ─────────────────────────────────────────────────────

    @Nested
    class DiscoveryCreation {

        @Test
        void createsTheRun_whenTheCreatorMayNotReadTheAuthoritysSecret() throws Exception {
            // given
            stubTheDiscoveryConnectorsSchema();
            denyTheCaller(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);
            DiscoveryDto request = aRequestReferringToTheAuthority();

            // when
            discoveryService.createDiscovery(request, true);

            // then
            assertThat(discoveryRepository.findByName(request.getName())).isPresent();
        }

        @Test
        void refusesAReference_whenItNamesAnotherKindThanItsAttributeTakes() throws Exception {
            // given
            stubTheDiscoveryConnectorsSchema();
            List<BaseAttributeContentV3<?>> secretInsteadOfAuthority = new ArrayList<>();
            secretInsteadOfAuthority
                    .add(new ResourceObjectContent(oauthClient.getName(), new ResourceSecretContentData(
                            oauthClient.getUuid().toString(), oauthClient.getName(), null)));
            DiscoveryDto request = aRequestReferringToTheAuthority();
            request
                    .setAttributes(List
                            .of(new RequestAttributeV3(UUID.fromString(AUTHORITY_DEFINITION_UUID), "authority",
                                    AttributeContentType.RESOURCE, secretInsteadOfAuthority)));

            // when
            ThrowingCallable create = () -> discoveryService.createDiscovery(request, true);

            // then
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'OTPKI authority' takes a reference to Authority, not to Secret");
            assertThat(discoveryRepository.findByName(request.getName())).isEmpty();
        }

        @Test
        void refusesAValue_whenItIsNotAReferenceThoughItsAttributeTakesOne() throws Exception {
            // given
            stubTheDiscoveryConnectorsSchema();
            denyResourceAccess(Resource.AUTHORITY, ResourceAction.DETAIL);
            HashMap<String, String> authorityIdentity = new HashMap<>();
            authorityIdentity.put("resource", AttributeResource.AUTHORITY.getCode());
            authorityIdentity.put("uuid", authority.getUuid().toString());
            authorityIdentity.put("name", authority.getName());
            List<BaseAttributeContentV3<?>> objectInsteadOfReference = new ArrayList<>();
            objectInsteadOfReference.add(new ObjectAttributeContentV3(authority.getName(), authorityIdentity));
            DiscoveryDto request = aRequestReferringToTheAuthority();
            request
                    .setAttributes(List
                            .of(new RequestAttributeV3(UUID.fromString(AUTHORITY_DEFINITION_UUID), "authority",
                                    AttributeContentType.RESOURCE, objectInsteadOfReference)));

            // when
            ThrowingCallable create = () -> discoveryService.createDiscovery(request, true);

            // then
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'OTPKI authority' takes a reference to Authority");
            assertThat(discoveryRepository.findByName(request.getName())).isEmpty();
        }

    }

    // ── DiscoveryFormCallbacks ────────────────────────────────────────────────

    @Nested
    class DiscoveryFormCallbacks {

        @Test
        void refusesTheAuthorityPicker_whenTheFormWasNotListed() throws Exception {
            // given
            stubTheDiscoveryConnectorsSchema();
            RequestAttributeCallback authorityPicker = callbackFor("authority");

            // when
            ThrowingCallable pick = () -> callbackService.callback(discoveryConnector.getUuid(), authorityPicker);

            // then
            assertThatThrownBy(pick).isInstanceOf(NotFoundException.class).hasMessageContaining("authority");
        }

        @Test
        void offersTheAuthority_whenTheAuthorityPickerAsksAfterTheFormWasListed() throws Exception {
            // given
            stubTheDiscoveryConnectorsSchema();
            discoveryService.getDiscoveryAttributes(SecuredUUID.fromUUID(discoveryConnector.getUuid()));

            // when
            Object offered = callbackService.callback(discoveryConnector.getUuid(), callbackFor("authority"));

            // then
            assertThat((List<?>) offered)
                    .extracting(option -> ((ResourceObjectContent) option).getData().getUuid())
                    .contains(authority.getUuid().toString());
        }

        @Test
        void sendsTheAuthoritysCredentials_whenTheCertificateAuthorityPickerAsksAfterTheFormWasListed()
                throws Exception {
            // given
            stubTheDiscoveryConnectorsSchema();
            denyTheCaller(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);
            discoveryService.getDiscoveryAttributes(SecuredUUID.fromUUID(discoveryConnector.getUuid()));
            RequestAttributeCallback caPicker = callbackFor("certificateAuthorities", authorityReference());

            // when
            callbackService.callback(discoveryConnector.getUuid(), caPicker);

            // then
            assertThat(lastCallbackRequestBody())
                    .contains("\"password\":\"%s\"".formatted(CLIENT_SECRET))
                    .contains(TRUST_ANCHOR);
        }

        @Test
        void answersAResourcesPicker_whenItsResourcesAttributesWereListed() throws Exception {
            // given
            stubTheDiscoveryConnectorsSchema();
            WireMock
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/certificates/attributes"))
                            .willReturn(WireMock
                                    .okJson(new ObjectMapper()
                                            .writeValueAsString(List
                                                    .of(pickerDependingOnTheAuthority(ISSUER_PICKER_DEFINITION_UUID,
                                                            "issuers"))))));
            discoveryService
                    .getDiscoveryResourceAttributes(SecuredUUID.fromUUID(discoveryConnector.getUuid()),
                            Resource.CERTIFICATE);

            // when
            callbackService.callback(discoveryConnector.getUuid(), callbackFor("issuers", authorityReference()));

            // then
            assertThat(lastCallbackRequestBody()).contains("\"attributeName\":\"issuers\"");
        }

        // ── Helpers ────────────────────────────────────────────────────────────

        private RequestAttributeCallback callbackFor(String attributeName, RequestAttribute... currentAttributes) {
            RequestAttributeCallback callback = new RequestAttributeCallback();
            callback.setName(attributeName);
            callback.setInterfaceUuid(discoveryInterface.getUuid());
            callback.setAttributes(List.of(currentAttributes));
            return callback;
        }

        private String lastCallbackRequestBody() {
            return connectors
                    .findAll(WireMock.postRequestedFor(WireMock.urlPathEqualTo(CALLBACK_PATH)))
                    .getLast()
                    .getBodyAsString();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Denies the action to the calling user only. The system identity that resolves what an object lends is asked the
     * same question, and a plain denial would refuse it too.
     */
    private void denyTheCaller(Resource resource, ResourceAction action) {
        OpaResourceAccessResult denied = new OpaResourceAccessResult();
        denied.setAuthorized(false);
        when(opaClient
                .checkResourceAccess(any(),
                        argThat(request -> request != null && request.getProperties() != null
                                && resource.getCode().equals(request.getProperties().get("name"))
                                && action.getCode().equals(request.getProperties().get("action"))),
                        argThat(principal -> principal == null
                                || !principal.contains(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME)),
                        any()))
                .thenReturn(denied);
    }

    private DiscoveryDto aRequestReferringToTheAuthority() {
        DiscoveryDto request = new DiscoveryDto();
        request.setName("through-authority-" + UUID.randomUUID());
        request.setConnectorUuid(discoveryConnector.getUuid().toString());
        request.setKind("OTPKI");
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(List.of(authorityReference()));
        return request;
    }

    private void stubTheDiscoveryConnectorsSchema() throws Exception {
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/resources"))
                        .willReturn(WireMock.okJson("""
                                [{"resource":"certificates"}]""")));
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/attributes"))
                        .willReturn(WireMock
                                .okJson(new ObjectMapper()
                                        .writeValueAsString(List
                                                .of(authorityDefinition(), pickerDependingOnTheAuthority(
                                                        CA_PICKER_DEFINITION_UUID, "certificateAuthorities"))))));
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v2/discoveryProvider/certificates/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo(CALLBACK_PATH)).willReturn(WireMock.okJson("""
                {"content":[]}""")));
    }

    /** A string picker whose options a connector callback lists from the authority picked on the same form. */
    private static DataAttributeV3 pickerDependingOnTheAuthority(String uuid, String name) {
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(uuid);
        definition.setName(name);
        definition.setType(AttributeType.DATA);
        definition.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Certificate authorities");
        properties.setVisible(true);
        properties.setList(true);
        properties.setMultiSelect(true);
        definition.setProperties(properties);
        AttributeCallback callback = new AttributeCallback();
        callback.setDependsOn(List.of("authority"));
        definition.setAttributeCallback(callback);
        return definition;
    }

    private static void assertTheCredentialsAreReferences(ResourceSimpleContentData authority) {
        assertThat(contentOf(authority, "oauthClient"))
                .isInstanceOfSatisfying(ResourceSecretContentData.class,
                        secret -> assertThat(secret.getContent()).isNull());
        assertThat(contentOf(authority, "tlsTrust"))
                .isInstanceOfSatisfying(ResourceCertificateContentData.class,
                        certificate -> assertThat(certificate.getContent()).isNull());
    }

    private static void assertTheCredentialsAreResolved(ResourceSimpleContentData authority, String password) {
        assertThat(contentOf(authority, "oauthClient"))
                .isInstanceOfSatisfying(ResourceSecretContentData.class,
                        secret -> assertThat(((BasicAuthSecretContent) secret.getContent()).getPassword())
                                .isEqualTo(password));
        assertThat(contentOf(authority, "tlsTrust"))
                .isInstanceOfSatisfying(ResourceCertificateContentData.class,
                        certificate -> assertThat(certificate.getContent()).isEqualTo(TRUST_ANCHOR));
    }

    private static ResourceObjectContentData contentOf(ResourceSimpleContentData object, String attributeName) {
        ResponseAttribute attribute = object
                .getAttributes()
                .stream()
                .filter(candidate -> attributeName.equals(candidate.getName()))
                .findFirst()
                .orElseThrow();
        return firstData(attribute.getContent());
    }

    private static ResourceObjectContentData firstData(List<?> content) {
        return ((ResourceObjectContent) content.getFirst()).getData();
    }

    private RequestAttribute authorityReference() {
        return authorityReference(authority);
    }

    private static RequestAttribute authorityReference(AuthorityInstanceReference target) {
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        content
                .add(new ResourceObjectContent(target.getName(), new ResourceSimpleContentData(
                        AttributeResource.AUTHORITY, target.getUuid().toString(), target.getName(), null)));
        return new RequestAttributeV3(UUID.fromString(AUTHORITY_DEFINITION_UUID), "authority",
                AttributeContentType.RESOURCE, content);
    }

    private static DataAttributeV3 authorityDefinition() {
        return referenceDefinition(AUTHORITY_DEFINITION_UUID, "authority", "OTPKI authority",
                AttributeResource.AUTHORITY);
    }

    private static DataAttributeV3 referenceDefinition(String uuid, String name, String label,
            AttributeResource resource) {
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(uuid);
        definition.setName(name);
        definition.setType(AttributeType.DATA);
        definition.setContentType(AttributeContentType.RESOURCE);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(label);
        properties.setResource(resource);
        properties.setVisible(true);
        definition.setProperties(properties);
        definition.setAttributeCallback(new AttributeCallback());
        return definition;
    }

    private void stubTheVault(String password) throws Exception {
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/secretProvider/secrets/basicAuth/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        WireMock
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/secretProvider/vaults/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/secretProvider/vaultProfiles/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        SecretContentResponseDto response = new SecretContentResponseDto();
        response.setContent(oauthClientContent(password));
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/secretProvider/secrets/content"))
                        .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(response))));
    }

    private static BasicAuthSecretContent oauthClientContent(String password) {
        BasicAuthSecretContent content = new BasicAuthSecretContent();
        content.setUsername("discovery-client");
        content.setPassword(password);
        return content;
    }

    private Secret seedASecret(String password) throws Exception {
        Connector vaultConnector = new Connector();
        vaultConnector.setName("nested-vault-connector");
        vaultConnector.setUrl(LoopbackWireMock.url(connectors));
        vaultConnector.setVersion(ConnectorVersion.V1);
        vaultConnector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(vaultConnector);

        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("nested-vault");
        vaultInstance.setConnector(vaultConnector);
        vaultInstanceRepository.save(vaultInstance);

        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("nested-vault-profile");
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfile.setEnabled(true);
        vaultProfileRepository.save(vaultProfile);

        Secret secret = new Secret();
        secret.setName("otpki-oauth-client");
        secret.setType(SecretType.BASIC_AUTH);
        secret.setState(SecretState.ACTIVE);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setSourceVaultProfileUuid(vaultProfile.getUuid());
        secret.setEnabled(true);

        SecretVersion version = new SecretVersion();
        version.setVersion(1);
        version.setVaultProfile(vaultProfile);
        version.setFingerprint(SecretsUtil.calculateSecretContentFingerprint(oauthClientContent(password)));
        secretVersionRepository.save(version);
        secret.setLatestVersion(version);
        secretRepository.save(secret);
        version.setSecretUuid(secret.getUuid());
        secretVersionRepository.save(version);
        return secret;
    }

    private X509CertificateEntity seedATrustCertificate() {
        CertificateContent content = new CertificateContent();
        content.setContent(TRUST_ANCHOR);
        content = certificateContentRepository.save(content);
        X509CertificateEntity certificate = aCertificate()
                .withCommonName("Private TLS CA")
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .build();
        return certificateRepository.save(certificate);
    }

    /** The same OTPKI-like authority as the one under test, held by a connector the discovery does not run on. */
    private AuthorityInstanceReference anAuthorityOfAnotherConnector() throws Exception {
        Connector otherConnector = new Connector();
        otherConnector.setName("nested-other-connector");
        otherConnector.setUrl("http://other-connector.invalid");
        otherConnector.setVersion(ConnectorVersion.V2);
        otherConnector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(otherConnector);
        return seedAnAuthority(otherConnector, "otpki-elsewhere");
    }

    /**
     * An OTPKI-like authority of the connector: a base URL, an OAuth client that refers to a secret, a TLS trust that
     * refers to a CA.
     */
    private AuthorityInstanceReference seedAnAuthority(Connector owner, String name) throws Exception {
        AuthorityInstanceReference reference = new AuthorityInstanceReference();
        reference.setName(name);
        reference.setKind("OTPKI");
        reference.setConnector(owner);
        reference.setConnectorUuid(owner.getUuid());
        reference = authorityInstanceReferenceRepository.save(reference);

        DataAttributeV3 baseUrl = new DataAttributeV3();
        baseUrl.setUuid(UUID.randomUUID().toString());
        baseUrl.setName("baseUrl");
        baseUrl.setType(AttributeType.DATA);
        baseUrl.setContentType(AttributeContentType.STRING);
        DataAttributeProperties baseUrlProperties = new DataAttributeProperties();
        baseUrlProperties.setLabel("Base URL");
        baseUrl.setProperties(baseUrlProperties);
        DataAttributeV3 oauthClientDefinition = referenceDefinition(UUID.randomUUID().toString(), "oauthClient",
                "OAuth client", AttributeResource.SECRET);
        DataAttributeV3 tlsTrustDefinition = referenceDefinition(UUID.randomUUID().toString(), "tlsTrust", "TLS trust",
                AttributeResource.CERTIFICATE);
        tlsTrustDefinition.getProperties().setList(true);
        attributeEngine
                .updateDataAttributeDefinitions(owner.getUuid(), null,
                        List.of(baseUrl, oauthClientDefinition, tlsTrustDefinition));

        List<BaseAttributeContentV3<?>> baseUrlContent = new ArrayList<>();
        baseUrlContent.add(new StringAttributeContentV3("https://otpki.example.com"));
        List<BaseAttributeContentV3<?>> oauthClientContent = new ArrayList<>();
        oauthClientContent
                .add(new ResourceObjectContent(oauthClient.getName(),
                        new ResourceSecretContentData(oauthClient.getUuid().toString(), oauthClient.getName(), null)));
        List<BaseAttributeContentV3<?>> tlsTrustContent = new ArrayList<>();
        tlsTrustContent
                .add(new ResourceObjectContent("Private TLS CA",
                        new ResourceCertificateContentData(trust.getUuid().toString(), "Private TLS CA", null, null)));
        attributeEngine
                .updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo
                                .builder(Resource.AUTHORITY, reference.getUuid())
                                .connector(owner.getUuid())
                                .build(),
                        List
                                .of(new RequestAttributeV3(UUID.fromString(baseUrl.getUuid()), "baseUrl",
                                        AttributeContentType.STRING, baseUrlContent),
                                        new RequestAttributeV3(UUID.fromString(oauthClientDefinition.getUuid()),
                                                "oauthClient", AttributeContentType.RESOURCE, oauthClientContent),
                                        new RequestAttributeV3(UUID.fromString(tlsTrustDefinition.getUuid()),
                                                "tlsTrust", AttributeContentType.RESOURCE, tlsTrustContent)));
        return reference;
    }

    private Connector seedADiscoveryConnector() {
        Connector connector = new Connector();
        connector.setName("nested-discovery-connector");
        connector.setUrl(LoopbackWireMock.url(connectors));
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        ConnectorInterfaceEntity v2Discovery = new ConnectorInterfaceEntity();
        v2Discovery.setConnectorUuid(connector.getUuid());
        v2Discovery.setInterfaceCode(ConnectorInterface.DISCOVERY);
        v2Discovery.setVersion("v2");
        discoveryInterface = connectorInterfaceRepository.save(v2Discovery);
        return connector;
    }
}

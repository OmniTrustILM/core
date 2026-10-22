package com.otilm.core.integration.api.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.SecretOperationException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.otilm.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.secrets.SecretContentResponseDto;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.connector.secrets.content.GenericSecretContent;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.proxy.ProxyStatus;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Credential;
import com.otilm.core.dao.entity.Proxy;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository.ResourceAttributeReferrer;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CredentialRepository;
import com.otilm.core.dao.repository.ProxyRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.SecretActionData;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.reference.ObjectRef;
import com.otilm.core.reference.ObjectReferenceGuard;
import com.otilm.core.service.NotificationInstanceExternalService;
import com.otilm.core.service.SecretExternalService;
import com.otilm.core.service.SecretInternalService;
import com.otilm.core.service.VaultInstanceExternalService;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.SecretsUtil;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import com.otilm.core.util.seeders.TspProfileBasicCredentialSeeder;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;

@AutoConfigureMockMvc
class SecretDeleteReferenceGuardHttpITest extends BaseSpringBootTest {

    private static final String PIN = "1234";
    private static final String PIN_SECRET_NAME = "token-pin";
    private static final String TOKEN_NAME = "pkcs11-v2-token";
    private static final String TOKEN_PIN_USE = "Token '" + TOKEN_NAME + "' (attribute 'PIN')";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ConnectorMockFactory connectorMockFactory;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;
    @Autowired
    private VaultProfileRepository vaultProfileRepository;
    @Autowired
    private SecretRepository secretRepository;
    @Autowired
    private SecretVersionRepository secretVersionRepository;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private SecretInternalService secretInternalService;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private TspProfileBasicCredentialSeeder tspCredentialSeeder;
    @Autowired
    private SecretExternalService secretService;
    @Autowired
    private SigningProfileRepository signingProfileRepository;
    @Autowired
    private ObjectReferenceGuard referenceGuard;
    @Autowired
    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;
    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private ProxyRepository proxyRepository;
    @Autowired
    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;
    @Autowired
    private NotificationInstanceExternalService notificationInstanceService;
    @Autowired
    private VaultInstanceExternalService vaultInstanceService;

    private CryptographyProviderV2ConnectorMock tokenProvider;
    private WireMockServer vaultConnector;
    private WireMockServer authService;
    private TokenInstanceReference token;
    private Secret secret;
    private UUID pinDefinitionUuid;

    @BeforeEach
    void storeATokenPinThatReferencesASecret() throws Exception {
        authService = AuthServiceWireMockStubs.startImpersonating(UUID.randomUUID(), "superadmin");
        tokenProvider = connectorMockFactory.startCryptographyProviderV2().stubTokenOperations();
        vaultConnector = startVaultConnector();
        secret = persistGenericSecret(persistVaultProfile(LoopbackWireMock.url(vaultConnector)), PIN_SECRET_NAME);
        token = persistV2Token(tokenProvider.getUrl());
        persistPinReference(token, secret);
    }

    @AfterEach
    void stopConnectors() {
        tokenProvider.stop();
        vaultConnector.stop();
        authService.stop();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String secretPath(Secret target) {
        return "/v1/secrets/" + target.getUuid();
    }

    private String tokenProfileAttributes() {
        return "/v1/tokens/" + token.getUuid() + "/tokenProfiles/attributes";
    }

    private MvcResult perform(RequestBuilder request) throws Exception {
        injectAuthentication();
        return mockMvc.perform(request).andReturn();
    }

    private List<ResourceAttributeReferrer> referrersOf(Secret referenced) {
        return attributeContent2ObjectRepository
                .findResourceAttributeReferrers(Resource.SECRET.getCode(), referenced.getUuid().toString());
    }

    /** The delete action the request queues, as the broker hands it to the listener. */
    private static ActionMessage deletion(Secret target, SecretState originalState, ObjectRef releasedBy) {
        ActionMessage message = new ActionMessage();
        message.setResource(Resource.SECRET);
        message.setResourceAction(ResourceAction.DELETE);
        message.setResourceUuid(target.getUuid());
        message
                .setData(SecretActionData
                        .builder()
                        .deleteInVault(true)
                        .originalState(originalState)
                        .releasedBy(releasedBy)
                        .build());
        return message;
    }

    /** Leaves the secret as a delete request does, and returns the state its action puts back on a refusal. */
    private SecretState awaitDeleteApproval(Secret target) {
        SecretState stateBeforeTheRequest = target.getState();
        target.setState(SecretState.PENDING_APPROVAL);
        secretRepository.save(target);
        return stateBeforeTheRequest;
    }

    private void assertStateRestored(Secret target, SecretState stateBeforeTheRequest) {
        assertThat(secretRepository.findById(target.getUuid()))
                .get()
                .extracting(Secret::getState)
                .isEqualTo(stateBeforeTheRequest);
    }

    /** Runs the request without committing it, so the action it would queue is never sent. */
    private void inRolledBackTransaction(TransactionalStep step) {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            step.runUnchecked();
            status.setRollbackOnly();
        });
    }

    private void inNewTransaction(TransactionalStep step) {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.executeWithoutResult(status -> step.runUnchecked());
    }

    @FunctionalInterface
    private interface TransactionalStep {
        void run() throws Exception;

        default void runUnchecked() {
            try {
                run();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static WireMockServer startVaultConnector() throws Exception {
        WireMockServer server = new WireMockServer(LoopbackWireMock.options());
        server.start();
        SecretContentResponseDto content = new SecretContentResponseDto();
        content.setContent(new GenericSecretContent(PIN));
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/secretProvider/secrets/[^/]+/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/v1/secretProvider/vaults/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v1/secretProvider/vaultProfiles/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v1/secretProvider/secrets/content"))
                        .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(content))));
        server
                .stubFor(WireMock
                        .delete(WireMock.urlPathEqualTo("/v1/secretProvider/secrets"))
                        .willReturn(WireMock.ok()));
        return server;
    }

    private VaultProfile persistVaultProfile(String url) {
        Connector connector = aConnector().withGeneratedUuid().withUrl(url).withVersion(ConnectorVersion.V1).build();
        connectorRepository.save(connector);

        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("test-vault");
        vaultInstance.setConnector(connector);
        vaultInstanceRepository.save(vaultInstance);

        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("test-vault-profile");
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfile.setEnabled(true);
        return vaultProfileRepository.save(vaultProfile);
    }

    private Secret persistGenericSecret(VaultProfile vaultProfile, String name) throws Exception {
        SecretVersion version = new SecretVersion();
        version.setVersion(1);
        version.setVaultProfile(vaultProfile);
        version.setFingerprint(SecretsUtil.calculateSecretContentFingerprint(new GenericSecretContent(PIN)));
        secretVersionRepository.save(version);

        Secret value = new Secret();
        value.setName(name);
        value.setType(SecretType.GENERIC);
        value.setState(SecretState.ACTIVE);
        value.setEnabled(true);
        value.setSourceVaultProfile(vaultProfile);
        value.setSourceVaultProfileUuid(vaultProfile.getUuid());
        value.setLatestVersion(version);
        // The version stays unlinked: the Hibernate-built test schema lacks the migration's ON DELETE SET NULL from
        // secret_version to secret, so a linked version would block deleting the secret.
        return secretRepository.save(value);
    }

    private Secret persistGenericSecret(String name) throws Exception {
        return persistGenericSecret(secret.getSourceVaultProfile(), name);
    }

    private void persistAcmeProfile(String name, Secret eabKey) {
        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setName(name);
        acmeProfile.setEabSecretUuids(new ArrayList<>(List.of(eabKey.getUuid())));
        acmeProfileRepository.save(acmeProfile);
    }

    private TokenProfile persistTokenProfile(String name) {
        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName(name);
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceReference(token);
        tokenProfile.setTokenInstanceReferenceUuid(token.getUuid());
        return tokenProfileRepository.save(tokenProfile);
    }

    private Proxy persistProxy(String name) {
        Proxy proxy = new Proxy();
        proxy.setName(name);
        proxy.setCode("PIN_PROXY");
        proxy.setStatus(ProxyStatus.CONNECTED);
        return proxyRepository.save(proxy);
    }

    private NotificationInstanceReference persistNotifier() {
        NotificationInstanceReference notifier = new NotificationInstanceReference();
        notifier.setName("pin-notifier");
        notifier.setNotificationInstanceUuid(UUID.randomUUID());
        return notificationInstanceReferenceRepository.save(notifier);
    }

    private Credential persistCredential(String name) {
        Credential credential = new Credential();
        credential.setKind("basic");
        credential.setName(name);
        return credentialRepository.save(credential);
    }

    private SigningProfile persistSigningProfile(String name, int latestVersion) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(latestVersion);
        return signingProfileRepository.save(profile);
    }

    private TokenInstanceReference persistV2Token(String url) {
        Connector connector = aConnector().withGeneratedUuid().withUrl(url).build();
        connectorRepository.save(connector);

        ConnectorInterfaceEntity cryptography = new ConnectorInterfaceEntity();
        cryptography.setConnector(connector);
        cryptography.setConnectorUuid(connector.getUuid());
        cryptography.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        cryptography.setVersion("v2");
        cryptography.setFeatures(List.of(FeatureFlag.STATELESS));
        connectorInterfaceRepository.save(cryptography);
        connector.getInterfaces().add(cryptography);

        TokenInstanceReference value = new TokenInstanceReference();
        value.setName(TOKEN_NAME);
        value.setConnector(connector);
        value.setConnectorInterface(cryptography);
        value.setKind("PKCS11");
        value.setStatus(TokenInstanceStatus.CONNECTED);
        return tokenInstanceReferenceRepository.save(value);
    }

    /** Stores the token's {@code pin} attribute as the PKCS#11 provider defines it: a reference to a secret. */
    private void persistPinReference(TokenInstanceReference tokenInstance, Secret pinSecret) throws Exception {
        pinDefinitionUuid = UUID.randomUUID();
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(pinDefinitionUuid.toString());
        definition.setName("pin");
        definition.setType(AttributeType.DATA);
        definition.setContentType(AttributeContentType.RESOURCE);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("PIN");
        properties.setResource(AttributeResource.SECRET);
        definition.setProperties(properties);
        AttributeCallback secretTypeFilter = new AttributeCallback();
        secretTypeFilter
                .setMappings(Set
                        .of(new AttributeCallbackMapping("SECRET_TYPE.EQUALS", Set.of(AttributeValueTarget.FILTER),
                                new ArrayList<>(List.of(SecretType.Codes.GENERIC)))));
        definition.setAttributeCallback(secretTypeFilter);
        attributeEngine.updateDataAttributeDefinitions(tokenInstance.getConnectorUuid(), null, List.of(definition));
        storePinReference(Resource.TOKEN, tokenInstance.getUuid(), null, pinSecret);
    }

    /** Adds a token attribute that references a credential, beside the PIN. */
    private void storeCredentialReference(Credential credential) throws Exception {
        UUID definitionUuid = UUID.randomUUID();
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(definitionUuid.toString());
        definition.setName("login");
        definition.setType(AttributeType.DATA);
        definition.setContentType(AttributeContentType.RESOURCE);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("HSM login");
        properties.setResource(AttributeResource.CREDENTIAL);
        definition.setProperties(properties);
        definition.setAttributeCallback(new AttributeCallback());
        attributeEngine.updateDataAttributeDefinitions(token.getConnectorUuid(), null, List.of(definition));

        ResourceSimpleContentData reference = new ResourceSimpleContentData(AttributeResource.CREDENTIAL,
                credential.getUuid().toString(), credential.getName(), null);
        List<BaseAttributeContentV3<?>> credentialContent = new ArrayList<>();
        credentialContent.add(new ResourceObjectContent(credential.getName(), reference));
        List<BaseAttributeContentV3<?>> pinContent = new ArrayList<>();
        pinContent
                .add(new ResourceObjectContent(secret.getName(),
                        new ResourceSecretContentData(secret.getUuid().toString(), secret.getName(), null)));
        attributeEngine
                .updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo
                                .builder(Resource.TOKEN, token.getUuid())
                                .connector(token.getConnectorUuid())
                                .build(),
                        List
                                .of(new RequestAttributeV3(pinDefinitionUuid, "pin", AttributeContentType.RESOURCE,
                                        pinContent),
                                        new RequestAttributeV3(definitionUuid, "login", AttributeContentType.RESOURCE,
                                                credentialContent)));
    }

    /** A null version stores the value of an unversioned object. */
    private void storePinReference(Resource objectType, UUID objectUuid, Integer version, Secret pinSecret)
            throws Exception {
        storePinReference(objectType, objectUuid, version, pinSecret.getUuid().toString(), pinSecret.getName());
    }

    private void storePinReference(Resource objectType, UUID objectUuid, Integer version, String pinSecretUuid,
            String pinSecretName) throws Exception {
        ResourceSecretContentData reference = new ResourceSecretContentData(pinSecretUuid, pinSecretName, null);
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        content.add(new ResourceObjectContent(pinSecretName, reference));
        attributeEngine
                .updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo
                                .builder(objectType, objectUuid)
                                .connector(token.getConnectorUuid())
                                .version(version)
                                .build(),
                        List
                                .of(new RequestAttributeV3(pinDefinitionUuid, "pin", AttributeContentType.RESOURCE,
                                        content)));
    }

    // ── DeleteRefusal ─────────────────────────────────────────────────────────

    @Nested
    class DeleteRefusal {

        @Test
        void refusesDelete_whenATokenPinUsesTheSecret() throws Exception {
            // given — the token's PIN references the secret since the class setup

            // when
            MvcResult deletion = perform(delete(secretPath(secret)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
            assertThat(deletion.getResponse().getContentAsString())
                    .contains("Cannot delete Secret '" + PIN_SECRET_NAME + "'")
                    .contains(TOKEN_PIN_USE);
            assertThat(secretRepository.findById(secret.getUuid())).isPresent();
            assertThat(perform(get(tokenProfileAttributes())).getResponse().getStatus()).isEqualTo(200);
        }

        @Test
        void namesEveryReferrer_whenSeveralObjectsUseTheSecret() throws Exception {
            // given
            var acmeProfileName = "acme-with-eab";
            persistAcmeProfile(acmeProfileName, secret);

            // when
            MvcResult deletion = perform(delete(secretPath(secret)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
            assertThat(deletion.getResponse().getContentAsString())
                    .contains(TOKEN_PIN_USE)
                    .contains("ACME Profile '" + acmeProfileName + "' (External Account Binding key)");
        }

        @Test
        void namesReferrerByUuid_whenItsResourceHasNoObjectLookup() throws Exception {
            // given
            var notifierPin = persistGenericSecret("notifier-pin");
            var notifier = persistNotifier();
            storePinReference(Resource.NOTIFICATION_INSTANCE, notifier.getUuid(), null, notifierPin);

            // when
            MvcResult deletion = perform(delete(secretPath(notifierPin)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
            assertThat(deletion.getResponse().getContentAsString())
                    .contains("Notification instance '" + notifier.getUuid() + "' (attribute 'PIN')");
        }

        @Test
        void refusesDelete_whenATspCredentialHoldsTheSecret() throws Exception {
            // given
            var credentialSecret = persistGenericSecret("tsa-client-password");
            var credential = tspCredentialSeeder.persistCredential(credentialSecret);

            // when
            MvcResult deletion = perform(delete(secretPath(credentialSecret)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
            assertThat(deletion.getResponse().getContentAsString())
                    .contains("TSP Profile Basic Credential '" + credential.getUsername() + "'")
                    .contains("delete the credential from TSP Profile '" + credential.getTspProfile().getName() + "'");
            assertThat(secretRepository.findById(credentialSecret.getUuid())).isPresent();
        }

        @Test
        void quotesTheSecretNameVerbatim_whenItHoldsFormatCharacters() {
            // given
            var nameWithFormatCharacters = "pin{}$1";
            var secretRef = new ObjectRef(Resource.SECRET, secret.getUuid());
            injectAuthentication();

            // when / then
            assertThatThrownBy(() -> referenceGuard.refuseWhileReferenced(secretRef, nameWithFormatCharacters, null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessage("Cannot delete Secret '" + nameWithFormatCharacters + "': it is still used by "
                            + TOKEN_PIN_USE + ".");
        }
    }

    // ── HiddenReferrers ───────────────────────────────────────────────────────

    @Nested
    class HiddenReferrers {

        @Test
        void countsReferrerWithoutNamingIt_whenTheCallerMayNotSeeIt() throws Exception {
            // given
            var acmeProfileName = "acme-with-eab";
            persistAcmeProfile(acmeProfileName, secret);
            denyResourceAccess(Resource.TOKEN, ResourceAction.DETAIL);

            // when
            MvcResult deletion = perform(delete(secretPath(secret)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
            assertThat(deletion.getResponse().getContentAsString())
                    .contains("it is still used by ACME Profile '" + acmeProfileName
                            + "' (External Account Binding key); 1 object you are not allowed to see.")
                    .doesNotContain(TOKEN_NAME);
        }

        @Test
        void countsReferrerWithoutNamingIt_whenTheCallerMayNotSeeItsParent() throws Exception {
            // given
            var hiddenProfileName = "pin-profile";
            var tokenProfile = persistTokenProfile(hiddenProfileName);
            storePinReference(Resource.TOKEN_PROFILE, tokenProfile.getUuid(), null, secret);
            denyResourceAccess(Resource.TOKEN, ResourceAction.DETAIL);

            // when
            MvcResult deletion = perform(delete(secretPath(secret)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
            assertThat(deletion.getResponse().getContentAsString())
                    .contains("it is still used by 2 objects you are not allowed to see.")
                    .doesNotContain(hiddenProfileName);
        }

        @Test
        void countsReferrerWithoutNamingIt_evenWhereItsResourceReadChecksNothing() throws Exception {
            // given
            var hiddenProxyName = "pin-proxy";
            var proxy = persistProxy(hiddenProxyName);
            storePinReference(Resource.PROXY, proxy.getUuid(), null, secret);
            denyResourceAccess(Resource.PROXY, ResourceAction.DETAIL);

            // when
            MvcResult deletion = perform(delete(secretPath(secret)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
            assertThat(deletion.getResponse().getContentAsString())
                    .contains("it is still used by " + TOKEN_PIN_USE + "; 1 object you are not allowed to see.")
                    .doesNotContain(hiddenProxyName);
        }
    }

    // ── ReferenceLookup ───────────────────────────────────────────────────────

    @Nested
    class ReferenceLookup {

        @Test
        void refusesDelete_whenTheReferenceIsStoredInUpperCase() throws Exception {
            // given
            var upperCasePin = persistGenericSecret("upper-case-pin");
            var storedUuid = upperCasePin.getUuid().toString().toUpperCase();
            storePinReference(Resource.TOKEN, token.getUuid(), null, storedUuid, upperCasePin.getName());

            // when
            MvcResult deletion = perform(delete(secretPath(upperCasePin)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
            assertThat(deletion.getResponse().getContentAsString()).contains(TOKEN_PIN_USE);
        }

        @Test
        void findsReferrer_whenTheUuidIsAskedForInUpperCase() throws Exception {
            // given
            var askedPin = persistGenericSecret("asked-pin");
            storePinReference(Resource.TOKEN, token.getUuid(), null, askedPin);
            var askedUuid = askedPin.getUuid().toString().toUpperCase();

            // when
            List<ResourceAttributeReferrer> referrers = attributeContent2ObjectRepository
                    .findResourceAttributeReferrers(Resource.SECRET.getCode(), askedUuid);

            // then
            assertThat(referrers).extracting(ResourceAttributeReferrer::getObjectUuid).containsExactly(token.getUuid());
        }

        @Test
        void allowsDelete_whenOnlyAnOlderSigningProfileVersionUsesTheSecret() throws Exception {
            // given
            var currentVersion = 2;
            var olderVersion = currentVersion - 1;
            var signingPin = persistGenericSecret("signing-pin");
            var profile = persistSigningProfile("versioned-signing", currentVersion);
            storePinReference(Resource.SIGNING_PROFILE, profile.getUuid(), olderVersion, signingPin);
            var signingPinRef = new ObjectRef(Resource.SECRET, signingPin.getUuid());
            injectAuthentication();

            // when
            ThrowingCallable deleteCheck = () -> referenceGuard
                    .refuseWhileReferenced(signingPinRef, signingPin.getName(), null);

            // then
            assertThat(referrersOf(signingPin))
                    .extracting(ResourceAttributeReferrer::getObjectVersion)
                    .containsExactly(olderVersion);
            assertThatCode(deleteCheck).doesNotThrowAnyException();
        }

        @Test
        void refusesDelete_whenTheCurrentSigningProfileVersionUsesTheSecret() throws Exception {
            // given
            var currentVersion = 2;
            var signingPin = persistGenericSecret("signing-pin");
            var profileName = "versioned-signing";
            var profile = persistSigningProfile(profileName, currentVersion);
            storePinReference(Resource.SIGNING_PROFILE, profile.getUuid(), currentVersion, signingPin);
            var signingPinRef = new ObjectRef(Resource.SECRET, signingPin.getUuid());
            injectAuthentication();

            // when / then
            assertThatThrownBy(() -> referenceGuard.refuseWhileReferenced(signingPinRef, signingPin.getName(), null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("'" + profileName + "' (attribute 'PIN')");
        }
    }

    // ── DeletedReferrers ──────────────────────────────────────────────────────

    @Nested
    class DeletedReferrers {

        @Test
        void deletesSecret_whenItsReferrerIsGone() throws Exception {
            // given — a token profile that no longer exists left its PIN reference behind
            var leftoverPin = persistGenericSecret("leftover-pin");
            var goneTokenProfileUuid = UUID.randomUUID();
            storePinReference(Resource.TOKEN_PROFILE, goneTokenProfileUuid, null, leftoverPin);

            // when
            MvcResult deletion = perform(delete(secretPath(leftoverPin)));

            // then
            assertThat(deletion.getResponse().getStatus()).isEqualTo(204);
        }

        @Test
        void dropsItsReferences_whenANotificationInstanceIsDeleted() throws Exception {
            // given
            var notifier = persistNotifier();
            storePinReference(Resource.NOTIFICATION_INSTANCE, notifier.getUuid(), null, secret);
            injectAuthentication();

            // when
            notificationInstanceService.deleteNotificationInstance(notifier.getUuid());

            // then
            assertThat(referrersOf(secret))
                    .extracting(ResourceAttributeReferrer::getObjectUuid)
                    .doesNotContain(notifier.getUuid());
        }

        @Test
        void dropsItsReferences_whenAVaultInstanceIsDeleted() throws Exception {
            // given
            var vault = new VaultInstance();
            vault.setName("pin-vault");
            vaultInstanceRepository.save(vault);
            storePinReference(Resource.VAULT, vault.getUuid(), null, secret);
            injectAuthentication();

            // when
            vaultInstanceService.deleteVaultInstance(vault.getUuid());

            // then
            assertThat(referrersOf(secret))
                    .extracting(ResourceAttributeReferrer::getObjectUuid)
                    .doesNotContain(vault.getUuid());
        }
    }

    // ── QueuedDelete ──────────────────────────────────────────────────────────

    @Nested
    class QueuedDelete {

        @Test
        void putsBackTheSecretState_whenTheDeleteIsRefusedAfterApproval() {
            // given
            var stateBeforeTheRequest = awaitDeleteApproval(secret);
            var approvedDeletion = deletion(secret, stateBeforeTheRequest, null);
            injectAuthentication();

            // when
            ThrowingCallable processApprovedDeletion = () -> secretInternalService
                    .processSecretAction(approvedDeletion, true, true);

            // then
            assertThatThrownBy(processApprovedDeletion)
                    .isInstanceOf(SecretOperationException.class)
                    .hasMessageContaining(TOKEN_PIN_USE);
            assertStateRestored(secret, stateBeforeTheRequest);
        }

        @Test
        void putsBackTheSecretState_whenTheRefusalNamesAReferrerByUuid() throws Exception {
            // given
            var notifierPin = persistGenericSecret("notifier-pin");
            var notifier = persistNotifier();
            storePinReference(Resource.NOTIFICATION_INSTANCE, notifier.getUuid(), null, notifierPin);
            var stateBeforeTheRequest = awaitDeleteApproval(notifierPin);
            var approvedDeletion = deletion(notifierPin, stateBeforeTheRequest, null);
            injectAuthentication();

            // when
            ThrowingCallable processApprovedDeletion = () -> secretInternalService
                    .processSecretAction(approvedDeletion, true, true);

            // then
            assertThatThrownBy(processApprovedDeletion)
                    .isInstanceOf(SecretOperationException.class)
                    .hasMessageContaining("Notification instance '" + notifier.getUuid() + "'");
            assertStateRestored(notifierPin, stateBeforeTheRequest);
        }

        @Test
        void putsBackTheSecretState_whenTheRefusalHidesAReferrerBehindItsParent() throws Exception {
            // given
            var tokenProfile = persistTokenProfile("pin-profile");
            storePinReference(Resource.TOKEN_PROFILE, tokenProfile.getUuid(), null, secret);
            denyResourceAccess(Resource.TOKEN, ResourceAction.DETAIL);
            var stateBeforeTheRequest = awaitDeleteApproval(secret);
            var approvedDeletion = deletion(secret, stateBeforeTheRequest, null);
            injectAuthentication();

            // when
            ThrowingCallable processApprovedDeletion = () -> secretInternalService
                    .processSecretAction(approvedDeletion, true, true);

            // then
            assertThatThrownBy(processApprovedDeletion)
                    .isInstanceOf(SecretOperationException.class)
                    .hasMessageContaining("2 objects you are not allowed to see");
            assertStateRestored(secret, stateBeforeTheRequest);
        }

        @Test
        void deletesSecret_whenItsOwnerReleasesIt() throws Exception {
            // given
            var credentialSecret = persistGenericSecret("tsa-client-password");
            var credential = tspCredentialSeeder.persistCredential(credentialSecret);
            var owner = new ObjectRef(Resource.TSP_PROFILE_BASIC_CREDENTIAL, credential.getUuid());
            injectAuthentication();

            // when
            inRolledBackTransaction(() -> secretService.deleteOwnedSecret(credentialSecret.getUuid(), owner));
            inNewTransaction(() -> secretInternalService
                    .processSecretAction(deletion(credentialSecret, credentialSecret.getState(), owner), false, false));

            // then
            assertThat(secretRepository.findById(credentialSecret.getUuid())).isEmpty();
        }
    }

    // ── ReferencedObjectResolution ────────────────────────────────────────────

    @Nested
    class ReferencedObjectResolution {

        @Test
        void answers422NamingTheAttribute_whenThePinSecretIsGone() throws Exception {
            // given
            secretRepository.deleteById(secret.getUuid());

            // when
            MvcResult attributes = perform(get(tokenProfileAttributes()));
            MvcResult reload = perform(patch("/v1/tokens/" + token.getUuid()));

            // then
            assertThat(attributes.getResponse().getStatus()).isEqualTo(422);
            assertThat(attributes.getResponse().getContentAsString())
                    .contains("Attribute 'PIN' refers to Secret '" + PIN_SECRET_NAME + "', which no longer exists");
            assertThat(reload.getResponse().getStatus()).isEqualTo(422);
        }

        @Test
        void answers200_whenTheReferencedCredentialExists() throws Exception {
            // given
            storeCredentialReference(persistCredential("hsm-login"));

            // when
            MvcResult attributes = perform(get(tokenProfileAttributes()));

            // then
            assertThat(attributes.getResponse().getStatus()).isEqualTo(200);
        }

        @Test
        void answers422_whenTheReferencedCredentialIsGone() throws Exception {
            // given
            var credentialName = "hsm-login";
            var credential = persistCredential(credentialName);
            storeCredentialReference(credential);
            credentialRepository.delete(credential);

            // when
            MvcResult attributes = perform(get(tokenProfileAttributes()));

            // then
            assertThat(attributes.getResponse().getStatus()).isEqualTo(422);
            assertThat(attributes.getResponse().getContentAsString())
                    .contains("Attribute 'HSM login' refers to Credential '" + credentialName
                            + "', which no longer exists");
        }
    }
}

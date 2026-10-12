package com.otilm.core.integration.api.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
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
import com.otilm.api.model.core.connector.ConnectorStatus;
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
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
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
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;

@AutoConfigureMockMvc
class SecretDeleteReferenceGuardHttpITest extends BaseSpringBootTest {

    private static final String PIN = "1234";

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
    private TspProfileRepository tspProfileRepository;
    @Autowired
    private TspProfileBasicCredentialRepository tspCredentialRepository;
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
    void setUp() throws Exception {
        authService = AuthServiceWireMockStubs.startImpersonating(UUID.randomUUID(), "superadmin");
        tokenProvider = connectorMockFactory
                .startCryptographyProviderV2()
                .stubTokenOperations()
                .stubTokenProfileKeyUsages("[\"sign\"]");
        vaultConnector = startVaultConnector();
        secret = persistGenericSecret(persistVaultProfile(LoopbackWireMock.url(vaultConnector)), "token-pin");
        token = persistV2Token(tokenProvider.getUrl());
        persistPinReference(token, secret);
    }

    @AfterEach
    void tearDown() {
        tokenProvider.stop();
        vaultConnector.stop();
        authService.stop();
    }

    @Test
    void deletingASecretATokenPinUsesIsRefusedAndTheTokenKeepsWorking() throws Exception {
        MvcResult deletion = perform(delete("/v1/secrets/" + secret.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
        assertThat(deletion.getResponse().getContentAsString())
                .contains("Cannot delete Secret 'token-pin'")
                .contains("Token 'pkcs11-v2-token' (attribute 'PIN')");
        assertThat(secretRepository.findById(secret.getUuid())).isPresent();
        assertThat(perform(get(tokenProfileAttributes())).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void aSecretUsedInSeveralPlacesNamesThemAll() throws Exception {
        persistAcmeProfileUsing(secret);

        MvcResult deletion = perform(delete("/v1/secrets/" + secret.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
        assertThat(deletion.getResponse().getContentAsString())
                .contains("Token 'pkcs11-v2-token' (attribute 'PIN')")
                .contains("ACME Profile 'acme-with-eab' (External Account Binding key)");
    }

    @Test
    void aUserTheCallerMayNotSeeIsCountedButNotNamed() throws Exception {
        persistAcmeProfileUsing(secret);
        denyResourceAccess(Resource.TOKEN, ResourceAction.DETAIL);

        MvcResult deletion = perform(delete("/v1/secrets/" + secret.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
        assertThat(deletion.getResponse().getContentAsString())
                .contains("it is still used by ACME Profile 'acme-with-eab' (External Account Binding key); "
                        + "1 object you are not allowed to see.")
                .doesNotContain("pkcs11-v2-token");
    }

    @Test
    void aUserUnderAParentTheCallerMayNotSeeIsCountedButNotNamed() throws Exception {
        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("pin-profile");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceReference(token);
        tokenProfile.setTokenInstanceReferenceUuid(token.getUuid());
        tokenProfileRepository.save(tokenProfile);
        storePinReference(Resource.TOKEN_PROFILE, tokenProfile.getUuid(), null, secret);
        denyResourceAccess(Resource.TOKEN, ResourceAction.DETAIL);

        MvcResult deletion = perform(delete("/v1/secrets/" + secret.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
        assertThat(deletion.getResponse().getContentAsString())
                .contains("it is still used by 2 objects you are not allowed to see.")
                .doesNotContain("pin-profile");
    }

    @Test
    void aUserIsCountedWithoutDetailOnItEvenWhereItsResourceReadChecksNothing() throws Exception {
        Proxy proxy = new Proxy();
        proxy.setName("pin-proxy");
        proxy.setCode("PIN_PROXY");
        proxy.setStatus(ProxyStatus.CONNECTED);
        proxyRepository.save(proxy);
        storePinReference(Resource.PROXY, proxy.getUuid(), null, secret);
        denyResourceAccess(Resource.PROXY, ResourceAction.DETAIL);

        MvcResult deletion = perform(delete("/v1/secrets/" + secret.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
        assertThat(deletion.getResponse().getContentAsString())
                .contains("it is still used by Token 'pkcs11-v2-token' (attribute 'PIN'); "
                        + "1 object you are not allowed to see.")
                .doesNotContain("pin-proxy");
    }

    @Test
    void aUserWhoseObjectIsGoneHoldsNothing() throws Exception {
        Secret leftoverPin = persistGenericSecret(secret.getSourceVaultProfile(), "leftover-pin");
        storePinReference(Resource.TOKEN_PROFILE, UUID.randomUUID(), null, leftoverPin);

        MvcResult deletion = perform(delete("/v1/secrets/" + leftoverPin.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(204);
    }

    @Test
    void aDeletedNotificationInstanceLeavesNoReferenceBehind() throws Exception {
        NotificationInstanceReference notifier = new NotificationInstanceReference();
        notifier.setName("pin-notifier");
        notifier.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(notifier);
        storePinReference(Resource.NOTIFICATION_INSTANCE, notifier.getUuid(), null, secret);
        injectAuthentication();

        notificationInstanceService.deleteNotificationInstance(notifier.getUuid());

        assertThat(referrersOf(secret)).doesNotContain(notifier.getUuid());
    }

    @Test
    void aDeletedVaultInstanceLeavesNoReferenceBehind() throws Exception {
        VaultInstance vault = new VaultInstance();
        vault.setName("pin-vault");
        vaultInstanceRepository.save(vault);
        storePinReference(Resource.VAULT, vault.getUuid(), null, secret);
        injectAuthentication();

        vaultInstanceService.deleteVaultInstance(vault.getUuid());

        assertThat(referrersOf(secret)).doesNotContain(vault.getUuid());
    }

    @Test
    void aUserWithoutAnObjectLookupIsNamedByItsUuid() throws Exception {
        Secret notifierPin = persistGenericSecret(secret.getSourceVaultProfile(), "notifier-pin");
        NotificationInstanceReference notifier = new NotificationInstanceReference();
        notifier.setName("pin-notifier");
        notifier.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(notifier);
        storePinReference(Resource.NOTIFICATION_INSTANCE, notifier.getUuid(), null, notifierPin);

        MvcResult deletion = perform(delete("/v1/secrets/" + notifierPin.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
        assertThat(deletion.getResponse().getContentAsString())
                .contains("Notification instance '" + notifier.getUuid() + "' (attribute 'PIN')");
    }

    @Test
    void aReferenceStoredInUpperCaseIsFound() throws Exception {
        Secret upperCasePin = persistGenericSecret(secret.getSourceVaultProfile(), "upper-case-pin");
        storePinReference(Resource.TOKEN, token.getUuid(), null, upperCasePin.getUuid().toString().toUpperCase(),
                upperCasePin.getName());

        MvcResult deletion = perform(delete("/v1/secrets/" + upperCasePin.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
        assertThat(deletion.getResponse().getContentAsString()).contains("Token 'pkcs11-v2-token' (attribute 'PIN')");
    }

    @Test
    void aReferenceIsFoundWhateverTheCaseOfTheUuidAskedFor() throws Exception {
        Secret askedPin = persistGenericSecret(secret.getSourceVaultProfile(), "asked-pin");
        storePinReference(Resource.TOKEN, token.getUuid(), null, askedPin);

        assertThat(attributeContent2ObjectRepository
                .findResourceAttributeReferrers(Resource.SECRET.getCode(), askedPin.getUuid().toString().toUpperCase()))
                .extracting(ResourceAttributeReferrer::getObjectUuid)
                .containsExactly(token.getUuid());
    }

    @Test
    void aNameIsQuotedAsWritten() {
        ObjectRef secretRef = new ObjectRef(Resource.SECRET, secret.getUuid());
        injectAuthentication();

        assertThatThrownBy(() -> referenceGuard.refuseWhileReferenced(secretRef, "pin{}$1", null))
                .isInstanceOf(ValidationException.class)
                .hasMessage("Cannot delete Secret 'pin{}$1': it is still used by Token 'pkcs11-v2-token' "
                        + "(attribute 'PIN').");
    }

    @Test
    void aDeleteRefusedAfterItsApprovalPutsBackTheSecretsState() throws Exception {
        secret.setState(SecretState.PENDING_APPROVAL);
        secretRepository.save(secret);
        injectAuthentication();

        assertThatThrownBy(() -> secretInternalService.processSecretAction(deletion(secret, null), true, true))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Token 'pkcs11-v2-token' (attribute 'PIN')");

        assertThat(secretRepository.findById(secret.getUuid()))
                .get()
                .extracting(Secret::getState)
                .isEqualTo(SecretState.ACTIVE);
    }

    @Test
    void onlyTheCurrentVersionOfASigningProfileHoldsItsReferences() throws Exception {
        Secret signingPin = persistGenericSecret(secret.getSourceVaultProfile(), "signing-pin");
        SigningProfile profile = persistSigningProfile("versioned-signing", 2);
        ObjectRef signingPinRef = new ObjectRef(Resource.SECRET, signingPin.getUuid());
        injectAuthentication();

        storePinReference(Resource.SIGNING_PROFILE, profile.getUuid(), 1, signingPin);
        assertThat(attributeContent2ObjectRepository
                .findResourceAttributeReferrers(Resource.SECRET.getCode(), signingPin.getUuid().toString()))
                .extracting(ResourceAttributeReferrer::getObjectVersion)
                .containsExactly(1);
        assertThatCode(() -> referenceGuard.refuseWhileReferenced(signingPinRef, "signing-pin", null))
                .doesNotThrowAnyException();

        storePinReference(Resource.SIGNING_PROFILE, profile.getUuid(), 2, signingPin);
        assertThatThrownBy(() -> referenceGuard.refuseWhileReferenced(signingPinRef, "signing-pin", null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("'versioned-signing' (attribute 'PIN')");
    }

    @Test
    void aTspCredentialsSecretIsRefusedToOthersAndReleasedToItsOwner() throws Exception {
        Secret credentialSecret = persistGenericSecret(secret.getSourceVaultProfile(), "tsa-client-password");
        TspProfileBasicCredential credential = persistTspCredential(credentialSecret);

        MvcResult deletion = perform(delete("/v1/secrets/" + credentialSecret.getUuid()));

        assertThat(deletion.getResponse().getStatus()).isEqualTo(422);
        assertThat(deletion.getResponse().getContentAsString())
                .contains("TSP Profile Basic Credential 'tsa-client'")
                .contains("delete the credential from TSP Profile 'tsa'");

        ObjectRef owner = new ObjectRef(Resource.TSP_PROFILE_BASIC_CREDENTIAL, credential.getUuid());
        injectAuthentication();
        inRolledBackTransaction(() -> secretService.deleteOwnedSecret(credentialSecret.getUuid(), owner));
        inNewTransaction(
                () -> secretInternalService.processSecretAction(deletion(credentialSecret, owner), false, false));

        assertThat(secretRepository.findById(credentialSecret.getUuid())).isEmpty();
    }

    @Test
    void aPinWhoseSecretWentMissingAnywayAnswers422NamingTheAttribute() throws Exception {
        secretRepository.deleteById(secret.getUuid());

        MvcResult attributes = perform(get(tokenProfileAttributes()));
        MvcResult reload = perform(patch("/v1/tokens/" + token.getUuid()));

        assertThat(attributes.getResponse().getStatus()).isEqualTo(422);
        assertThat(attributes.getResponse().getContentAsString())
                .contains("Attribute 'PIN' refers to Secret 'token-pin', which no longer exists");
        assertThat(reload.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void aCredentialReferenceAnswers422OnceTheCredentialIsGone() throws Exception {
        Credential credential = new Credential();
        credential.setKind("basic");
        credential.setName("hsm-login");
        credentialRepository.save(credential);
        storeCredentialReference(credential);

        assertThat(perform(get(tokenProfileAttributes())).getResponse().getStatus()).isEqualTo(200);

        credentialRepository.delete(credential);
        MvcResult attributes = perform(get(tokenProfileAttributes()));

        assertThat(attributes.getResponse().getStatus()).isEqualTo(422);
        assertThat(attributes.getResponse().getContentAsString())
                .contains("Attribute 'HSM login' refers to Credential 'hsm-login', which no longer exists");
    }

    private String tokenProfileAttributes() {
        return "/v1/tokens/" + token.getUuid() + "/tokenProfiles/attributes";
    }

    private MvcResult perform(RequestBuilder request) throws Exception {
        injectAuthentication();
        return mockMvc.perform(request).andReturn();
    }

    private List<UUID> referrersOf(Secret referenced) {
        return attributeContent2ObjectRepository
                .findResourceAttributeReferrers(Resource.SECRET.getCode(), referenced.getUuid().toString())
                .stream()
                .map(ResourceAttributeReferrer::getObjectUuid)
                .toList();
    }

    /** The delete action the request queues, as the broker hands it to the listener. */
    private static ActionMessage deletion(Secret secret, ObjectRef releasedBy) {
        ActionMessage message = new ActionMessage();
        message.setResource(Resource.SECRET);
        message.setResourceAction(ResourceAction.DELETE);
        message.setResourceUuid(secret.getUuid());
        message
                .setData(SecretActionData
                        .builder()
                        .deleteInVault(true)
                        .originalState(SecretState.ACTIVE)
                        .releasedBy(releasedBy)
                        .build());
        return message;
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

    private WireMockServer startVaultConnector() throws Exception {
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
        Connector connector = new Connector();
        connector.setName("test-vault-connector");
        connector.setUrl(url);
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
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

    private void persistAcmeProfileUsing(Secret eabKey) {
        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setName("acme-with-eab");
        acmeProfile.setEabSecretUuids(new ArrayList<>(List.of(eabKey.getUuid())));
        acmeProfileRepository.save(acmeProfile);
    }

    private SigningProfile persistSigningProfile(String name, int latestVersion) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(latestVersion);
        return signingProfileRepository.save(profile);
    }

    private TspProfileBasicCredential persistTspCredential(Secret password) {
        TspProfile profile = new TspProfile();
        profile.setName("tsa");
        tspProfileRepository.save(profile);

        TspProfileBasicCredential credential = new TspProfileBasicCredential();
        credential.setTspProfile(profile);
        credential.setUsername("tsa-client");
        credential.setSecretUuid(password.getUuid());
        credential.setMappedUserUuid(UUID.randomUUID());
        return tspCredentialRepository.save(credential);
    }

    private TokenInstanceReference persistV2Token(String url) {
        Connector connector = new Connector();
        connector.setName("pkcs11-cryptography-provider");
        connector.setUrl(url);
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
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
        value.setName("pkcs11-v2-token");
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
}

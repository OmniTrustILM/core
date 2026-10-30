package com.otilm.core.integration.service.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.client.acme.AcmeProfileEditRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.connector.secrets.content.SecretKeySecretContent;
import com.otilm.api.model.core.acme.ExternalAccountBinding;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.AcmeProfileExternalService;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.AcmeTestUtil;
import com.otilm.core.service.acme.eab.AcmeEabKeys;
import com.otilm.core.service.acme.eab.EabTestUtil;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SecretsUtil;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pins the permissions the {@code acme} role must hold for External Account Binding, against the code path that
 * actually asks for them.
 *
 * <p>
 * Reading a binding key is not one authorization check but three, spread across three classes, and the grants live in a
 * Flyway migration that no other test touches — {@code BaseSpringBootTest} stubs {@code OpaClient} to allow everything,
 * so a missing grant is invisible to the rest of the suite and shows up only against a real auth service. These tests
 * assert on the questions put to OPA rather than on the answer, so the migration and the call path cannot drift apart
 * unnoticed.
 *
 * <p>
 * No vault is stubbed. All three checks happen before the connector is called, so the request ends in
 * {@code serverInternal} either way; what is asserted is which checks were reached first. For the same reason the
 * absence of a CREDENTIAL check cannot be asserted here: that one would come after the connector call this fixture
 * never completes, so the assertion would hold whether or not the skip exists. It is covered in
 * {@code ConnectorRequestAttributesBuilderTest}, where the branch is real.
 */
class AcmeEabAuthorizationITest extends BaseSpringBootTest {

    private static final String KEY_TEXT = AcmeEabKeys.generate();
    private static final String PROFILE_NAME = "eabAuthzProfile";
    private static final String NEW_ACCOUNT_PATH = "/acme/" + PROFILE_NAME + "/new-account";

    @Autowired
    private AcmeExternalService acmeService;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private AcmeProfileExternalService acmeProfileService;
    @Autowired
    private AcmeNonceRepository acmeNonceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;
    @Autowired
    private VaultProfileRepository vaultProfileRepository;
    @Autowired
    private SecretRepository secretRepository;
    @Autowired
    private SecretVersionRepository secretVersionRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private KeyPair accountKeyPair;
    private JWK accountKey;
    private Secret secret;
    private VaultProfile vaultProfile;
    private Connector connector;

    @BeforeEach
    void setUpEabProfile() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        accountKeyPair = generator.generateKeyPair();
        accountKey = new RSAKey.Builder((RSAPublicKey) accountKeyPair.getPublic()).build();

        connector = new Connector();
        connector.setName("vaultConnector");
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setConnectorUuid(connector.getUuid());
        authorityInstanceReferenceRepository.save(authority);
        RaProfile raProfile = new RaProfile();
        raProfile.setName("eabAuthzRaProfile");
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authority);
        raProfileRepository.save(raProfile);

        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("eabVaultInstance");
        vaultInstance.setConnector(connector);
        vaultInstanceRepository.save(vaultInstance);

        vaultProfile = new VaultProfile();
        vaultProfile.setName("eabVaultProfile");
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfile.setEnabled(true);
        vaultProfileRepository.save(vaultProfile);

        secret = new Secret();
        secret.setName("eabKeySecret");
        secret.setType(SecretType.SECRET_KEY);
        secret.setState(SecretState.ACTIVE);
        secret.setEnabled(true);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setSourceVaultProfileUuid(vaultProfile.getUuid());

        SecretVersion version = new SecretVersion();
        version.setVersion(1);
        version.setVaultProfile(vaultProfile);
        version.setFingerprint(SecretsUtil.calculateSecretContentFingerprint(new SecretKeySecretContent(KEY_TEXT)));
        secretVersionRepository.save(version);
        secret.setLatestVersion(version);
        secretRepository.save(secret);
        version.setSecretUuid(secret.getUuid());
        secretVersionRepository.save(version);

        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setName(PROFILE_NAME);
        acmeProfile.setEnabled(true);
        acmeProfile.setDisableNewOrders(false);
        acmeProfile.setRaProfile(raProfile);
        acmeProfile.setRetryInterval(30);
        acmeProfile.setValidity(30);
        acmeProfile.setEabSecretUuids(List.of(secret.getUuid()));
        acmeProfileRepository.save(acmeProfile);
    }

    @Test
    void readingABindingKeyAsksForEveryPermissionTheAcmeRoleIsGranted() throws Exception {
        registerExpectingInternalError();

        // The set granted by V202609101100. Adding a gate to the read path without granting it here fails this.
        verify(opaClient, atLeastOnce())
                .checkResourceAccess(any(), argThat(asks(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT)), any(),
                        any());
        verify(opaClient, atLeastOnce())
                .checkResourceAccess(any(), argThat(asks(Resource.VAULT_PROFILE, ResourceAction.MEMBERS)), any(),
                        any());
        verify(opaClient, atLeastOnce())
                .checkResourceAccess(any(), argThat(asks(Resource.CONNECTOR, ResourceAction.DETAIL)), any(), any());
    }

    @Test
    void withoutTheSecretContentPermissionTheReadStopsAtTheFirstGate() throws Exception {
        deny(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);

        registerExpectingInternalError();

        verify(opaClient, never())
                .checkResourceAccess(any(), argThat(asks(Resource.VAULT_PROFILE, ResourceAction.MEMBERS)), any(),
                        any());
    }

    @Test
    void withoutTheVaultProfilePermissionTheReadStopsBeforeTheConnector() throws Exception {
        deny(Resource.VAULT_PROFILE, ResourceAction.MEMBERS);

        registerExpectingInternalError();

        verify(opaClient, atLeastOnce())
                .checkResourceAccess(any(), argThat(asks(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT)), any(),
                        any());
        verify(opaClient, never())
                .checkResourceAccess(any(), argThat(asks(Resource.CONNECTOR, ResourceAction.DETAIL)), any(), any());
    }

    @Test
    void withoutTheConnectorPermissionTheReadStillFails() throws Exception {
        deny(Resource.CONNECTOR, ResourceAction.DETAIL);

        registerExpectingInternalError();

        verify(opaClient, atLeastOnce())
                .checkResourceAccess(any(), argThat(asks(Resource.CONNECTOR, ResourceAction.DETAIL)), any(), any());
    }

    @Test
    void assigningAKeyDemandsBothPermissionsTheReadItself() {
        // The operator delegating the read must be able to perform it, which takes the same two gates the read
        // passes. Checking only the content permission would let someone who cannot read a secret put it in charge
        // of a profile.
        AcmeProfileEditRequestDto request = new AcmeProfileEditRequestDto();
        request.setEabSecretUuids(List.of(secret.getUuid()));
        SecuredUUID profileUuid = SecuredUUID
                .fromUUID(acmeProfileRepository.findByName(PROFILE_NAME).orElseThrow().getUuid());

        deny(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);
        Assertions
                .assertThrows(AccessDeniedException.class,
                        () -> acmeProfileService.editAcmeProfile(profileUuid, request));

        mockSuccessfulCheckResourceAccess();
        deny(Resource.VAULT_PROFILE, ResourceAction.MEMBERS);
        Assertions
                .assertThrows(AccessDeniedException.class,
                        () -> acmeProfileService.editAcmeProfile(profileUuid, request));
    }

    /**
     * Every outcome here is {@code serverInternal}: with the permissions granted the read reaches the vault, which is
     * not stubbed, and without them it is denied. The distinction the tests draw is in the checks reached, not the
     * response.
     */
    private void registerExpectingInternalError() throws Exception {
        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class, this::newAccountWithBinding);

        Assertions.assertEquals(500, e.getHttpStatusCode());
        Assertions.assertEquals("urn:ietf:params:acme:error:serverInternal", e.getProblemDocument().getType());
    }

    private void newAccountWithBinding() throws Exception {
        ExternalAccountBinding binding = EabTestUtil
                .build(secret.getUuid(), NEW_ACCOUNT_PATH, accountKey, AcmeEabKeys.decode(KEY_TEXT));
        Map<String, Object> payload = new HashMap<>();
        payload.put("termsOfServiceAgreed", true);
        payload.put("externalAccountBinding", binding);

        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, accountKeyPair, acmeNonceRepository, payload, NEW_ACCOUNT_PATH, null,
                        PROFILE_NAME);
        acmeService.newAccount(PROFILE_NAME, jws, URI.create(NEW_ACCOUNT_PATH), false);
    }

    private void deny(Resource resource, ResourceAction action) {
        OpaResourceAccessResult denied = new OpaResourceAccessResult();
        denied.setAuthorized(false);
        denied.setAllow(List.of());
        when(opaClient.checkResourceAccess(any(), argThat(asks(resource, action)), any(), any())).thenReturn(denied);
    }

    private static org.mockito.ArgumentMatcher<OpaRequestedResource> asks(Resource resource, ResourceAction action) {
        return request -> request != null && request.getProperties() != null
                && resource.getCode().equals(request.getProperties().get("name"))
                && action.getCode().equals(request.getProperties().get("action"));
    }
}

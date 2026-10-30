package com.otilm.core.integration.service.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.Directory;
import com.otilm.api.model.core.acme.ExternalAccountBinding;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.AcmeTestUtil;
import com.otilm.core.service.acme.eab.AcmeEabKeys;
import com.otilm.core.service.acme.eab.EabTestUtil;
import com.otilm.core.util.BaseSpringBootTest;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

/**
 * Covers how a profile's External Account Binding configuration reaches the ACME endpoints: what the directory
 * advertises, and what newAccount does with the binding a client presents.
 *
 * <p>
 * The binding that verifies is exercised in {@code AcmeEabVerifierTest}; reaching it here would need a vault-backed
 * secret whose content can actually be read. What this test pins instead is the wiring around that call - that the
 * verifier is consulted at all, against the URL the client signed over, and that a request it turns down leaves no
 * account behind.
 */
class AcmeEabAccountITest extends BaseSpringBootTest {

    private static final String PROFILE_NAME = "eabProfile";
    private static final String NEW_ACCOUNT_PATH = "/acme/" + PROFILE_NAME + "/new-account";

    @Autowired
    private AcmeExternalService acmeService;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private AcmeAccountRepository acmeAccountRepository;
    @Autowired
    private AcmeNonceRepository acmeNonceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AcmeProfile acmeProfile;
    private KeyPair accountKeyPair;
    private JWK accountKey;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        accountKeyPair = generator.generateKeyPair();
        accountKey = new RSAKey.Builder((RSAPublicKey) accountKeyPair.getPublic()).build();

        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setConnectorUuid(connector.getUuid());
        authorityInstanceReferenceRepository.save(authority);
        RaProfile raProfile = new RaProfile();
        raProfile.setName("eabRaProfile");
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authority);
        raProfileRepository.save(raProfile);

        acmeProfile = new AcmeProfile();
        acmeProfile.setName(PROFILE_NAME);
        acmeProfile.setEnabled(true);
        acmeProfile.setDisableNewOrders(false);
        acmeProfile.setRaProfile(raProfile);
        acmeProfile.setRetryInterval(30);
        acmeProfile.setValidity(30);
        acmeProfileRepository.save(acmeProfile);
    }

    @Test
    void theDirectoryAdvertisesTheRequirementOnlyWhenAKeyIsConfigured() throws Exception {
        ResponseEntity<Directory> open = acmeService.getDirectory(PROFILE_NAME, URI.create("/acme/x/directory"), false);
        Assertions.assertEquals(Boolean.FALSE, open.getBody().getMeta().getExternalAccountRequired());

        configureKeys(UUID.randomUUID());

        ResponseEntity<Directory> bound = acmeService
                .getDirectory(PROFILE_NAME, URI.create("/acme/x/directory"), false);
        Assertions.assertEquals(Boolean.TRUE, bound.getBody().getMeta().getExternalAccountRequired());
    }

    @Test
    void aProfileWithoutKeysRegistersAnAccountUnboundToAnySecret() throws Exception {
        ResponseEntity<Account> response = newAccount(null);

        Assertions.assertEquals(201, response.getStatusCode().value());
        Assertions.assertNull(storedAccount().getEabSecretUuid());
    }

    @Test
    void aProfileWhoseNewOrderSwitchWasNeverSetStillServesRequests() throws Exception {
        // Older rows, and any edit that once cleared it, leave the column null; reading it must not fail the request.
        acmeProfile.setDisableNewOrders(null);
        acmeProfileRepository.save(acmeProfile);

        Assertions.assertEquals(201, newAccount(null).getStatusCode().value());
    }

    @Test
    void aKeyWithdrawnWhileTheBindingWasVerifiedDoesNotAdmitTheAccount() throws Exception {
        // The profile is re-read under a lock at write time, so an edit that lands during verification decides the
        // outcome rather than the copy the verification was performed against.
        UUID configured = UUID.randomUUID();
        configureKeys(configured);
        byte[] macKey = AcmeEabKeys.decode(AcmeEabKeys.generate());
        ExternalAccountBinding binding = EabTestUtil.build(configured, NEW_ACCOUNT_PATH, accountKey, macKey);

        // Stand in for the concurrent edit: the verification below cannot succeed anyway (the secret is unreadable),
        // so what this pins is that the write refuses a key the profile no longer lists.
        configureKeys(UUID.randomUUID());

        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> newAccount(binding));

        Assertions.assertEquals(401, e.getHttpStatusCode());
        assertNoAccountWasCreated();
    }

    @Test
    void aProfileWithKeysRefusesAnAccountThatPresentsNoBinding() throws Exception {
        configureKeys(UUID.randomUUID());

        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> newAccount(null));

        Assertions.assertEquals(400, e.getHttpStatusCode());
        Assertions.assertEquals("urn:ietf:params:acme:error:externalAccountRequired", e.getProblemDocument().getType());
        assertNoAccountWasCreated();
    }

    @Test
    void aBindingNamingAKeyTheProfileDoesNotAcceptIsRefused() throws Exception {
        configureKeys(UUID.randomUUID());
        byte[] macKey = AcmeEabKeys.decode(AcmeEabKeys.generate());

        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> newAccount(EabTestUtil.build(UUID.randomUUID(), NEW_ACCOUNT_PATH, accountKey, macKey)));

        Assertions.assertEquals(401, e.getHttpStatusCode());
        Assertions.assertEquals("urn:ietf:params:acme:error:unauthorized", e.getProblemDocument().getType());
        assertNoAccountWasCreated();
    }

    @Test
    void aBindingNamingAConfiguredButUnreadableKeyFailsAsAnInternalError() throws Exception {
        // The secret the profile names does not exist, so the read the verifier attempts cannot succeed. Reaching
        // this outcome is what shows the named key - not some other one - is the one looked up.
        UUID configured = UUID.randomUUID();
        configureKeys(configured);
        byte[] macKey = AcmeEabKeys.decode(AcmeEabKeys.generate());

        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> newAccount(EabTestUtil.build(configured, NEW_ACCOUNT_PATH, accountKey, macKey)));

        Assertions.assertEquals(500, e.getHttpStatusCode());
        Assertions.assertEquals("urn:ietf:params:acme:error:serverInternal", e.getProblemDocument().getType());
        assertNoAccountWasCreated();
    }

    @Test
    void aBindingSignedOverAnotherUrlIsRefused() throws Exception {
        UUID configured = UUID.randomUUID();
        configureKeys(configured);
        byte[] macKey = AcmeEabKeys.decode(AcmeEabKeys.generate());

        // Signed over a different newAccount URL, so it is turned down before the key is ever read - which pins that
        // the URL handed to the verifier is the one the request arrived on.
        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> newAccount(EabTestUtil.build(configured, "/acme/other/new-account", accountKey, macKey)));

        Assertions.assertEquals(401, e.getHttpStatusCode());
        assertNoAccountWasCreated();
    }

    private void configureKeys(UUID... secretUuids) {
        acmeProfile.setEabSecretUuids(List.of(secretUuids));
        acmeProfileRepository.save(acmeProfile);
    }

    private ResponseEntity<Account> newAccount(ExternalAccountBinding binding) throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("termsOfServiceAgreed", true);
        payload.put("contact", List.of("mailto:admin@example.com"));
        if (binding != null) {
            payload.put("externalAccountBinding", binding);
        }
        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, accountKeyPair, acmeNonceRepository, payload, NEW_ACCOUNT_PATH, null,
                        PROFILE_NAME);
        return acmeService.newAccount(PROFILE_NAME, jws, URI.create(NEW_ACCOUNT_PATH), false);
    }

    private AcmeAccount storedAccount() {
        List<AcmeAccount> accounts = acmeAccountRepository.findAll();
        Assertions.assertEquals(1, accounts.size(), "exactly one account is expected");
        return accounts.getFirst();
    }

    private void assertNoAccountWasCreated() {
        Assertions.assertTrue(acmeAccountRepository.findAll().isEmpty(), "a refused binding must leave no account");
    }
}

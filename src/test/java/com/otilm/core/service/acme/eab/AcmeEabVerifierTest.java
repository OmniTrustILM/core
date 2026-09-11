package com.otilm.core.service.acme.eab;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.connector.secrets.content.GenericSecretContent;
import com.otilm.api.model.connector.secrets.content.SecretKeySecretContent;
import com.otilm.api.model.core.acme.ExternalAccountBinding;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.service.SecretExternalService;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AcmeEabVerifierTest {

    private static final URI NEW_ACCOUNT = URI.create("https://acme.example/api/acme/profile/new-account");

    private SecretExternalService secretService;
    private AcmeEabVerifier verifier;

    private AcmeProfile acmeProfile;
    private UUID keyUuid;
    private String keyText;
    private byte[] macKey;
    private ECKey accountKey;

    @BeforeEach
    void setUp() throws Exception {
        secretService = mock(SecretExternalService.class);
        verifier = new AcmeEabVerifier();
        verifier.setSecretService(secretService);

        keyUuid = UUID.randomUUID();
        keyText = AcmeEabKeys.generate();
        macKey = AcmeEabKeys.decode(keyText);
        accountKey = new ECKeyGenerator(Curve.P_256).generate();

        acmeProfile = new AcmeProfile();
        acmeProfile.setName("eab-profile");
        acmeProfile.setEabSecretUuids(List.of(keyUuid));
        when(secretService.getSecretContent(keyUuid)).thenReturn(new SecretKeySecretContent(keyText));
    }

    @Test
    void aBindingUnderAConfiguredKeyVerifiesAndNamesThatKey() throws Exception {
        ExternalAccountBinding binding = EabTestUtil.build(keyUuid, NEW_ACCOUNT.toString(), accountKey, macKey);

        assertEquals(keyUuid, verifier.verify(acmeProfile, binding, accountKey.toPublicJWK(), NEW_ACCOUNT));
    }

    @Test
    void aGenericSecretHoldsTheKeyJustAsWell() throws Exception {
        when(secretService.getSecretContent(keyUuid)).thenReturn(new GenericSecretContent(keyText));
        ExternalAccountBinding binding = EabTestUtil.build(keyUuid, NEW_ACCOUNT.toString(), accountKey, macKey);

        assertEquals(keyUuid, verifier.verify(acmeProfile, binding, accountKey.toPublicJWK(), NEW_ACCOUNT));
    }

    @Test
    void noBindingAtAllAsksTheClientForOne() {
        AcmeProblemDocumentException e = assertThrows(AcmeProblemDocumentException.class,
                () -> verifier.verify(acmeProfile, null, accountKey.toPublicJWK(), NEW_ACCOUNT));

        assertEquals(400, e.getHttpStatusCode());
        assertEquals("urn:ietf:params:acme:error:externalAccountRequired", e.getProblemDocument().getType());
    }

    @Test
    void aKeyTheProfileDoesNotAcceptIsRejectedWithoutReadingAnySecret() throws Exception {
        ExternalAccountBinding binding = EabTestUtil
                .build(UUID.randomUUID(), NEW_ACCOUNT.toString(), accountKey, macKey);

        assertUnauthorized(binding, accountKey.toPublicJWK(), NEW_ACCOUNT);
        verify(secretService, never()).getSecretContent(any());
    }

    @Test
    void aBindingForAnotherUrlIsRejected() throws Exception {
        ExternalAccountBinding binding = EabTestUtil
                .build(keyUuid, "https://acme.example/api/acme/other/new-account", accountKey, macKey);

        assertUnauthorized(binding, accountKey.toPublicJWK(), NEW_ACCOUNT);
    }

    @Test
    void aBindingCarryingAnotherAccountKeyIsRejected() throws Exception {
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        ExternalAccountBinding binding = EabTestUtil.build(keyUuid, NEW_ACCOUNT.toString(), otherKey, macKey);

        assertUnauthorized(binding, accountKey.toPublicJWK(), NEW_ACCOUNT);
    }

    @Test
    void aBindingMacedUnderAnotherKeyIsRejected() throws Exception {
        byte[] otherMacKey = AcmeEabKeys.decode(AcmeEabKeys.generate());
        ExternalAccountBinding binding = EabTestUtil.build(keyUuid, NEW_ACCOUNT.toString(), accountKey, otherMacKey);

        assertUnauthorized(binding, accountKey.toPublicJWK(), NEW_ACCOUNT);
    }

    @Test
    void aBindingCarryingANonceIsRejected() throws Exception {
        ExternalAccountBinding binding = EabTestUtil
                .buildWithNonce(keyUuid, NEW_ACCOUNT.toString(), accountKey, macKey, "replay-me");

        assertUnauthorized(binding, accountKey.toPublicJWK(), NEW_ACCOUNT);
    }

    @Test
    void everyRejectionReadsTheSame() throws Exception {
        ExternalAccountBinding unknownKey = EabTestUtil
                .build(UUID.randomUUID(), NEW_ACCOUNT.toString(), accountKey, macKey);
        ExternalAccountBinding badMac = EabTestUtil
                .build(keyUuid, NEW_ACCOUNT.toString(), accountKey, AcmeEabKeys.decode(AcmeEabKeys.generate()));

        String first = assertUnauthorized(unknownKey, accountKey.toPublicJWK(), NEW_ACCOUNT);
        String second = assertUnauthorized(badMac, accountKey.toPublicJWK(), NEW_ACCOUNT);

        assertEquals(first, second, "a caller must not learn which of the checks it failed");
    }

    @Test
    void anUnreadableKeyIsAnInternalErrorRatherThanARejection() throws Exception {
        when(secretService.getSecretContent(keyUuid)).thenThrow(new NotFoundException("Secret", keyUuid));
        ExternalAccountBinding binding = EabTestUtil.build(keyUuid, NEW_ACCOUNT.toString(), accountKey, macKey);

        assertServerInternal(binding);
    }

    @Test
    void anUnavailableVaultIsAnInternalErrorRatherThanARejection() throws Exception {
        when(secretService.getSecretContent(keyUuid)).thenThrow(new ConnectorException("vault is down"));
        ExternalAccountBinding binding = EabTestUtil.build(keyUuid, NEW_ACCOUNT.toString(), accountKey, macKey);

        assertServerInternal(binding);
    }

    @Test
    void aSecretThatHoldsNoKeyIsAnInternalError() throws Exception {
        when(secretService.getSecretContent(keyUuid)).thenReturn(new BasicAuthSecretContent("user", "password"));
        ExternalAccountBinding binding = EabTestUtil.build(keyUuid, NEW_ACCOUNT.toString(), accountKey, macKey);

        assertServerInternal(binding);
    }

    @Test
    void aKeyTooShortForHs256IsAnInternalError() throws Exception {
        // Signed under a usable key: only the stored one is too short, which is the configuration fault under test.
        // A client could not produce a binding under a 128-bit key at all - the signer refuses it.
        when(secretService.getSecretContent(keyUuid))
                .thenReturn(new SecretKeySecretContent(Base64URL.encode(new byte[16]).toString()));
        ExternalAccountBinding binding = EabTestUtil.build(keyUuid, NEW_ACCOUNT.toString(), accountKey, macKey);

        assertServerInternal(binding);
    }

    @Test
    void anyOfTheProfilesKeysMayBeUsed() throws Exception {
        UUID secondUuid = UUID.randomUUID();
        String secondKeyText = AcmeEabKeys.generate();
        acmeProfile.setEabSecretUuids(List.of(keyUuid, secondUuid));
        when(secretService.getSecretContent(secondUuid)).thenReturn(new SecretKeySecretContent(secondKeyText));
        ExternalAccountBinding binding = EabTestUtil
                .build(secondUuid, NEW_ACCOUNT.toString(), accountKey, AcmeEabKeys.decode(secondKeyText));

        assertEquals(secondUuid, verifier.verify(acmeProfile, binding, accountKey.toPublicJWK(), NEW_ACCOUNT));
    }

    private String assertUnauthorized(ExternalAccountBinding binding, com.nimbusds.jose.jwk.JWK accountJwk, URI uri) {
        AcmeProblemDocumentException e = assertThrows(AcmeProblemDocumentException.class,
                () -> verifier.verify(acmeProfile, binding, accountJwk, uri));

        assertEquals(401, e.getHttpStatusCode());
        assertEquals("urn:ietf:params:acme:error:unauthorized", e.getProblemDocument().getType());
        return e.getProblemDocument().getDetail();
    }

    private void assertServerInternal(ExternalAccountBinding binding) throws JOSEException {
        AcmeProblemDocumentException e = assertThrows(AcmeProblemDocumentException.class,
                () -> verifier.verify(acmeProfile, binding, accountKey.toPublicJWK(), NEW_ACCOUNT));

        assertEquals(500, e.getHttpStatusCode());
        assertEquals("urn:ietf:params:acme:error:serverInternal", e.getProblemDocument().getType());
    }
}

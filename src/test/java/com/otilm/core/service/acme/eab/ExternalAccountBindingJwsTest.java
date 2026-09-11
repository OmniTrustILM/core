package com.otilm.core.service.acme.eab;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.otilm.api.model.core.acme.ExternalAccountBinding;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExternalAccountBindingJwsTest {

    private static final String URL = "https://acme.example/api/acme/profile/new-account";
    private static final UUID KID = UUID.fromString("f2bfe4a1-b834-4f0c-9bd6-e0b323f8a5f8");

    private ECKey accountKey;
    private byte[] macKey;

    @BeforeEach
    void setUp() throws JOSEException {
        accountKey = new ECKeyGenerator(Curve.P_256).generate();
        macKey = AcmeEabKeys.decode(AcmeEabKeys.generate());
    }

    @Test
    void aGeneratedKeyCarriesEnoughMaterialForHs256() {
        assertTrue(macKey.length >= 32, "a generated key must be at least 256 bits");
    }

    @Test
    void standardBase64DecodesToTheSameBytesAsBase64Url() {
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (250 - i);
        }
        String base64Url = Base64URL.encode(bytes).toString();
        String standard = java.util.Base64.getEncoder().encodeToString(bytes);

        assertArrayEquals(bytes, AcmeEabKeys.decode(base64Url));
        assertArrayEquals(bytes, AcmeEabKeys.decode(standard),
                "an operator pasting standard base64 must yield the same key");
    }

    @Test
    void anEmptyOrUndecodableKeyIsUnusable() {
        assertThrows(UnusableEabKeyException.class, () -> AcmeEabKeys.decode("  "));
        assertThrows(UnusableEabKeyException.class, () -> AcmeEabKeys.decode(null));
        assertThrows(UnusableEabKeyException.class, () -> AcmeEabKeys.decode("!!!"));
    }

    @Test
    void wellFormedBindingParsesAndVerifies() throws JOSEException {
        ExternalAccountBindingJws jws = ExternalAccountBindingJws
                .parse(EabTestUtil.build(KID, URL, accountKey, macKey));

        assertNotNull(jws);
        assertEquals(KID, jws.keyIdentifier());
        assertTrue(jws.isForUrl(URL));
        assertFalse(jws.hasNonce());
        assertTrue(jws.bindsAccountKey(accountKey.toPublicJWK()));
        assertTrue(jws.verify(macKey));
    }

    @Test
    void wrongKeyDoesNotVerify() throws JOSEException {
        ExternalAccountBindingJws jws = ExternalAccountBindingJws
                .parse(EabTestUtil.build(KID, URL, accountKey, macKey));

        assertFalse(jws.verify(AcmeEabKeys.decode(AcmeEabKeys.generate())));
    }

    @Test
    void aMacThatCannotBeEvaluatedIsNotReportedAsAWrongMac() throws JOSEException {
        // A provider or verifier fault must not reach a client holding a good credential as a rejection.
        ExternalAccountBindingJws jws = ExternalAccountBindingJws
                .parse(EabTestUtil.build(KID, URL, accountKey, macKey));

        assertThrows(UnusableEabKeyException.class, () -> jws.verify(new byte[0]));
    }

    @Test
    void keyTooShortForHs256IsAConfigurationFaultNotAMismatch() throws JOSEException {
        ExternalAccountBindingJws jws = ExternalAccountBindingJws
                .parse(EabTestUtil.build(KID, URL, accountKey, macKey));
        byte[] shortKey = "device-7-secret".getBytes(StandardCharsets.UTF_8);

        assertThrows(UnusableEabKeyException.class, () -> jws.verify(shortKey));
    }

    @Test
    void otherUrlAndOtherAccountKeyDoNotBind() throws JOSEException {
        ExternalAccountBindingJws jws = ExternalAccountBindingJws
                .parse(EabTestUtil.build(KID, URL, accountKey, macKey));

        assertFalse(jws.isForUrl(URL + "/"));
        assertFalse(jws.bindsAccountKey(new ECKeyGenerator(Curve.P_256).generate().toPublicJWK()));
        assertFalse(jws.bindsAccountKey(null));
    }

    @Test
    void nonUuidOrMissingKidNamesNoKey() throws JOSEException {
        assertNull(ExternalAccountBindingJws
                .parse(EabTestUtil.build(JWSAlgorithm.HS256, "not-a-uuid", URL, accountKey, macKey))
                .keyIdentifier());
        assertNull(ExternalAccountBindingJws
                .parse(EabTestUtil.build(JWSAlgorithm.HS256, null, URL, accountKey, macKey))
                .keyIdentifier());
    }

    @Test
    void missingUrlIsNotForAnyUrl() throws JOSEException {
        assertFalse(ExternalAccountBindingJws
                .parse(EabTestUtil.build(JWSAlgorithm.HS256, KID.toString(), null, accountKey, macKey))
                .isForUrl(URL));
    }

    @Test
    void aNonceInTheProtectedHeaderIsVisible() throws JOSEException {
        assertTrue(ExternalAccountBindingJws
                .parse(EabTestUtil.buildWithNonce(KID, URL, accountKey, macKey, "replay-me"))
                .hasNonce());
    }

    @Test
    void onlyHs256IsAccepted() throws JOSEException {
        byte[] longKey = new byte[48];
        assertNull(ExternalAccountBindingJws
                .parse(EabTestUtil.build(JWSAlgorithm.HS384, KID.toString(), URL, accountKey, longKey)));
    }

    @Test
    void structurallyInvalidBindingsDoNotParse() throws JOSEException {
        assertNull(ExternalAccountBindingJws.parse(null));

        ExternalAccountBinding missingSignature = EabTestUtil.build(KID, URL, accountKey, macKey);
        missingSignature.setSignature(null);
        assertNull(ExternalAccountBindingJws.parse(missingSignature));

        ExternalAccountBinding garbageHeader = EabTestUtil.build(KID, URL, accountKey, macKey);
        garbageHeader.setProtectedHeader("!!not-base64url!!");
        assertNull(ExternalAccountBindingJws.parse(garbageHeader));

        ExternalAccountBinding payloadNotJwk = EabTestUtil.build(KID, URL, accountKey, macKey);
        payloadNotJwk.setPayload(Base64URL.encode("{\"hello\":\"world\"}").toString());
        assertNull(ExternalAccountBindingJws.parse(payloadNotJwk));
    }
}

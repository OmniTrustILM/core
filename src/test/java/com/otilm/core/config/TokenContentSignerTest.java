package com.otilm.core.config;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureResponseData;
import com.otilm.api.model.client.cryptography.operations.VerificationResponseData;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.OperationKeyContext;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TokenContentSignerTest {

    private static final byte[] DATA = {1, 2, 3};
    private static final byte[] SIGNATURE = {7, 7};
    private static final AlgorithmIdentifier SHA256_WITH_RSA = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);

    private final KeyProviderAdapter keyProvider = mock(KeyProviderAdapter.class);
    private final OperationKeyContext signingKey = OperationKeyContext
            .legacy(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA));
    private final OperationKeyContext verificationKey = OperationKeyContext
            .legacy(CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA));
    private final List<RequestAttribute> attributes = List
            .of(RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

    @Test
    void getSignature_signsTheWrittenBytesWithTheSigningKey() throws Exception {
        // given
        when(keyProvider.signData(eq(signingKey), any())).thenReturn(signatures(SIGNATURE));
        TokenContentSigner signer = signer((data, signature) -> true);

        // when
        byte[] signature = sign(signer, DATA);

        // then
        assertArrayEquals(SIGNATURE, signature);
        ArgumentCaptor<SignDataRequestDto> request = ArgumentCaptor.forClass(SignDataRequestDto.class);
        verify(keyProvider).signData(eq(signingKey), request.capture());
        assertEquals("AQID", request.getValue().getData().getFirst().getData());
        assertSame(attributes, request.getValue().getSignatureAttributes());
    }

    @Test
    void getSignature_refusesSignatureTheCheckRejects() throws Exception {
        // given
        when(keyProvider.signData(eq(signingKey), any())).thenReturn(signatures(SIGNATURE));
        TokenContentSigner signer = signer((data, signature) -> false);

        // when
        Executable sign = () -> sign(signer, DATA);

        // then
        assertThrows(ValidationException.class, sign);
    }

    @Test
    void getSignature_refusesResponseWithoutSignature() throws Exception {
        // given
        when(keyProvider.signData(eq(signingKey), any())).thenReturn(new SignDataResponseDto());
        TokenContentSigner signer = signer((data, signature) -> true);

        // when
        Executable sign = () -> sign(signer, DATA);

        // then
        assertThrows(ValidationException.class, sign);
    }

    @Test
    void getSignature_reportsConnectorFailureWithoutTheConnectorsText() throws Exception {
        // given
        when(keyProvider.signData(eq(signingKey), any())).thenThrow(new ConnectorException("provider down"));
        TokenContentSigner signer = signer((data, signature) -> true);

        // when
        Executable sign = () -> sign(signer, DATA);

        // then
        ValidationException failure = assertThrows(ValidationException.class, sign);
        assertEquals(List.of("Error when communicating with the connector."), descriptions(failure));
    }

    @Test
    void verifiedByProvider_asksTheVerificationKeyAboutTheSignedData() throws Exception {
        // given
        when(keyProvider.verifyData(eq(verificationKey), any())).thenReturn(verifications(true));
        TokenContentSigner.SignatureCheck check = TokenContentSigner
                .verifiedByProvider(keyProvider, verificationKey, attributes);

        // when
        boolean valid = check.verify(DATA, SIGNATURE);

        // then
        assertTrue(valid);
        ArgumentCaptor<VerifyDataRequestDto> request = ArgumentCaptor.forClass(VerifyDataRequestDto.class);
        verify(keyProvider).verifyData(eq(verificationKey), request.capture());
        assertEquals("AQID", request.getValue().getData().getFirst().getData());
        assertEquals("Bwc=", request.getValue().getSignatures().getFirst().getData());
        assertSame(attributes, request.getValue().getSignatureAttributes());
    }

    @Test
    void verifiedByProvider_isFalse_whenTheProviderRejectsTheSignature() throws Exception {
        // given
        when(keyProvider.verifyData(eq(verificationKey), any())).thenReturn(verifications(false));
        TokenContentSigner.SignatureCheck check = TokenContentSigner
                .verifiedByProvider(keyProvider, verificationKey, attributes);

        // when
        boolean valid = check.verify(DATA, SIGNATURE);

        // then
        assertFalse(valid);
    }

    @Test
    void verifiedByProvider_isFalse_whenTheProviderReturnsNoVerification() throws Exception {
        // given
        when(keyProvider.verifyData(eq(verificationKey), any())).thenReturn(new VerifyDataResponseDto());
        TokenContentSigner.SignatureCheck check = TokenContentSigner
                .verifiedByProvider(keyProvider, verificationKey, attributes);

        // when
        boolean valid = check.verify(DATA, SIGNATURE);

        // then
        assertFalse(valid);
    }

    @Test
    void verifiedAgainst_acceptsOnlyASignatureOfThatKey() throws Exception {
        // given
        KeyPair keyPair = rsaKeyPair();
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(keyPair.getPrivate());
        rsa.update(DATA);
        byte[] signature = rsa.sign();
        TokenContentSigner.SignatureCheck check = TokenContentSigner
                .verifiedAgainst(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()), SHA256_WITH_RSA);

        // when
        boolean validForSignedData = check.verify(DATA, signature);
        boolean validForOtherData = check.verify(new byte[]{4, 5, 6}, signature);

        // then
        assertTrue(validForSignedData);
        assertFalse(validForOtherData);
    }

    @Test
    void verifiedAgainst_isFalse_forBytesThatAreNoSignatureOfTheKeyAtAll() throws Exception {
        // given
        KeyPair keyPair = rsaKeyPair();
        TokenContentSigner.SignatureCheck check = TokenContentSigner
                .verifiedAgainst(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()), SHA256_WITH_RSA);

        // when
        boolean valid = check.verify(DATA, SIGNATURE);

        // then
        assertFalse(valid);
    }

    @Test
    void verifiedAgainst_refusesWithoutTheVerifiersText_whenTheKeyCannotVerifyUnderTheAlgorithm() throws Exception {
        // given
        KeyPair keyPair = rsaKeyPair();
        AlgorithmIdentifier ecdsa = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        TokenContentSigner.SignatureCheck check = TokenContentSigner
                .verifiedAgainst(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()), ecdsa);

        // when
        Executable verify = () -> check.verify(DATA, SIGNATURE);

        // then
        ValidationException failure = assertThrows(ValidationException.class, verify);
        assertEquals(List.of("Cannot verify the signature from the connector."), descriptions(failure));
    }

    private static List<String> descriptions(ValidationException failure) {
        return failure.getErrors().stream().map(ValidationError::getErrorDescription).toList();
    }

    private TokenContentSigner signer(TokenContentSigner.SignatureCheck check) {
        return new TokenContentSigner(keyProvider, signingKey, attributes, SHA256_WITH_RSA, check);
    }

    private static byte[] sign(TokenContentSigner signer, byte[] data) throws Exception {
        try (OutputStream out = signer.getOutputStream()) {
            out.write(data);
        }
        return signer.getSignature();
    }

    private static SignDataResponseDto signatures(byte[] signature) {
        SignatureResponseData data = new SignatureResponseData();
        data.setData(Base64.getEncoder().encodeToString(signature));
        SignDataResponseDto response = new SignDataResponseDto();
        response.setSignatures(List.of(data));
        return response;
    }

    private static VerifyDataResponseDto verifications(boolean result) {
        VerificationResponseData data = new VerificationResponseData();
        data.setResult(result);
        VerifyDataResponseDto response = new VerifyDataResponseDto();
        response.setVerifications(List.of(data));
        return response;
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}

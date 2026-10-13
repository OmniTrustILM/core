package com.otilm.core.provider;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.ObjectAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.handler.LegacyOperationFixtures;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.handler.key.KeyProviderV1Adapter;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class LegacyRawSignatureProviderTest {

    private final CryptographicOperationsSyncApiClient client = mock(CryptographicOperationsSyncApiClient.class);
    private KeyProviderV1Adapter adapter;
    private PlatformProvider provider;

    @BeforeEach
    void setUp() throws NotFoundException {
        ApiClientConnectorInfo connector = mock(ApiClientConnectorInfo.class);
        ConnectorApiFactory apiFactory = mock(ConnectorApiFactory.class);
        when(apiFactory.getCryptographicOperationsApiClient(connector)).thenReturn(client);
        adapter = new KeyProviderV1Adapter(apiFactory, connector, mock(AttributeEngine.class));
        KeyProviderAdapterFactory adapterFactory = mock(KeyProviderAdapterFactory.class);
        when(adapterFactory.forKeyItem(any())).thenReturn(adapter);
        provider = PlatformProvider.getInstance("raw-signature-test", false, adapterFactory);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "NONEwithRSA",
            "NONEwithRSA/PSS",
            "NONEwithECDSA",
            "SHA256withRSA",
            "SHA256withRSA/PSS",
            "SHA256withECDSA"})
    void sign_forwardsInputAndAlgorithmAttributes_throughLegacyAdapter(String algorithm) throws Exception {
        // given
        byte[] prehashed = {1, 2, 3, 4};
        byte[] signed = {5, 6};
        Signature signature = Signature.getInstance(algorithm, provider);
        signature.initSign(new PlatformPrivateKey(privateKey(algorithm)));
        signature.update(prehashed);
        when(client.signData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.signResponse(signed, null));

        // when
        byte[] result = signature.sign();

        // then
        assertArrayEquals(signed, result);
        ArgumentCaptor<com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto> request = ArgumentCaptor
                .forClass(com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto.class);
        verify(client).signData(any(), any(), any(), request.capture());
        assertArrayEquals(prehashed, request.getValue().getData().getFirst().getData());
        assertSignatureAttributes(algorithm, request.getValue().getSignatureAttributes());
        DataAttribute digestDefinition = adapter
                .listSignAttributes(privateKey(algorithm))
                .stream()
                .filter(definition -> RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST.equals(definition.getName()))
                .map(definition -> (DataAttribute) definition)
                .findFirst()
                .orElseThrow();
        assertTrue(digestDefinition.getProperties().isRequired());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "NONEwithRSA",
            "NONEwithRSA/PSS",
            "NONEwithECDSA",
            "SHA256withRSA",
            "SHA256withRSA/PSS",
            "SHA256withECDSA"})
    void verify_forwardsInputAndAlgorithmAttributes_throughLegacyAdapter(String algorithm) throws Exception {
        // given
        byte[] prehashed = {1, 2, 3, 4};
        byte[] signed = {5, 6};
        VerifyDataRequestDto submitted = new VerifyDataRequestDto();
        submitted.setSignatureAttributes(adapter.signatureAttributesFor(algorithm));
        submitted.setData(List.of(signatureData(prehashed)));
        submitted.setSignatures(List.of(signatureData(signed)));
        when(client.verifyData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.verifyResponse(true, null));

        // when
        VerifyDataResponseDto result = adapter.verifyData(publicKey(algorithm), submitted);

        // then
        assertTrue(result.getVerifications().getFirst().isResult());
        ArgumentCaptor<com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto> request = ArgumentCaptor
                .forClass(com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto.class);
        verify(client).verifyData(any(), any(), any(), request.capture());
        assertArrayEquals(prehashed, request.getValue().getData().getFirst().getData());
        assertArrayEquals(signed, request.getValue().getSignatures().getFirst().getData());
        assertSignatureAttributes(algorithm, request.getValue().getSignatureAttributes());
    }

    @Test
    void sign_rawRsaRequestWithoutScheme_isRejected() {
        // given
        CryptographicKeyItemOperationModel key = CryptographicKeyItemModelFixtures
                .activeSigningPrivateKey(KeyAlgorithm.RSA);
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        String expectedError = "Required attribute RSA Signature Scheme not found.";

        // when
        Executable sign = () -> adapter.signData(key, request);

        // then
        ValidationException failure = assertThrows(ValidationException.class, sign);
        assertTrue(failure.getMessage().contains(expectedError));
        verifyNoInteractions(client);
    }

    @Test
    void verify_rawRsaRequestWithoutScheme_isRejected() {
        // given
        CryptographicKeyItemOperationModel key = CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA);
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        String expectedError = "Required attribute RSA Signature Scheme not found.";

        // when
        Executable verifySignature = () -> adapter.verifyData(key, request);

        // then
        ValidationException failure = assertThrows(ValidationException.class, verifySignature);
        assertTrue(failure.getMessage().contains(expectedError));
        verifyNoInteractions(client);
    }

    @ParameterizedTest
    @ValueSource(strings = {"NONEwithRSA", "NONEwithRSA/PSS", "NONEwithECDSA"})
    void resolveSignatureAlgorithm_stillRequiresDigest(String algorithm) {
        // given
        List<RequestAttribute> attributes = adapter.signatureAttributesFor(algorithm);
        String expectedError = "Required attribute Digest Algorithm not found.";

        // when
        Executable resolve = () -> adapter
                .resolveSignatureAlgorithm(privateKey(algorithm), publicKey(algorithm), attributes);

        // then
        ValidationException failure = assertThrows(ValidationException.class, resolve);
        assertTrue(failure.getMessage().contains(expectedError));
        verifyNoInteractions(client);
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA256withRSA", "SHA256withRSA/PSS", "SHA256withECDSA"})
    void sign_rejectsWrongDigestContentType(String algorithm) {
        // given
        Map<String, Object> invalidDigestContent = Map.of("digest", "SHA-256");
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(invalidDigestAttributes(algorithm, invalidDigestContent));

        // when
        Executable sign = () -> adapter.signData(privateKey(algorithm), request);

        // then
        assertThrows(ValidationException.class, sign);
        verifyNoInteractions(client);
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA256withRSA", "SHA256withRSA/PSS", "SHA256withECDSA"})
    void verify_rejectsWrongDigestContentType(String algorithm) {
        // given
        Map<String, Object> invalidDigestContent = Map.of("digest", "SHA-256");
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(invalidDigestAttributes(algorithm, invalidDigestContent));

        // when
        Executable verifySignature = () -> adapter.verifyData(publicKey(algorithm), request);

        // then
        assertThrows(ValidationException.class, verifySignature);
        verifyNoInteractions(client);
    }

    @ParameterizedTest
    @ValueSource(strings = {"NONEwithRSA", "NONEwithRSA/PSS", "NONEwithECDSA"})
    void sign_preservesConnectorOwnedAttributeAlongsideRawSelection(String algorithm) throws Exception {
        // given
        String unknownAttribute = "unexpected";
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(withUnknownAttribute(algorithm, unknownAttribute));
        request.setData(List.of(signatureData(new byte[]{1})));
        when(client.signData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.signResponse(new byte[]{2}, null));

        // when
        adapter.signData(privateKey(algorithm), request);

        // then
        ArgumentCaptor<com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto> captured = ArgumentCaptor
                .forClass(com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto.class);
        verify(client).signData(any(), any(), any(), captured.capture());
        assertEquals(unknownAttribute, captured.getValue().getSignatureAttributes().getLast().getName());
    }

    @ParameterizedTest
    @ValueSource(strings = {"NONEwithRSA", "NONEwithRSA/PSS", "NONEwithECDSA"})
    void verify_preservesConnectorOwnedAttributeAlongsideRawSelection(String algorithm) throws Exception {
        // given
        String unknownAttribute = "unexpected";
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(withUnknownAttribute(algorithm, unknownAttribute));
        request.setData(List.of(signatureData(new byte[]{1})));
        request.setSignatures(List.of(signatureData(new byte[]{2})));
        when(client.verifyData(any(), any(), any(), any()))
                .thenReturn(LegacyOperationFixtures.verifyResponse(true, null));

        // when
        adapter.verifyData(publicKey(algorithm), request);

        // then
        ArgumentCaptor<com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto> captured = ArgumentCaptor
                .forClass(com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto.class);
        verify(client).verifyData(any(), any(), any(), captured.capture());
        assertEquals(unknownAttribute, captured.getValue().getSignatureAttributes().getLast().getName());
    }

    private List<RequestAttribute> withUnknownAttribute(String algorithm, String unknownAttribute) {
        List<RequestAttribute> attributes = new ArrayList<>(adapter.signatureAttributesFor(algorithm));
        attributes
                .add(new RequestAttributeV2(UUID.randomUUID(), unknownAttribute, AttributeContentType.STRING,
                        List.of(new StringAttributeContentV2("value"))));
        return attributes;
    }

    private List<RequestAttribute> invalidDigestAttributes(String algorithm, Map<String, Object> invalidDigestContent) {
        List<RequestAttribute> attributes = adapter.signatureAttributesFor(algorithm);
        RequestAttributeV2 digest = (RequestAttributeV2) attributes.getLast();
        digest.setContent(List.of(new ObjectAttributeContentV2(new HashMap<>(invalidDigestContent))));
        return attributes;
    }

    private static SignatureRequestData signatureData(byte[] bytes) {
        SignatureRequestData data = new SignatureRequestData();
        data.setData(Base64.getEncoder().encodeToString(bytes));
        return data;
    }

    private static KeyAlgorithm keyAlgorithm(String algorithm) {
        return algorithm.endsWith("ECDSA") ? KeyAlgorithm.ECDSA : KeyAlgorithm.RSA;
    }

    private static CryptographicKeyItemOperationModel privateKey(String algorithm) {
        return CryptographicKeyItemModelFixtures.activeSigningPrivateKey(keyAlgorithm(algorithm));
    }

    private static CryptographicKeyItemOperationModel publicKey(String algorithm) {
        return CryptographicKeyItemModelFixtures.publicKey(keyAlgorithm(algorithm));
    }

    private static void assertSignatureAttributes(String algorithm, List<RequestAttribute> attributes) {
        boolean hasDigest = !algorithm.startsWith("NONEwith");
        if (algorithm.endsWith("ECDSA")) {
            assertEquals(hasDigest ? List.of(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST) : List.of(),
                    attributes.stream().map(RequestAttribute::getName).toList());
        } else {
            List<String> expectedNames = hasDigest
                    ? List
                            .of(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                                    RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST)
                    : List.of(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME);
            assertEquals(expectedNames, attributes.stream().map(RequestAttribute::getName).toList());
            RsaSignatureScheme expectedScheme = algorithm.endsWith("RSA/PSS")
                    ? RsaSignatureScheme.PSS
                    : RsaSignatureScheme.PKCS1_v1_5;
            RequestAttributeV2 schemeAttribute = assertInstanceOf(RequestAttributeV2.class, attributes.getFirst());
            assertEquals(expectedScheme.getCode(), schemeAttribute.getContent().getFirst().getData());
        }
        if (hasDigest) {
            RequestAttributeV2 digest = assertInstanceOf(RequestAttributeV2.class, attributes.getLast());
            assertEquals("SHA-256", digest.getContent().getFirst().getData());
        }
    }
}

package com.otilm.core.provider;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.cryptography.operations.*;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PlatformProviderTest {
    private final KeyProviderAdapterFactory factory = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final PlatformProvider provider = PlatformProvider.getInstance("test", false, factory);
    private final CryptographicKeyItemOperationModel privateItem = CryptographicKeyItemModelFixtures
            .activeSigningPrivateKey(KeyAlgorithm.RSA);

    @BeforeEach
    void setUp() throws Exception {
        when(factory.forKeyItem(any())).thenReturn(adapter);
        when(adapter.signatureAttributesFor(anyString())).thenReturn(List.of());
        when(adapter.cipherAttributesFor(anyString())).thenReturn(List.of());
    }

    @Test
    void signature_routesEachSuppliedKey_andPreservesTheInputBytes() throws Exception {
        // given
        byte[] data = {1, 2, 3};
        byte[] signed = {4, 5};
        var otherItem = v2Item();
        when(adapter.signData(any(), any())).thenReturn(signingResult(signed));
        Signature signature = Signature.getInstance("SHA256withRSA", provider);

        // when
        signature.initSign(new PlatformPrivateKey(privateItem));
        signature.update(data);
        byte[] first = signature.sign();
        signature.initSign(new PlatformPrivateKey(otherItem));
        signature.update(data);
        byte[] second = signature.sign();

        // then
        assertArrayEquals(signed, first);
        assertArrayEquals(signed, second);
        verify(factory).forKeyItem(privateItem);
        verify(factory).forKeyItem(otherItem);
        ArgumentCaptor<SignDataRequestDto> request = ArgumentCaptor.forClass(SignDataRequestDto.class);
        verify(adapter).signData(eq(otherItem), request.capture());
        assertArrayEquals(data, Base64.getDecoder().decode(request.getValue().getData().getFirst().getData()));
        verify(adapter, times(2)).signatureAttributesFor("SHA256withRSA");
    }

    @Test
    void decryption_supportsCmsRsaKeyTransport() throws Exception {
        // given
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        byte[] plaintext = {1, 2, 3, 4};
        var bc = new BouncyCastleProvider();
        var envelopeGenerator = new CMSEnvelopedDataGenerator();
        envelopeGenerator
                .addRecipientInfoGenerator(
                        new JceKeyTransRecipientInfoGenerator(new byte[]{1}, pair.getPublic()).setProvider(bc));
        var envelope = envelopeGenerator
                .generate(new CMSProcessableByteArray(plaintext),
                        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(bc).build());
        when(adapter.decryptData(any(), any())).thenAnswer(invocation -> {
            CipherDataRequestDto request = invocation.getArgument(1);
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", bc);
            rsa.init(Cipher.DECRYPT_MODE, pair.getPrivate());
            return decryptionResult(
                    rsa.doFinal(Base64.getDecoder().decode(request.getCipherData().getFirst().getData())));
        });
        var recipient = new JceKeyTransEnvelopedRecipient(new PlatformPrivateKey(privateItem))
                .setProvider(provider)
                .setContentProvider(bc)
                .setMustProduceEncodableUnwrappedKey(true);

        // when
        byte[] recovered = envelope.getRecipientInfos().getRecipients().iterator().next().getContent(recipient);

        // then
        assertArrayEquals(plaintext, recovered);
        verify(adapter).decryptData(eq(privateItem), any());
    }

    @Test
    void signing_reportsMissingScopeSeparatelyFromConnectorFailure() throws Exception {
        // given
        when(adapter.signData(any(), any())).thenThrow(new NotFoundException("internal detail"));
        Signature signature = Signature.getInstance("SHA256withRSA", provider);
        signature.initSign(new PlatformPrivateKey(privateItem));

        // when
        Executable sign = signature::sign;

        // then
        SignatureException failure = assertThrows(SignatureException.class, sign);
        assertTrue(failure.getMessage().contains("not found"));
        assertFalse(failure.getMessage().contains("internal detail"));
    }

    @ParameterizedTest
    @MethodSource("providerFailures")
    void decryption_reportsProviderFailure_withoutExposingInternalDetails(Exception cause) throws Exception {
        // given
        when(adapter.decryptData(any(), any())).thenThrow(cause);
        Cipher cipher = Cipher.getInstance("RSA", provider);
        cipher.init(Cipher.DECRYPT_MODE, new PlatformPrivateKey(privateItem));

        // when
        Executable decrypt = () -> cipher.doFinal(new byte[]{1});

        // then
        ProviderException failure = assertThrows(ProviderException.class, decrypt);
        assertSame(cause, failure.getCause());
        assertFalse(failure.getMessage().contains(cause.getMessage()));
    }

    private static Stream<Named<Exception>> providerFailures() {
        String internalDetail = "sensitive upstream detail";
        return Stream
                .of(Named.of("connector failure", new ConnectorException(internalDetail)),
                        Named.of("missing key or profile", new NotFoundException(internalDetail)),
                        Named.of("unsupported algorithm", new NotSupportedException(internalDetail)),
                        Named.of("invalid operation", new ValidationException(internalDetail)));
    }

    private CryptographicKeyItemOperationModel v2Item() {
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, privateItem.keyAlgorithm(),
                privateItem.keyState(), privateItem.keyType(), privateItem.keyUsage(), null,
                new RemoteKeyReference.MetadataReference(List.of()), privateItem.connectorUuid(), null,
                UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, "v2");
    }

    private static SignDataResponseDto signingResult(byte[] bytes) {
        SignatureResponseData data = new SignatureResponseData();
        data.setData(Base64.getEncoder().encodeToString(bytes));
        SignDataResponseDto result = new SignDataResponseDto();
        result.setSignatures(List.of(data));
        return result;
    }

    private static DecryptDataResponseDto decryptionResult(byte[] bytes) {
        CipherResponseData data = new CipherResponseData();
        data.setData(Base64.getEncoder().encodeToString(bytes));
        DecryptDataResponseDto result = new DecryptDataResponseDto();
        result.setDecryptedData(List.of(data));
        return result;
    }
}

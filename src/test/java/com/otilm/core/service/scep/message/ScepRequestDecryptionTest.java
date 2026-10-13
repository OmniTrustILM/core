package com.otilm.core.service.scep.message;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ScepException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.CipherResponseData;
import com.otilm.api.model.client.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.provider.PlatformProvider;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.scep.ScepMessageTestData;
import com.otilm.core.util.CertificateTestUtil;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Exercises RSA SCEP envelope decryption through the platform provider with only the connector boundary mocked.
 */
class ScepRequestDecryptionTest {

    private final KeyProviderAdapterFactory factory = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final CryptographicKeyItemOperationModel keyItem = CryptographicKeyItemModelFixtures
            .keyItem(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, KeyState.ACTIVE, List.of(KeyUsage.DECRYPT));
    private final PlatformPrivateKey privateKey = new PlatformPrivateKey(keyItem);
    private final PlatformProvider provider = PlatformProvider.getInstance("scep-decryption-test", false, factory);
    private KeyPair caKeyPair;
    private ScepRequest request;

    @BeforeEach
    void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        caKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate caCertificate = CertificateTestUtil.generateRandomX509Certificate(caKeyPair);
        byte[] message = ScepMessageTestData
                .keyTransportEnvelopedPkcsReq(caCertificate, ScepMessageTestData.SUBJECT_DN, List.of(), null);
        request = new ScepRequest(message);
        when(factory.forKeyItem(keyItem)).thenReturn(adapter);
        when(adapter.cipherAttributesFor(any())).thenReturn(List.of());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providerFailures")
    void decryptData_reportsSafeScepFailure_andPreservesProviderCause(Exception cause) throws Exception {
        // given
        String safeMessage = "Failed to decrypt encapsulated content";
        when(adapter.decryptData(eq(keyItem), any())).thenThrow(cause);

        // when
        Executable decrypt = () -> request.decryptData(privateKey, provider, KeyAlgorithm.RSA, null);

        // then
        ScepException failure = assertThrows(ScepException.class, decrypt);
        assertEquals(FailInfo.BAD_REQUEST, failure.getFailInfo());
        assertEquals(safeMessage, failure.getMessage());
        ProviderException providerFailure = assertInstanceOf(ProviderException.class, failure.getCause());
        assertSame(cause, providerFailure.getCause());
        assertFalse(failure.getMessage().contains(cause.getMessage()));
        verify(adapter).decryptData(eq(keyItem), any());
    }

    @Test
    void decryptData_propagatesUnexpectedRuntimeFailure() throws Exception {
        // given
        NullPointerException unexpectedFailure = new NullPointerException("unexpected connector boundary bug");
        when(adapter.decryptData(eq(keyItem), any())).thenThrow(unexpectedFailure);

        // when
        Executable decrypt = () -> request.decryptData(privateKey, provider, KeyAlgorithm.RSA, null);

        // then
        assertSame(unexpectedFailure, assertThrows(NullPointerException.class, decrypt));
        verify(adapter).decryptData(eq(keyItem), any());
    }

    @Test
    void decryptData_opensRsaEnvelope_whenConnectorReturnsDecryptedKey() throws Exception {
        // given
        when(adapter.decryptData(eq(keyItem), any())).thenAnswer(invocation -> {
            CipherDataRequestDto cipherRequest = invocation.getArgument(1);
            byte[] encryptedKey = Base64.getDecoder().decode(cipherRequest.getCipherData().getFirst().getData());
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, caKeyPair.getPrivate());
            CipherResponseData data = new CipherResponseData();
            data.setData(Base64.getEncoder().encodeToString(cipher.doFinal(encryptedKey)));
            DecryptDataResponseDto response = new DecryptDataResponseDto();
            response.setDecryptedData(List.of(data));
            return response;
        });

        // when
        request.decryptData(privateKey, provider, KeyAlgorithm.RSA, null);

        // then
        assertEquals(ScepMessageTestData.SUBJECT_DN, request.getPkcs10Request().getSubject().toString());
        verify(adapter).decryptData(eq(keyItem), any());
    }

    private static Stream<Named<Exception>> providerFailures() {
        String internalDetail = "sensitive upstream detail";
        return Stream
                .of(Named.of("connector failure", new ConnectorException(internalDetail)),
                        Named.of("missing scope", new NotFoundException(internalDetail)),
                        Named.of("unsupported cipher", new NotSupportedException(internalDetail)),
                        Named.of("invalid request", new ValidationException(internalDetail)),
                        Named.of("invalid result", new IllegalArgumentException(internalDetail)));
    }
}

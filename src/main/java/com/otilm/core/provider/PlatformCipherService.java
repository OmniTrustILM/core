package com.otilm.core.provider;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.CipherRequestData;
import com.otilm.api.model.client.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.handler.key.KeyOperationValidator;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import java.security.ProviderException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import lombok.Getter;

public class PlatformCipherService {
    private final KeyProviderAdapterFactory adapterFactory;
    @Getter
    private final String algorithm;

    public PlatformCipherService(KeyProviderAdapterFactory adapterFactory, String algorithm) {
        this.adapterFactory = Objects.requireNonNull(adapterFactory, "adapterFactory must not be null");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
    }

    public byte[] decrypt(byte[] encryptedData, PlatformPrivateKey privateKey) {
        Objects.requireNonNull(encryptedData, "encryptedData must not be null");
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        try {
            CryptographicKeyItemOperationModel keyItem = privateKey.keyItem();
            KeyOperationValidator.requireAllowed(keyItem, KeyUsage.DECRYPT);
            KeyProviderAdapter adapter = adapterFactory.forKeyItem(keyItem);

            CipherRequestData data = new CipherRequestData();
            data.setData(Base64.getEncoder().encodeToString(encryptedData));

            // The legacy cryptography provider treats "RSA" as PKCS1 v1.5. The v2 of the provider does not have this
            // mapping as it may be ambiguous. So we resolve it here where we know that "RSA" should mean "PKCS1 v1.5"
            String cipherAlgorithm = "RSA".equalsIgnoreCase(algorithm) ? "RSA/ECB/PKCS1Padding" : algorithm;

            CipherDataRequestDto request = new CipherDataRequestDto();
            request.setCipherData(List.of(data));
            request.setCipherAttributes(adapter.cipherAttributesFor(cipherAlgorithm));

            DecryptDataResponseDto response = adapter.decryptData(keyItem, request);
            return Base64.getDecoder().decode(response.getDecryptedData().getFirst().getData());
        } catch (NotFoundException e) {
            throw new ProviderException("The decryption key, token profile or connector was not found.", e);
        } catch (NotSupportedException e) {
            throw new ProviderException("The key provider does not support the requested cipher algorithm.", e);
        } catch (ConnectorException e) {
            throw new ProviderException("The connector failed to decrypt the data.", e);
        } catch (ValidationException | IllegalArgumentException e) {
            throw new ProviderException("The decryption request or connector result is invalid.", e);
        }
    }

}

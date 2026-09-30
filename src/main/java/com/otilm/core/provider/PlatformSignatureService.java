package com.otilm.core.provider;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.provider.key.PlatformPublicKey;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import java.security.SignatureException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import lombok.Getter;

public class PlatformSignatureService {
    private final KeyProviderAdapterFactory adapterFactory;
    @Getter
    private final String algorithm;

    public PlatformSignatureService(KeyProviderAdapterFactory adapterFactory, String algorithm) {
        this.adapterFactory = Objects.requireNonNull(adapterFactory, "adapterFactory must not be null");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
    }

    public byte[] sign(PlatformPrivateKey privateKey, byte[] dataToSign) throws SignatureException {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        Objects.requireNonNull(dataToSign, "dataToSign must not be null");
        try {
            CryptographicKeyItemOperationModel keyItem = privateKey.keyItem();
            KeyProviderAdapter adapter = adapterFactory.forKeyItem(keyItem);

            SignDataRequestDto request = new SignDataRequestDto();
            request.setSignatureAttributes(adapter.signatureAttributesFor(algorithm));
            request.setData(List.of(data(dataToSign)));

            SignDataResponseDto response = adapter.signData(keyItem, request);
            return Base64.getDecoder().decode(response.getSignatures().getFirst().getData());
        } catch (NotFoundException e) {
            throw new SignatureException("The signing key, token profile or connector was not found.", e);
        } catch (NotSupportedException e) {
            throw new SignatureException("The key provider does not support the requested signature algorithm.", e);
        } catch (ConnectorException e) {
            throw new SignatureException("The connector failed to sign the data.", e);
        } catch (ValidationException | IllegalArgumentException e) {
            throw new SignatureException("The signing request or connector result is invalid.", e);
        }
    }

    public boolean verify(PlatformPublicKey publicKey, byte[] signature, byte[] dataToVerify)
            throws SignatureException {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Objects.requireNonNull(signature, "signature must not be null");
        Objects.requireNonNull(dataToVerify, "dataToVerify must not be null");
        try {
            CryptographicKeyItemOperationModel keyItem = publicKey.keyItem();
            KeyProviderAdapter adapter = adapterFactory.forKeyItem(keyItem);

            VerifyDataRequestDto request = new VerifyDataRequestDto();
            request.setSignatureAttributes(adapter.signatureAttributesFor(algorithm));
            request.setSignatures(List.of(data(signature)));
            request.setData(List.of(data(dataToVerify)));

            VerifyDataResponseDto response = adapter.verifyData(keyItem, request);
            return response.getVerifications().getFirst().isResult();
        } catch (NotFoundException e) {
            throw new SignatureException("The verification key, token profile or connector was not found.", e);
        } catch (NotSupportedException e) {
            throw new SignatureException("The key provider does not support the requested signature algorithm.", e);
        } catch (ConnectorException e) {
            throw new SignatureException("The connector failed to verify the signature.", e);
        } catch (ValidationException | IllegalArgumentException e) {
            throw new SignatureException("The verification request or connector result is invalid.", e);
        }
    }

    private static SignatureRequestData data(byte[] bytes) {
        SignatureRequestData data = new SignatureRequestData();
        data.setData(Base64.getEncoder().encodeToString(bytes));
        return data;
    }
}

package com.otilm.core.service.handler;

import com.otilm.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.VerificationResponseData;
import java.util.List;

public final class LegacyOperationFixtures {

    private LegacyOperationFixtures() {
    }

    public static RandomDataResponseDto randomResponse(byte[] data) {
        RandomDataResponseDto response = new RandomDataResponseDto();
        response.setData(data);
        return response;
    }

    public static SignDataResponseDto signResponse(byte[] signature, String identifier) {
        SignatureResponseData data = new SignatureResponseData();
        data.setData(signature);
        data.setIdentifier(identifier);
        SignDataResponseDto response = new SignDataResponseDto();
        response.setSignatures(List.of(data));
        return response;
    }

    public static EncryptDataResponseDto encryptResponse(byte[] data, String identifier) {
        EncryptDataResponseDto response = new EncryptDataResponseDto();
        response.setEncryptedData(List.of(cipherResponseItem(data, identifier, null)));
        return response;
    }

    public static DecryptDataResponseDto decryptResponse(byte[] data, String identifier) {
        DecryptDataResponseDto response = new DecryptDataResponseDto();
        response.setDecryptedData(List.of(cipherResponseItem(data, identifier, null)));
        return response;
    }

    public static EncryptDataResponseDto encryptResponseWithoutData() {
        return new EncryptDataResponseDto();
    }

    public static SignDataResponseDto signResponseWithoutSignatures() {
        return new SignDataResponseDto();
    }

    public static VerifyDataResponseDto verifyResponseWithoutVerifications() {
        return new VerifyDataResponseDto();
    }

    public static VerifyDataResponseDto verifyResponse(boolean result, String identifier) {
        VerificationResponseData data = new VerificationResponseData();
        data.setResult(result);
        data.setIdentifier(identifier);
        VerifyDataResponseDto response = new VerifyDataResponseDto();
        response.setVerifications(List.of(data));
        return response;
    }

    public static CipherResponseData cipherResponseItem(byte[] data, String identifier, Object details) {
        CipherResponseData item = new CipherResponseData();
        item.setData(data);
        item.setIdentifier(identifier);
        item.setDetails(details);
        return item;
    }
}

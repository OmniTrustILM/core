package com.otilm.core.service.handler;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.otilm.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.VerificationResponseData;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/** Builds connector-side v1 operation requests; the only file that names those DTOs. */
public final class LegacyOperationCodec {

    private LegacyOperationCodec() {
    }

    public static RandomDataRequestDto randomRequest(int length, List<RequestAttribute> attributes) {
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(length);
        request.setAttributes(attributes);
        return request;
    }

    public static CipherDataRequestDto cipherRequest(List<OperationDataItem> items, List<RequestAttribute> attributes) {
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherData(items.stream().map(item -> {
            CipherRequestData data = new CipherRequestData();
            data.setData(decode(item.data()));
            data.setIdentifier(item.identifier());
            return data;
        }).toList());
        request.setCipherAttributes(attributes);
        return request;
    }

    public static SignDataRequestDto signRequest(List<OperationDataItem> items, List<RequestAttribute> attributes) {
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(attributes);
        request.setData(signatureItems(items));
        return request;
    }

    /** {@code data} may be null: a v1 verify request needs only the signatures when the connector holds the data. */
    public static VerifyDataRequestDto verifyRequest(List<OperationDataItem> data, List<OperationDataItem> signatures,
            List<RequestAttribute> attributes) {
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(attributes);
        if (data != null) {
            request.setData(signatureItems(data));
        }
        request.setSignatures(signatureItems(signatures));
        return request;
    }

    public static List<OperationResultItem> cipherResults(List<CipherResponseData> items) {
        return items
                .stream()
                .map(item -> new OperationResultItem(encode(item.getData()), null, item.getIdentifier(),
                        item.getDetails()))
                .toList();
    }

    public static List<OperationResultItem> signatureResults(List<SignatureResponseData> items) {
        return items
                .stream()
                .map(item -> new OperationResultItem(encode(item.getData()), null, item.getIdentifier(),
                        item.getDetails()))
                .toList();
    }

    public static List<OperationResultItem> verificationResults(List<VerificationResponseData> items) {
        return items
                .stream()
                .map(item -> new OperationResultItem(null, item.isResult(), item.getIdentifier(), item.getDetails()))
                .toList();
    }

    private static List<SignatureRequestData> signatureItems(List<OperationDataItem> items) {
        return items.stream().map(item -> {
            SignatureRequestData data = new SignatureRequestData();
            data.setData(decode(item.data()));
            data.setIdentifier(item.identifier());
            return data;
        }).toList();
    }

    private static byte[] decode(String base64) {
        return base64 == null ? null : Base64.getDecoder().decode(base64.getBytes(StandardCharsets.UTF_8));
    }

    private static String encode(byte[] bytes) {
        return bytes == null ? null : Base64.getEncoder().encodeToString(bytes);
    }
}

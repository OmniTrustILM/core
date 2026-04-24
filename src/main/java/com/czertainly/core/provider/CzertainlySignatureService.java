package com.czertainly.core.provider;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.czertainly.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.czertainly.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.czertainly.core.attribute.EcdsaSignatureAttributes;
import com.czertainly.core.attribute.RsaSignatureAttributes;
import com.czertainly.core.provider.key.CzertainlyPrivateKey;
import com.czertainly.core.provider.key.CzertainlyPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SignatureException;
import java.util.List;

public class CzertainlySignatureService {

    private static final Logger log = LoggerFactory.getLogger(CzertainlySignatureService.class);

    private final CryptographicOperationsSyncApiClient apiClient;
    private final List<RequestAttribute> signatureAttributes;
    private final String algorithm;

    public CzertainlySignatureService(CryptographicOperationsSyncApiClient apiClient, String algorithm) {
        this.apiClient = apiClient;
        this.signatureAttributes = mapSignatureAttributesFromSignatureAlgorithm(algorithm);
        this.algorithm = algorithm;
    }

    public List<RequestAttribute> mapSignatureAttributesFromSignatureAlgorithm(String algorithm) {
        switch (algorithm) {
            case "NONEwithRSA" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5)
                );
            }
            case "MD5withRSA" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.MD5)
                );
            }
            case "SHA1withRSA" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_1)
                );
            }
            case "SHA224withRSA" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_224)
                );
            }
            case "SHA256withRSA" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)
                );
            }
            case "SHA384withRSA" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384)
                );
            }
            case "SHA512withRSA" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_512)
                );
            }
            case "NONEwithRSA/PSS" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS)
                );
            }
            case "SHA1withRSA/PSS" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_1)
                );
            }
            case "SHA224withRSA/PSS" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_224)
                );
            }
            case "SHA256withRSA/PSS" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)
                );
            }
            case "SHA384withRSA/PSS" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384)
                );
            }
            case "SHA512withRSA/PSS" -> {
                return List.of(
                        RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_512)
                );
            }
            case "NONEwithECDSA" -> {
                return List.of();
            }
            case "SHA1withECDSA" -> {
                return List.of(
                        EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_1)
                );
            }
            case "SHA224withECDSA" -> {
                return List.of(
                        EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_224)
                );
            }
            case "SHA256withECDSA" -> {
                return List.of(
                        EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)
                );
            }
            case "SHA384withECDSA" -> {
                return List.of(
                        EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384)
                );
            }
            case "SHA512withECDSA" -> {
                return List.of(
                        EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_512)
                );
            }
            default -> throw new IllegalArgumentException("No signatures attributes mapped for algorithm: " + algorithm);
        }
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] sign(CzertainlyPrivateKey privateKey, byte[] dataToSign) throws SignatureException {
        SignDataRequestDto requestDto = new SignDataRequestDto();
        requestDto.setSignatureAttributes(signatureAttributes);
        SignatureRequestData signatureRequestData = new SignatureRequestData();
        signatureRequestData.setData(dataToSign);
        requestDto.setData(List.of(signatureRequestData));

        log.debug("Signing data on connector: {} with token instance: {} and key: {}",
                privateKey.getConnectorDto().getName(),
                privateKey.getTokenInstanceUuid(),
                privateKey.getKeyUuid());

        try {
            SignDataResponseDto response = apiClient.signData(
                    privateKey.getConnectorDto(),
                    privateKey.getTokenInstanceUuid(),
                    privateKey.getKeyUuid(),
                    requestDto
            );

            return response.getSignatures().get(0).getData();

        } catch (ConnectorException e) {
            throw new SignatureException("Failed to sign on connector", e);
        }
    }

    public boolean verify(CzertainlyPublicKey publicKey, byte[] signature, byte[] dataToVerify) throws SignatureException {
        try {
            VerifyDataRequestDto requestDto = new VerifyDataRequestDto();
            requestDto.setSignatureAttributes(signatureAttributes);

            SignatureRequestData signatureRequest = new SignatureRequestData();
            signatureRequest.setData(signature);
            requestDto.setSignatures(List.of(signatureRequest));

            SignatureRequestData signatureRequestData = new SignatureRequestData();
            signatureRequestData.setData(publicKey.getData());
            signatureRequestData.setData(signature);
            requestDto.setSignatures(List.of(signatureRequestData));

            VerifyDataResponseDto response = apiClient.verifyData(
                    publicKey.getConnectorDto(),
                    publicKey.getTokenInstanceUuid(),
                    publicKey.getKeyUuid(),
                    requestDto
            );

            return response.getVerifications().get(0).isResult();

        } catch (ConnectorException e) {
            throw new SignatureException("Failed to verify signature on connector", e);
        }
    }

}

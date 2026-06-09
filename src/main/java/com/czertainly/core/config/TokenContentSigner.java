package com.czertainly.core.config;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.czertainly.core.util.CryptographyUtil;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.UUID;

/**
 * Cryptographic Provider Signer. This class extends the content signer from bouncy castle
 * and communicates with the cryptography provider for the signing operation
 */
public class TokenContentSigner implements ContentSigner {

    private static final Logger logger = LoggerFactory.getLogger(TokenContentSigner.class);

    private final CryptographicOperationsSyncApiClient apiClient;
    private final ApiClientConnectorInfo connector;
    private final UUID privateKeyUuid;
    private final UUID publicKeyUuid;
    //Used to determine the signature algorithm for the PQC Items
    private final String publicKey;
    private final KeyAlgorithm keyAlgorithm;
    private final UUID tokenInstanceUuid;
    private final List<RequestAttribute> signatureAttributes;


    private final ByteArrayOutputStream outputStream;

    public TokenContentSigner(CryptographicOperationsSyncApiClient apiClient,
                              ApiClientConnectorInfo connector,
                              UUID tokenInstanceUuid,
                              UUID privateKeyUuid,
                              UUID publicKeyUuid,
                              String publicKey,
                              KeyAlgorithm keyAlgorithm,
                              List<RequestAttribute> signatureAttributes) {
        this.connector = connector;
        this.privateKeyUuid = privateKeyUuid;
        this.publicKeyUuid = publicKeyUuid;
        this.tokenInstanceUuid = tokenInstanceUuid;
        this.signatureAttributes = signatureAttributes;
        this.apiClient = apiClient;
        this.keyAlgorithm = keyAlgorithm;
        this.publicKey = publicKey;
        this.outputStream = new ByteArrayOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return CryptographyUtil.prepareSignatureAlgorithm(
                keyAlgorithm,
                publicKey,
                signatureAttributes
        );
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        byte[] dataToSign = outputStream.toByteArray();
        logger.debug("Obtained the data to sign using the provider: {}", connector);
        SignatureRequestData data = new SignatureRequestData();
        data.setData(dataToSign);

        SignDataRequestDto dto = new SignDataRequestDto();
        dto.setSignatureAttributes(signatureAttributes);
        dto.setData(List.of(data));
        logger.trace("Request for signature is : {}", dto);
        try {

            logger.debug("Signing using Key: {}, Token Profile: {}", privateKeyUuid, tokenInstanceUuid);
            SignDataResponseDto response = apiClient.signData(connector, tokenInstanceUuid.toString(), privateKeyUuid.toString(), dto);
            logger.debug("Data Signed by the connector. Response is: {}", response);
            if (response == null || response.getSignatures() == null || response.getSignatures().isEmpty()) {
                throw new ValidationException(
                        ValidationError.create(
                                "Invalid Signature from the connector"
                        )
                );
            }
            logger.debug("Proceeding to verify the signature using the public key: {}", publicKeyUuid);
            SignatureRequestData verifyRequest = new SignatureRequestData();
            verifyRequest.setData(response.getSignatures().get(0).getData());

            VerifyDataRequestDto verifyDataRequestDto = new VerifyDataRequestDto();
            verifyDataRequestDto.setSignatures(List.of(verifyRequest));
            verifyDataRequestDto.setSignatureAttributes(dto.getSignatureAttributes());
            verifyDataRequestDto.setData(dto.getData());

            VerifyDataResponseDto verifyResponse = apiClient.verifyData(connector, tokenInstanceUuid.toString(), publicKeyUuid.toString(), verifyDataRequestDto);

            if (verifyResponse == null
                    || verifyResponse.getVerifications() == null
                    || verifyResponse.getVerifications().isEmpty()
                    || !verifyResponse.getVerifications().get(0).isResult()
            ) {
                throw new ValidationException(
                        ValidationError.create(
                                "Validation of the signature from connector failed. Cannot proceed with the request"
                        )
                );
            }
            return response.getSignatures().get(0).getData();

        } catch (ConnectorException e) {
            throw new ValidationException(
                    ValidationError.create(
                            "Error when communicating with the connector. Error: " + e.getMessage()
                    )
            );
        }
    }
}

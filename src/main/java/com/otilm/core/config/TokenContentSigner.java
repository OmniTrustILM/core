package com.otilm.core.config;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.OperationKeyContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cryptographic Provider Signer. This class extends the content signer from bouncy castle and signs through the key's
 * provider, whichever version serves it.
 */
public class TokenContentSigner implements ContentSigner {

    private static final Logger logger = LoggerFactory.getLogger(TokenContentSigner.class);

    private final KeyProviderAdapter keyProvider;
    private final OperationKeyContext signingKey;
    private final List<RequestAttribute> signatureAttributes;
    private final AlgorithmIdentifier algorithmIdentifier;
    private final SignatureCheck signatureCheck;

    private final ByteArrayOutputStream outputStream;

    /**
     * @param algorithmIdentifier the algorithm the signature attributes select, resolved before anything is signed
     * @param signatureCheck decides whether the provider's signature is valid before it is used
     */
    public TokenContentSigner(KeyProviderAdapter keyProvider, OperationKeyContext signingKey,
            List<RequestAttribute> signatureAttributes, AlgorithmIdentifier algorithmIdentifier,
            SignatureCheck signatureCheck) {
        this.keyProvider = keyProvider;
        this.signingKey = signingKey;
        this.signatureAttributes = signatureAttributes;
        this.algorithmIdentifier = algorithmIdentifier;
        this.signatureCheck = signatureCheck;
        this.outputStream = new ByteArrayOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        byte[] dataToSign = outputStream.toByteArray();
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(signatureAttributes);
        request.setData(List.of(data(dataToSign)));
        try {
            logger.debug("Signing using key item: {}", signingKey.keyItem().keyItemUuid());
            SignDataResponseDto response = keyProvider.signData(signingKey, request);
            if (response == null || response.getSignatures() == null || response.getSignatures().isEmpty()
                    || response.getSignatures().getFirst().getData() == null) {
                throw new ValidationException(ValidationError.create("Invalid Signature from the connector"));
            }
            byte[] signature = Base64.getDecoder().decode(response.getSignatures().getFirst().getData());
            if (!signatureCheck.verify(dataToSign, signature)) {
                throw new ValidationException(ValidationError
                        .create("Validation of the signature from connector failed. Cannot proceed with the request"));
            }
            return signature;
        } catch (ConnectorException e) {
            logger.warn("Signing with key item {} through the connector failed", signingKey.keyItem().keyItemUuid(), e);
            throw new ValidationException(ValidationError.create("Error when communicating with the connector."));
        }
    }

    /** Whether a signature the provider returned is a valid signature over the data it was given. */
    @FunctionalInterface
    public interface SignatureCheck {
        boolean verify(byte[] data, byte[] signature) throws ConnectorException;
    }

    /** Asks the provider itself to verify the signature with the key pair's public key item. */
    public static SignatureCheck verifiedByProvider(KeyProviderAdapter keyProvider, OperationKeyContext verificationKey,
            List<RequestAttribute> signatureAttributes) {
        return (data, signature) -> {
            VerifyDataRequestDto request = new VerifyDataRequestDto();
            request.setSignatureAttributes(signatureAttributes);
            request.setData(List.of(data(data)));
            request.setSignatures(List.of(data(signature)));
            VerifyDataResponseDto response = keyProvider.verifyData(verificationKey, request);
            return response != null && response.getVerifications() != null && !response.getVerifications().isEmpty()
                    && response.getVerifications().getFirst().isResult();
        };
    }

    /**
     * Verifies the signature locally against the public key, under the algorithm the signature is labelled with, so it
     * also catches a signature made under another algorithm than the selected one.
     */
    public static SignatureCheck verifiedAgainst(SubjectPublicKeyInfo publicKey, AlgorithmIdentifier algorithm) {
        return (data, signature) -> {
            try {
                ContentVerifier verifier = new JcaContentVerifierProviderBuilder().build(publicKey).get(algorithm);
                try (OutputStream out = verifier.getOutputStream()) {
                    out.write(data);
                }
                return verifier.verify(signature);
            } catch (RuntimeOperatorException e) {
                logger.debug("The signature from the connector is malformed", e);
                return false;
            } catch (OperatorCreationException | IOException e) {
                logger.warn("The signature from the connector could not be verified", e);
                throw new ValidationException(
                        ValidationError.create("Cannot verify the signature from the connector."));
            }
        };
    }

    private static SignatureRequestData data(byte[] bytes) {
        SignatureRequestData data = new SignatureRequestData();
        data.setData(Base64.getEncoder().encodeToString(bytes));
        return data;
    }
}

package com.otilm.core.signing.engine.signer;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.SignatureResponseData;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * {@link Signer} implementation that delegates signing to {@link CryptographicOperationInternalService}. Created
 * per-request by {@link StaticManagedKeySignerCreator} with pre-resolved key routing information.
 */
public class CryptographicOperationServiceSigner implements Signer {

    private final CryptographicOperationInternalService cryptographicOperationService;
    private final SecuredParentUUID tokenInstanceUuid;
    private final SecuredUUID tokenProfileUuid;
    private final UUID keyUuid;
    private final UUID privateKeyItemUuid;
    private final List<RequestAttribute> signatureAttributes;
    private final SignatureAlgorithm signatureAlgorithm;
    private final PublicKey signingKey;

    public CryptographicOperationServiceSigner(CryptographicOperationInternalService cryptographicOperationService,
            SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID keyUuid, UUID privateKeyItemUuid,
            List<RequestAttribute> signatureAttributes, SignatureAlgorithm signatureAlgorithm, PublicKey signingKey) {
        this.cryptographicOperationService = cryptographicOperationService;
        this.tokenInstanceUuid = tokenInstanceUuid;
        this.tokenProfileUuid = tokenProfileUuid;
        this.keyUuid = keyUuid;
        this.privateKeyItemUuid = privateKeyItemUuid;
        this.signatureAttributes = signatureAttributes;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signingKey = signingKey;
    }

    @Override
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    @Override
    public List<byte[]> signAll(List<byte[]> items, SignatureInputMode inputMode) throws SigningEngineException {
        boolean prehashed = switch (inputMode == null ? SignatureInputMode.DATA : inputMode) {
            case DATA -> false;
            case PREHASHED_DIGEST -> true;
        };
        List<SignatureRequestData> requestItems = buildRequestItems(items);
        if (prehashed) {
            checkDigests(items);
        }

        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(signatureAttributes);
        request.setData(requestItems);

        try {
            SignDataResponseDto response = prehashed
                    ? cryptographicOperationService
                            .signDataWithoutEventHistory(tokenInstanceUuid, tokenProfileUuid, keyUuid,
                                    privateKeyItemUuid, request, inputMode)
                    : cryptographicOperationService
                            .signDataWithoutEventHistory(tokenInstanceUuid, tokenProfileUuid, keyUuid,
                                    privateKeyItemUuid, request);

            if (response == null || response.getSignatures() == null || response.getSignatures().isEmpty()) {
                throw signerFault("Signing operation returned no signatures");
            }
            List<byte[]> signatures = matchByIdentifier(response.getSignatures(), requestItems.size());
            if (prehashed) {
                verifyAgainstDigests(items, signatures);
            }
            return signatures;

        } catch (ConnectorException e) {
            throw new SigningEngineException(SigningEngineFailure.SIGNER_FAULT,
                    "Connector error during signing: " + e.getMessage(), e, "Internal signing error");
        } catch (NotFoundException e) {
            throw new SigningEngineException(SigningEngineFailure.SIGNER_FAULT,
                    "Key or token not found during signing: " + e.getMessage(), e, "Internal signing error");
        } catch (ValidationException e) {
            if (!prehashed) {
                throw e;
            }
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED, e.getMessage(), e,
                    "The signing key cannot sign digests.");
        }
    }

    private static List<SignatureRequestData> buildRequestItems(List<byte[]> items) {
        if (items == null || items.isEmpty()) {
            throw new IllegalArgumentException("items must not be null or empty");
        }
        List<SignatureRequestData> requestItems = new ArrayList<>(items.size());
        for (int i = 0; i < items.size(); i++) {
            byte[] item = items.get(i);
            if (item == null || item.length == 0) {
                throw new IllegalArgumentException("item must not be null or empty");
            }
            SignatureRequestData requestData = new SignatureRequestData();
            requestData.setIdentifier(Integer.toString(i));
            requestData.setData(Base64.getEncoder().encodeToString(item));
            requestItems.add(requestData);
        }
        return requestItems;
    }

    // A wrong input is the caller's to fix, so it is refused here rather than left to the provider as a fault.
    private void checkDigests(List<byte[]> digests) throws SigningEngineException {
        if (!PrehashedSigning.admits(signatureAlgorithm)) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "Signature algorithm %s cannot sign a prehashed digest".formatted(signatureAlgorithm),
                    "The signing profile's signature algorithm cannot sign a digest.");
        }
        int digestSize = PrehashedSigning.digestAlgorithm(signatureAlgorithm).getDigestSizeBytes();
        for (int i = 0; i < digests.size(); i++) {
            if (digests.get(i).length != digestSize) {
                throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                        "Digest %d is %d bytes, expected %d for %s"
                                .formatted(i, digests.get(i).length, digestSize, signatureAlgorithm.getCode()),
                        "Each digest must be %d bytes for %s.".formatted(digestSize, signatureAlgorithm.getCode()));
            }
        }
    }

    // A provider that ignores the mode hashes the digest again and signs the wrong message.
    private void verifyAgainstDigests(List<byte[]> digests, List<byte[]> signatures) throws SigningEngineException {
        for (int i = 0; i < digests.size(); i++) {
            if (!PrehashedSignatureVerifier
                    .verifies(signatureAlgorithm, signingKey, digests.get(i), signatures.get(i))) {
                throw signerFault(
                        "Signature %d does not verify against its digest under %s; the provider may have hashed it again"
                                .formatted(i, signatureAlgorithm.getCode()));
            }
        }
    }

    // Providers may answer out of order, so results are matched by the identifier sent with each item.
    private static List<byte[]> matchByIdentifier(List<SignatureResponseData> results, int expected)
            throws SigningEngineException {
        if (results.size() != expected) {
            throw signerFault(
                    "Signing operation returned " + results.size() + " signatures for " + expected + " items");
        }
        if (expected == 1) {
            // A lone item cannot be mismatched, so its identifier is not checked.
            return List.of(decodeSignature(results.getFirst(), 0));
        }
        byte[][] ordered = new byte[expected][];
        for (SignatureResponseData result : results) {
            int index = indexOf(result.getIdentifier(), expected);
            if (ordered[index] != null) {
                throw signerFault("Signing operation returned a repeated identifier: " + result.getIdentifier());
            }
            ordered[index] = decodeSignature(result, index);
        }
        return Arrays.asList(ordered);
    }

    private static int indexOf(String identifier, int expected) throws SigningEngineException {
        if (identifier == null) {
            throw signerFault("Signing operation returned a result without an identifier");
        }
        try {
            int index = Integer.parseInt(identifier);
            // parseInt also reads "+1", "01" and non-ASCII digits, none of which was sent.
            boolean sent = index >= 0 && index < expected && Integer.toString(index).equals(identifier);
            if (sent) {
                return index;
            }
        } catch (NumberFormatException ignored) {
            // A non-numeric identifier is unknown.
        }
        throw signerFault("Signing operation returned an unknown identifier: " + identifier);
    }

    // A v1 connector reports a failed item as a result without data and gives the reason in its details.
    private static byte[] decodeSignature(SignatureResponseData result, int index) throws SigningEngineException {
        String data = result.getData();
        if (data == null || data.isEmpty()) {
            throw signerFault("Signing operation returned no signature for item " + index + ": " + result.getDetails());
        }
        return Base64.getDecoder().decode(data);
    }

    private static SigningEngineException signerFault(String message) {
        return new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, message, "Internal signing error");
    }
}

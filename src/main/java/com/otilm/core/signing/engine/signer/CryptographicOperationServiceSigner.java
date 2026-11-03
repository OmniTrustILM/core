package com.otilm.core.signing.engine.signer;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.SignatureResponseData;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;

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

    public CryptographicOperationServiceSigner(CryptographicOperationInternalService cryptographicOperationService,
            SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID keyUuid, UUID privateKeyItemUuid,
            List<RequestAttribute> signatureAttributes, SignatureAlgorithm signatureAlgorithm) {
        this.cryptographicOperationService = cryptographicOperationService;
        this.tokenInstanceUuid = tokenInstanceUuid;
        this.tokenProfileUuid = tokenProfileUuid;
        this.keyUuid = keyUuid;
        this.privateKeyItemUuid = privateKeyItemUuid;
        this.signatureAttributes = signatureAttributes;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    @Override
    public List<byte[]> signAll(List<byte[]> dtbsList) throws SigningEngineException {
        if (dtbsList == null || dtbsList.isEmpty()) {
            throw new IllegalArgumentException("dtbsList must not be null or empty");
        }
        List<SignatureRequestData> items = new ArrayList<>(dtbsList.size());
        for (int i = 0; i < dtbsList.size(); i++) {
            byte[] dtbs = dtbsList.get(i);
            if (dtbs == null || dtbs.length == 0) {
                throw new IllegalArgumentException("dtbs must not be null or empty");
            }
            SignatureRequestData requestData = new SignatureRequestData();
            requestData.setIdentifier(Integer.toString(i));
            requestData.setData(Base64.getEncoder().encodeToString(dtbs));
            items.add(requestData);
        }

        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(signatureAttributes);
        request.setData(items);

        try {
            SignDataResponseDto response = cryptographicOperationService
                    .signDataWithoutEventHistory(tokenInstanceUuid, tokenProfileUuid, keyUuid, privateKeyItemUuid,
                            request);

            if (response == null || response.getSignatures() == null || response.getSignatures().isEmpty()) {
                throw signerFault("Signing operation returned no signatures");
            }
            return matchByIdentifier(response.getSignatures(), items.size());

        } catch (ConnectorException e) {
            throw new SigningEngineException(SigningEngineFailure.SIGNER_FAULT,
                    "Connector error during signing: " + e.getMessage(), e, "Internal signing error");
        } catch (NotFoundException e) {
            throw new SigningEngineException(SigningEngineFailure.SIGNER_FAULT,
                    "Key or token not found during signing: " + e.getMessage(), e, "Internal signing error");
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
            return List.of(Base64.getDecoder().decode(results.getFirst().getData()));
        }
        byte[][] ordered = new byte[expected][];
        for (SignatureResponseData result : results) {
            int index = indexOf(result.getIdentifier(), expected);
            if (ordered[index] != null) {
                throw signerFault("Signing operation returned a repeated identifier: " + result.getIdentifier());
            }
            ordered[index] = Base64.getDecoder().decode(result.getData());
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

    private static SigningEngineException signerFault(String message) {
        return new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, message, "Internal signing error");
    }
}

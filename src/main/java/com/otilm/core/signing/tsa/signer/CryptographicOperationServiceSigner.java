package com.otilm.core.signing.tsa.signer;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationInternalService;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * {@link Signer} implementation that delegates signing to {@link CryptographicOperationInternalService}.
 * Created per-request by {@link StaticManagedKeySignerCreator} with pre-resolved key routing information.
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
                                               SecuredParentUUID tokenInstanceUuid,
                                               SecuredUUID tokenProfileUuid,
                                               UUID keyUuid,
                                               UUID privateKeyItemUuid,
                                               List<RequestAttribute> signatureAttributes,
                                               SignatureAlgorithm signatureAlgorithm) {
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
    public byte[] sign(byte[] dtbs) throws TspException {
        if (dtbs == null || dtbs.length == 0) {
            throw new IllegalArgumentException("dtbs must not be null or empty");
        }

        SignatureRequestData requestData = new SignatureRequestData();
        requestData.setData(Base64.getEncoder().encodeToString(dtbs));

        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(signatureAttributes);
        request.setData(List.of(requestData));

        try {
            SignDataResponseDto response = cryptographicOperationService.signDataWithoutEventHistory(
                    tokenInstanceUuid, tokenProfileUuid, keyUuid, privateKeyItemUuid, request);

            if (response == null || response.getSignatures() == null || response.getSignatures().isEmpty()) {
                throw new TspException(TspFailureInfo.SYSTEM_FAILURE,
                        "Signing operation returned no signatures",
                        "Internal signing error");
            }

            return Base64.getDecoder().decode(response.getSignatures().getFirst().getData());

        } catch (ConnectorException e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE,
                    "Connector error during signing: " + e.getMessage(), e,
                    "Internal signing error");
        } catch (NotFoundException e) {
            throw new TspException(TspFailureInfo.SYSTEM_FAILURE,
                    "Key or token not found during signing: " + e.getMessage(), e,
                    "Internal signing error");
        }
    }
}

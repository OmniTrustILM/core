package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import org.bouncycastle.asn1.x509.Extensions;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.UUID;

/**
 * Internal cryptographic operations intended for internal callers only (e.g. TSA, signing
 * profiles, client operations).
 */
public interface CryptographicOperationInternalService {

    /**
     * Returns the Core-internal signature attribute definitions for the given key algorithm.
     * Unlike the connector-backed overload, this method operates purely in-memory and requires
     * no token instance or connector interaction.
     *
     * @param keyAlgorithm the key algorithm
     * @return list of Core-internal attribute definitions for signing operations
     * @throws ValidationException when the key algorithm is not supported
     */
    List<BaseAttribute> listSignatureAttributes(KeyAlgorithm keyAlgorithm) throws ValidationException;

    /**
     * Same as {@link CryptographicOperationExternalService#signData} but does not record any key event history.
     * Intended for internal callers (e.g. TSA) that manage their own audit trail.
     *
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param request           DTO containing the data to sign a request {@link SignDataRequestDto}
     * @return Signed Data {@link SignDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    SignDataResponseDto signDataWithoutEventHistory(
            SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUUID,
            UUID uuid, UUID keyItemUuid,
            SignDataRequestDto request
    ) throws ConnectorException, NotFoundException;

    /**
     * Generate the CSR with the key and token profile and CSR parameters
     *
     * @param keyUuid             UUID of the cryptographic key
     * @param tokenProfileUuid    UUID of the token profile
     * @param principal           X500 Principal
     * @param extensions          Extensions
     * @param signatureAttributes Signature attributes
     * @return Base64 encoded CSR string
     * @throws NotFoundException        When the key or token profile is not found
     * @throws NoSuchAlgorithmException when the algorithm is invalid
     * @throws InvalidKeySpecException  when the key is invalid
     * @throws IOException              when there are issues with writing the key data as string
     */
    String generateCsr(
            UUID keyUuid,
            UUID tokenProfileUuid,
            X500Principal principal,
            Extensions extensions,
            List<RequestAttribute> signatureAttributes,
            UUID altKeyUUid,
            UUID altTokenProfileUuid,
            List<RequestAttribute> altSignatureAttributes
    ) throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, AttributeException;
}

package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.OperationAttributeSchema;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * Internal cryptographic operations intended for internal callers only (e.g. TSA, signing profiles, client operations).
 */
public interface CryptographicOperationInternalService {

    /**
     * Returns signature attribute definitions used for signing, from the provider that serves it.
     *
     * @param keyUuid UUID of the key
     * @return the definitions and the connector owning them, null for Core's registry (crypto v1)
     * @throws NotFoundException when the key, its private item or its token-profile scope cannot be found
     * @throws ConnectorException when a cryptography provider v2 cannot be reached or returns no schema
     */
    OperationAttributeSchema listSignAttributeSchema(UUID keyUuid) throws NotFoundException, ConnectorException;

    /**
     * Same as {@link CryptographicOperationExternalService#signData} but does not record any key event history.
     * Intended for internal callers (e.g. TSA) that manage their own audit trail.
     *
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID UUID of the token profile
     * @param uuid UUID of the cryptographic key
     * @param keyItemUuid UUID of the Item inside the key Object
     * @param request DTO containing the data to sign a request {@link SignDataRequestDto}
     * @return Signed Data {@link SignDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    SignDataResponseDto signDataWithoutEventHistory(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUUID,
            UUID uuid, UUID keyItemUuid, SignDataRequestDto request) throws ConnectorException, NotFoundException;

    /**
     * Generate the CSR with the key and token profile and CSR parameters
     *
     * @param keyUuid UUID of the cryptographic key
     * @param tokenProfileUuid UUID of the token profile
     * @param principal X500 Principal
     * @param extensions Extensions
     * @param signatureAttributes Signature attributes
     * @return Base64 encoded CSR string
     * @throws NotFoundException When the key or token profile is not found
     * @throws NoSuchAlgorithmException when the algorithm is invalid
     * @throws InvalidKeySpecException when the key is invalid
     * @throws IOException when there are issues with writing the key data as string
     */
    String generateCsr(UUID keyUuid, UUID tokenProfileUuid, X500Principal principal, Extensions extensions,
            List<RequestAttribute> signatureAttributes, UUID altKeyUUid, UUID altTokenProfileUuid,
            List<RequestAttribute> altSignatureAttributes) throws NotFoundException, NoSuchAlgorithmException,
            InvalidKeySpecException, IOException, AttributeException;

    /**
     * The signature algorithm the signing attributes select for the key.
     *
     * @param privateKeyItem the signing key item
     * @param publicKeyItem the matching public key item, which carries the parameter set of a PQC key
     * @param signatureAttributes the attributes the caller intends to sign with
     * @throws NotFoundException when the key item's connector cannot be found
     * @throws ValidationException when the signing attributes select no algorithm the key and the platform can sign
     * with
     */
    SignatureAlgorithm resolveSignatureAlgorithm(CryptographicKeyItemOperationModel privateKeyItem,
            CryptographicKeyItemOperationModel publicKeyItem, List<RequestAttribute> signatureAttributes)
            throws NotFoundException;
}

package com.czertainly.core.service;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.cryptography.operations.*;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.UUID;

public interface CryptographicOperationService {
    /**
     * List Cipher Attributes
     *
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param keyAlgorithm      Key algorithm for which the attributes have to be fetched {@Link KeyAlgorithm}
     * @return List of attributes for Cipher Attributes
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    List<BaseAttribute> listCipherAttributes(
            SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUUID,
            UUID uuid,
            UUID keyItemUuid,
            KeyAlgorithm keyAlgorithm
    ) throws ConnectorException, NotFoundException;

    /**
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param request           DTO containing the data to encrypt the data
     * @return Encrypted data response {@Link EncryptDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    EncryptDataResponseDto encryptData(
            SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUUID,
            UUID uuid,
            UUID keyItemUuid,
            CipherDataRequestDto request
    ) throws ConnectorException, NotFoundException;

    /**
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param request           DTO containing the data to decrypt the data
     * @return Decrypted data response {@Link DecryptDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    DecryptDataResponseDto decryptData(
            SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUUID,
            UUID uuid,
            UUID keyItemUuid,
            CipherDataRequestDto request
    ) throws ConnectorException, NotFoundException;

    /**
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param keyAlgorithm      Key algorithm for which the Signature Attributes has to be fetched {@Link KeyAlgorithm}
     * @return List of attributes for the Signature Algorithm
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    List<BaseAttribute> listSignatureAttributes(
            SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUUID,
            UUID uuid,
            UUID keyItemUuid,
            KeyAlgorithm keyAlgorithm
    ) throws ConnectorException, NotFoundException;

    /**
     * Returns the Core-internal signature attribute definitions for the given key algorithm.
     * Unlike the connector-backed overload, this method operates purely in-memory and requires
     * no token instance or connector interaction.
     *
     * @param keyAlgorithm the key algorithm
     * @return list of Core-internal attribute definitions for signing operations
     * @throws ValidationException when the key algorithm is not supported
     */
    List<BaseAttribute> listSignatureAttributes(KeyAlgorithm keyAlgorithm);

    /**
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param request           DTO containing the data to sign a request {@Link SignDataRequestDto}
     * @return Signed Data {@Link SignDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    SignDataResponseDto signData(
            SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUUID,
            UUID uuid, UUID keyItemUuid,
            SignDataRequestDto request
    ) throws ConnectorException, NotFoundException;

    /**
     * Same as {@link #signData} but does not record any key event history.
     * Intended for internal callers (e.g. TSA) that manage their own audit trail.
     *
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param request           DTO containing the data to sign a request {@Link SignDataRequestDto}
     * @return Signed Data {@Link SignDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    SignDataResponseDto signDataWithoutEventHistory(
            SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUUID,
            UUID uuid, UUID keyItemUuid,
            SignDataRequestDto request
    ) throws ConnectorException, NotFoundException;

    /**
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param request           DTO Containing the data to verify the signature {@Link VerifyDataRequestDto}
     * @return Verification result {@Link VerifyDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    VerifyDataResponseDto verifyData(
            SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUUID,
            UUID uuid, UUID keyItemUuid,
            VerifyDataRequestDto request
    ) throws ConnectorException, NotFoundException;

    /**
     * @param tokenInstanceUuid UUID of the token instance
     * @return List of attributes for random data generation
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    List<BaseAttribute> listRandomAttributes(
            SecuredUUID tokenInstanceUuid
    ) throws ConnectorException, NotFoundException;

    /**
     * @param tokenInstanceUuid UUID of the token instance
     * @param request           DTO containing the information for generating a strong random data {@Link RandomDataRequestDto}
     * @return Random generated data {@Link RandomDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    RandomDataResponseDto randomData(
            SecuredUUID tokenInstanceUuid,
            RandomDataRequestDto request
    ) throws ConnectorException, NotFoundException;

    /**
     * Generate the CSR with the key and token profile and CSR parameters
     *
     * @param keyUuid             UUID of the cryptographic key
     * @param tokenProfileUuid    UUID of the token profile
     * @param principal           X500 Principal
     * @param signatureAttributes Signature attributes
     * @return Base64 encoded CSR string
     * @throws NotFoundException        When the key or token profile is not found
     * @throws NoSuchAlgorithmException when thw algorithm is invalid
     * @throws InvalidKeySpecException  when the key is invalid
     * @throws IOException              when there are issues with writing the key data as string
     */
    String generateCsr(
            UUID keyUuid,
            UUID tokenProfileUuid,
            X500Principal principal,
            List<RequestAttribute> signatureAttributes,
            UUID altKeyUUid,
            UUID altTokenProfileUuid,
            List<RequestAttribute> altSignatureAttributes
    ) throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, AttributeException;
}

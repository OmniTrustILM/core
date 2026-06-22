package com.otilm.core.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.cryptography.operations.*;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;

import java.util.List;
import java.util.UUID;

public interface CryptographicOperationExternalService {
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
}

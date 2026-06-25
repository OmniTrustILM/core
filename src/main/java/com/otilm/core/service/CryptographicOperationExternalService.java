package com.otilm.core.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.*;
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

public interface CryptographicOperationExternalService {
    /**
     * List Cipher Attributes
     *
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUUID  UUID of the token profile
     * @param uuid              UUID of the cryptographic key
     * @param keyItemUuid       UUID of the Item inside the key Object
     * @param keyAlgorithm      Key algorithm for which the attributes have to be fetched {@link KeyAlgorithm}
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
     * @return Encrypted data response {@link EncryptDataResponseDto}
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
     * @return Decrypted data response {@link DecryptDataResponseDto}
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
     * @param keyAlgorithm      Key algorithm for which the Signature Attributes has to be fetched {@link KeyAlgorithm}
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
     * @param request           DTO containing the data to sign a request {@link SignDataRequestDto}
     * @return Signed Data {@link SignDataResponseDto}
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
     * @param request           DTO Containing the data to verify the signature {@link VerifyDataRequestDto}
     * @return Verification result {@link VerifyDataResponseDto}
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
     * @param request           DTO containing the information for generating a strong random data {@link RandomDataRequestDto}
     * @return Random generated data {@link RandomDataResponseDto}
     * @throws NotFoundException when the token instance with the specified UUID is not found
     */
    RandomDataResponseDto randomData(
            SecuredUUID tokenInstanceUuid,
            RandomDataRequestDto request
    ) throws ConnectorException, NotFoundException;

    /**
     * Generate the CSR with the key and token profile and CSR parameters.
     * Pass {@code null} for {@code extensions} when there are no SAN or extension entries.
     *
     * @param keyUuid             UUID of the cryptographic key
     * @param tokenProfileUuid    UUID of the token profile
     * @param principal             Subject DN
     * @param extensions          Optional extensions to embed as pkcs-9-at-extensionRequest
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

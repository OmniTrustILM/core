package com.otilm.core.api.web;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.CryptographicOperationsController;
import com.otilm.api.model.client.cryptography.operations.*;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class CryptographicOperationControllerImpl implements CryptographicOperationsController {

    private CryptographicOperationExternalService cryptographicOperationService;

    @Autowired
    public void setCryptographicOperationService(CryptographicOperationExternalService cryptographicOperationService) {
        this.cryptographicOperationService = cryptographicOperationService;
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, affiliatedResource = Resource.TOKEN, operation = Operation.ENCRYPT)
    public EncryptDataResponseDto encryptData(
            @LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            String tokenProfileUuid,
            String uuid,
            @LogResource(uuid = true) String keyItemUuid,
            CipherDataRequestDto request
    ) throws ConnectorException, NotFoundException {
        return cryptographicOperationService.encryptData(
                SecuredParentUUID.fromString(tokenInstanceUuid),
                SecuredUUID.fromString(tokenProfileUuid),
                UUID.fromString(uuid),
                UUID.fromString(keyItemUuid),
                request);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, affiliatedResource = Resource.TOKEN, operation = Operation.DECRYPT)
    public DecryptDataResponseDto decryptData(
            @LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            String tokenProfileUuid,
            String uuid,
            @LogResource(uuid = true) String keyItemUuid,
            CipherDataRequestDto request)
            throws ConnectorException, NotFoundException {
        return cryptographicOperationService.decryptData(
                SecuredParentUUID.fromString(tokenInstanceUuid),
                SecuredUUID.fromString(tokenProfileUuid),
                UUID.fromString(uuid),
                UUID.fromString(keyItemUuid),
                request);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.SIGN)
    public SignDataResponseDto signData(
            @LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            String tokenProfileUuid,
            String uuid,
            @LogResource(uuid = true) String keyItemUuid,
            SignDataRequestDto request
    ) throws ConnectorException, NotFoundException {
        return cryptographicOperationService.signData(
                SecuredParentUUID.fromString(tokenInstanceUuid),
                SecuredUUID.fromString(tokenProfileUuid),
                UUID.fromString(uuid),
                UUID.fromString(keyItemUuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.VERIFY)
    public VerifyDataResponseDto verifyData(
            @LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            String tokenProfileUuid,
            String uuid,
            @LogResource(uuid = true) String keyItemUuid,
            VerifyDataRequestDto request
    ) throws ConnectorException, NotFoundException {
        return cryptographicOperationService.verifyData(
                SecuredParentUUID.fromString(tokenInstanceUuid),
                SecuredUUID.fromString(tokenProfileUuid),
                UUID.fromString(uuid),
                UUID.fromString(keyItemUuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.RANDOM_DATA)
    public RandomDataResponseDto randomData(
            @LogResource(uuid = true) String tokenInstanceUuid,
            RandomDataRequestDto request
    ) throws ConnectorException, NotFoundException {
        return cryptographicOperationService.randomData(
                SecuredUUID.fromString(tokenInstanceUuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.ATTRIBUTE, name = "signature", affiliatedResource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listSignatureAttributes(
            String tokenInstanceUuid,
            String tokenProfileUuid,
            String uuid,
            @LogResource(uuid = true, affiliated = true) String keyItemUuid,
            KeyAlgorithm algorithm
    ) throws ConnectorException, NotFoundException {
        return cryptographicOperationService.listSignatureAttributes(
                SecuredParentUUID.fromString(tokenInstanceUuid),
                SecuredUUID.fromString(tokenProfileUuid),
                UUID.fromString(uuid),
                UUID.fromString(keyItemUuid),
                algorithm
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.ATTRIBUTE, name = "cipher", affiliatedResource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listCipherAttributes(
            String tokenInstanceUuid,
            String tokenProfileUuid,
            String uuid,
            @LogResource(uuid = true, affiliated = true) String keyItemUuid,
            KeyAlgorithm algorithm
    ) throws ConnectorException, NotFoundException {
        return cryptographicOperationService.listCipherAttributes(
                SecuredParentUUID.fromString(tokenInstanceUuid),
                SecuredUUID.fromString(tokenProfileUuid),
                UUID.fromString(uuid),
                UUID.fromString(keyItemUuid),
                algorithm
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.ATTRIBUTE, name = "random", affiliatedResource = Resource.TOKEN, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listRandomAttributes(
            @LogResource(uuid = true, affiliated = true) String tokenInstanceUuid
    ) throws ConnectorException, NotFoundException {
        return cryptographicOperationService.listRandomAttributes(
                SecuredUUID.fromString(tokenInstanceUuid)
        );
    }
}

package com.otilm.core.api.web;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.CryptographicKeyController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.otilm.api.model.client.cryptography.key.*;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDto;
import com.otilm.api.model.core.cryptography.key.KeyEventHistoryDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.util.converter.KeyRequestTypeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RestController
public class CryptographicKeyControllerImpl implements CryptographicKeyController {

    private CryptographicKeyExternalService cryptographicKeyService;

    @Autowired
    public void setCryptographicKeyExternalService(CryptographicKeyExternalService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(KeyRequestType.class, new KeyRequestTypeConverter());
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.LIST)
    public CryptographicKeyResponseDto listCryptographicKeys(SearchRequestDto request) throws ValidationException {
        return cryptographicKeyService.listCryptographicKeys(SecurityFilter.create(), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return cryptographicKeyService.getSearchableFieldInformation();
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN_PROFILE, operation = Operation.LIST)
    public List<KeyDto> listKeyPairs(@LogResource(uuid = true, affiliated = true) Optional<String> tokenProfileUuid) {
        return cryptographicKeyService.listKeyPairs(tokenProfileUuid, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.DETAIL)
    public KeyDetailDto getKey(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, @LogResource(uuid = true) String uuid) throws NotFoundException {
        return cryptographicKeyService.getKey(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.DETAIL)
    public KeyDetailDto getKey(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return cryptographicKeyService.getKey(SecuredUUID.fromString(uuid));
    }

    @Override
    public KeyItemDetailDto editKeyItem(String uuid, String keyItemUuid, EditKeyItemDto request) throws NotFoundException {
        return cryptographicKeyService.editKeyItem(SecuredUUID.fromString(uuid), UUID.fromString(keyItemUuid), request);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.DETAIL)
    public KeyItemDetailDto getKeyItem(
            String uuid,
            @LogResource(uuid = true) String keyItemUuid
    ) throws NotFoundException {
        return cryptographicKeyService.getKeyItem(
                SecuredUUID.fromString(uuid),
                keyItemUuid
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, affiliatedResource = Resource.TOKEN, operation = Operation.DETAIL)
    public KeyItemDetailDto getKeyItem(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, String uuid, @LogResource(uuid = true) String keyItemUuid) throws NotFoundException {
        return cryptographicKeyService.getKeyItem(SecuredUUID.fromString(uuid), keyItemUuid);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.CREATE)
    public KeyDetailDto createKey(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, String tokenProfileUuid, KeyRequestType type, KeyRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        return cryptographicKeyService.createKey(
                UUID.fromString(tokenInstanceUuid),
                SecuredParentUUID.fromString(tokenProfileUuid),
                type,
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.UPDATE)
    public KeyDetailDto editKey(@LogResource(uuid = true) String uuid, EditKeyRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        return cryptographicKeyService.editKey(
                SecuredUUID.fromString(uuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.SYNC)
    public void syncKeys(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid) throws ConnectorException, AttributeException, NotFoundException {
        cryptographicKeyService.syncKeys(
                SecuredParentUUID.fromString(tokenInstanceUuid)
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.COMPROMISE)
    public void compromiseKey(@LogResource(uuid = true) String uuid, CompromiseKeyRequestDto request) throws NotFoundException {
        cryptographicKeyService.compromiseKey(
                UUID.fromString(uuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.COMPROMISE)
    public void compromiseKey(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, @LogResource(uuid = true) String uuid, CompromiseKeyRequestDto request) throws NotFoundException {
        cryptographicKeyService.compromiseKey(
                UUID.fromString(uuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.COMPROMISE)
    public void compromiseKeys(BulkCompromiseKeyRequestDto request) {
        cryptographicKeyService.compromiseKey(
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.COMPROMISE)
    public void compromiseKeyItems(BulkCompromiseKeyItemRequestDto request) {
        cryptographicKeyService.compromiseKeyItems(
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.DESTROY)
    public void destroyKey(String uuid, List<String> keyItemUuids) throws ConnectorException, NotFoundException {
        cryptographicKeyService.destroyKey(
                UUID.fromString(uuid),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.DESTROY)
    public void destroyKey(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, @LogResource(uuid = true) String uuid, List<String> keyItemUuids) throws ConnectorException, NotFoundException {
        cryptographicKeyService.destroyKey(
                UUID.fromString(uuid),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.DESTROY)
    public void destroyKeys(@LogResource(uuid = true) List<String> keyUuids) throws ConnectorException, NotFoundException {
        cryptographicKeyService.destroyKey(
                keyUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.DESTROY)
    public void destroyKeyItems(@LogResource(uuid = true) List<String> keyItemUuids) throws ConnectorException {
        cryptographicKeyService.destroyKeyItems(
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.DELETE)
    public void deleteKey(@LogResource(uuid = true) String uuid, List<String> keyItemUuids) throws ConnectorException, NotFoundException {
        cryptographicKeyService.deleteKey(
                UUID.fromString(uuid),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.DELETE)
    public void deleteKey(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, @LogResource(uuid = true) String uuid, List<String> keyItemUuids) throws ConnectorException, NotFoundException {
        cryptographicKeyService.deleteKey(
                UUID.fromString(uuid),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.DELETE)
    public void deleteKeys(@LogResource(uuid = true) List<String> keyUuids) throws ConnectorException {
        cryptographicKeyService.deleteKey(
                keyUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.DELETE)
    public void deleteKeyItems(@LogResource(uuid = true) List<String> keyItemUuids) throws ConnectorException {
        cryptographicKeyService.deleteKeyItems(
                SecurityFilter.create(),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.ENABLE)
    public void enableKey(@LogResource(uuid = true) String uuid, List<String> keyItemUuids) throws NotFoundException {
        cryptographicKeyService.enableKey(
                UUID.fromString(uuid),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.ENABLE)
    public void enableKey(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, @LogResource(uuid = true) String uuid, List<String> keyItemUuids) throws NotFoundException {
        cryptographicKeyService.enableKey(
                UUID.fromString(uuid),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.ENABLE)
    public void enableKeys(@LogResource(uuid = true) List<String> uuids) {
        cryptographicKeyService.enableKey(
                uuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.ENABLE)
    public void enableKeyItems(@LogResource(uuid = true) List<String> uuids) {
        cryptographicKeyService.enableKeyItems(
                uuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.DISABLE)
    public void disableKey(@LogResource(uuid = true) String uuid, List<String> keyItemUuids) throws NotFoundException {
        cryptographicKeyService.disableKey(
                UUID.fromString(uuid),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.DISABLE)
    public void disableKey(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, @LogResource(uuid = true) String uuid, List<String> keyItemUuids) throws NotFoundException {
        cryptographicKeyService.disableKey(
                UUID.fromString(uuid),
                keyItemUuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.DISABLE)
    public void disableKeys(@LogResource(uuid = true) List<String> uuids) {
        cryptographicKeyService.disableKey(
                uuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.DISABLE)
    public void disableKeyItems(@LogResource(uuid = true) List<String> uuids) {
        cryptographicKeyService.disableKeyItems(
                uuids
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.UPDATE_KEY_USAGE)
    public void updateKeyUsages(@LogResource(uuid = true) String uuid, UpdateKeyUsageRequestDto request) throws NotFoundException, ValidationException {
        cryptographicKeyService.updateKeyUsages(
                UUID.fromString(uuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, affiliatedResource = Resource.TOKEN, operation = Operation.UPDATE_KEY_USAGE)
    public void updateKeyUsages(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, @LogResource(uuid = true) String uuid, UpdateKeyUsageRequestDto request) throws NotFoundException, ValidationException {
        cryptographicKeyService.updateKeyUsages(
                UUID.fromString(uuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY, operation = Operation.UPDATE_KEY_USAGE)
    public void updateKeysUsages(BulkKeyUsageRequestDto request) {
        cryptographicKeyService.updateKeyUsages(
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.UPDATE_KEY_USAGE)
    public void updateKeyItemUsages(BulkKeyItemUsageRequestDto request) {
        cryptographicKeyService.updateKeyItemUsages(
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.ATTRIBUTE, affiliatedResource = Resource.TOKEN, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listCreateKeyAttributes(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, String tokenProfileUuid, @LogResource(name = true) KeyRequestType type) throws ConnectorException, NotFoundException {
        return cryptographicKeyService.listCreateKeyAttributes(
                UUID.fromString(tokenInstanceUuid),
                SecuredParentUUID.fromString(tokenProfileUuid),
                type
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, operation = Operation.HISTORY)
    public List<KeyEventHistoryDto> getEventHistory(@LogResource(uuid = true) String uuid, String keyItemUuid) throws NotFoundException {
        return cryptographicKeyService.getEventHistory(
                UUID.fromString(uuid),
                UUID.fromString(keyItemUuid)
        );
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.CRYPTOGRAPHIC_KEY_ITEM, affiliatedResource = Resource.TOKEN, operation = Operation.HISTORY)
    public List<KeyEventHistoryDto> getEventHistory(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, String uuid, @LogResource(uuid = true) String keyItemUuid) throws NotFoundException {
        return cryptographicKeyService.getEventHistory(
                UUID.fromString(uuid),
                UUID.fromString(keyItemUuid)
        );
    }
}

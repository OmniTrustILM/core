package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.TokenProfileController;
import com.otilm.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.BulkTokenProfileKeyUsageRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.TokenProfileKeyUsageRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
public class TokenProfileControllerImpl implements TokenProfileController {

    private TokenProfileExternalService tokenProfileService;
    private TokenInstanceExternalService tokenInstanceService;

    @Autowired
    public void setTokenProfileService(TokenProfileExternalService tokenProfileService) {
        this.tokenProfileService = tokenProfileService;
    }

    @Autowired
    public void setTokenInstanceService(TokenInstanceExternalService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.TOKEN_PROFILE)
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE, operation = Operation.LIST)
    public List<TokenProfileDto> listTokenProfiles(Optional<Boolean> enabled) {
        return tokenProfileService.listTokenProfiles(enabled, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.ATTRIBUTE, name = "tokenProfile",
            affiliatedResource = Resource.TOKEN, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listTokenProfileAttributes(
            @LogResource(uuid = true, affiliated = true) String tokenInstanceUuid)
            throws ConnectorException, NotFoundException {
        return tokenInstanceService.listTokenProfileAttributes(SecuredUUID.fromString(tokenInstanceUuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            affiliatedResource = Resource.TOKEN, operation = Operation.DETAIL)
    public TokenProfileDetailDto getTokenProfile(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            @LogResource(uuid = true) String uuid) throws NotFoundException {
        return tokenProfileService
                .getTokenProfile(SecuredParentUUID.fromString(tokenInstanceUuid), SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            affiliatedResource = Resource.TOKEN, operation = Operation.CREATE)
    public ResponseEntity<TokenProfileDetailDto> createTokenProfile(
            @LogResource(uuid = true, affiliated = true) String tokenInstanceUuid, AddTokenProfileRequestDto request)
            throws AlreadyExistException, ValidationException, ConnectorException, AttributeException,
            NotFoundException {
        TokenProfileDetailDto tokenProfileDetailDto = tokenProfileService
                .createTokenProfile(SecuredParentUUID.fromString(tokenInstanceUuid), request);
        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(tokenProfileDetailDto.getUuid())
                .toUri();
        return ResponseEntity.created(location).body(tokenProfileDetailDto);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            affiliatedResource = Resource.TOKEN, operation = Operation.UPDATE)
    public TokenProfileDetailDto editTokenProfile(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            @LogResource(uuid = true) String uuid, EditTokenProfileRequestDto request)
            throws ConnectorException, AttributeException, NotFoundException {
        return tokenProfileService
                .editTokenProfile(SecuredParentUUID.fromString(tokenInstanceUuid), SecuredUUID.fromString(uuid),
                        request);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            affiliatedResource = Resource.TOKEN, operation = Operation.DELETE)
    public void deleteTokenProfile(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            @LogResource(uuid = true) String uuid) throws NotFoundException {
        tokenProfileService
                .deleteTokenProfile(SecuredParentUUID.fromString(tokenInstanceUuid), SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE, operation = Operation.DELETE)
    public void deleteTokenProfile(@LogResource(uuid = true) String uuid) throws NotFoundException {
        tokenProfileService.deleteTokenProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            affiliatedResource = Resource.TOKEN, operation = Operation.DISABLE)
    public void disableTokenProfile(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            @LogResource(uuid = true) String uuid) throws NotFoundException {
        tokenProfileService
                .disableTokenProfile(SecuredParentUUID.fromString(tokenInstanceUuid), SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            affiliatedResource = Resource.TOKEN, operation = Operation.ENABLE)
    public void enableTokenProfile(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            @LogResource(uuid = true) String uuid) throws NotFoundException {
        tokenProfileService
                .enableTokenProfile(SecuredParentUUID.fromString(tokenInstanceUuid), SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE, operation = Operation.DELETE)
    public void deleteTokenProfiles(@LogResource(uuid = true) List<String> uuids) {
        tokenProfileService.deleteTokenProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE, operation = Operation.DISABLE)
    public void disableTokenProfiles(@LogResource(uuid = true) List<String> uuids) {
        tokenProfileService.disableTokenProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE, operation = Operation.ENABLE)
    public void enableTokenProfiles(@LogResource(uuid = true) List<String> uuids) {
        tokenProfileService.enableTokenProfile(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            affiliatedResource = Resource.TOKEN, operation = Operation.LIST_KEY_USAGES)
    public List<KeyUsage> listSupportedTokenProfileKeyUsages(
            @LogResource(uuid = true, affiliated = true) String tokenInstanceUuid)
            throws ConnectorException, NotFoundException {
        return tokenInstanceService.listSupportedKeyUsages(SecuredUUID.fromString(tokenInstanceUuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            affiliatedResource = Resource.TOKEN, operation = Operation.UPDATE_KEY_USAGE)
    public void updateKeyUsages(@LogResource(uuid = true, affiliated = true) String tokenInstanceUuid,
            @LogResource(uuid = true) String tokenProfileUuid, TokenProfileKeyUsageRequestDto request)
            throws NotFoundException, ValidationException {
        tokenProfileService
                .updateKeyUsages(SecuredParentUUID.fromString(tokenInstanceUuid),
                        SecuredUUID.fromString(tokenProfileUuid), request.getUsage());
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN_PROFILE,
            operation = Operation.UPDATE_KEY_USAGE)
    public void updateKeysUsages(BulkTokenProfileKeyUsageRequestDto request) {
        tokenProfileService.updateKeyUsages(SecuredUUID.fromUuidList(request.getUuids()), request.getUsage());
    }
}

package com.otilm.core.api.web;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.TokenInstanceController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.token.TokenInstanceRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.TokenInstanceExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class TokenInstanceControllerImpl implements TokenInstanceController {

    private TokenInstanceExternalService tokenInstanceService;

    @Autowired
    public void setTokenInstanceService(TokenInstanceExternalService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }


    @Override
    @AuthEndpoint(resourceName = Resource.TOKEN)
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.LIST)
    public List<TokenInstanceDto> listTokenInstances() {
        return tokenInstanceService.listTokenInstances(SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.DETAIL)
    public TokenInstanceDetailDto getTokenInstance(@LogResource(uuid = true) String uuid) throws ConnectorException, NotFoundException {
        return tokenInstanceService.getTokenInstance(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.CREATE)
    public TokenInstanceDetailDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        return tokenInstanceService.createTokenInstance(request);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.UPDATE)
    public TokenInstanceDetailDto updateTokenInstance(@LogResource(uuid = true) String uuid, TokenInstanceRequestDto request) throws ConnectorException, ValidationException, AttributeException, NotFoundException {
        return tokenInstanceService.updateTokenInstance(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.DELETE)
    public void deleteTokenInstance(@LogResource(uuid = true) String uuid) throws NotFoundException {
        tokenInstanceService.deleteTokenInstance(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.ACTIVATE)
    public void activateTokenInstance(@LogResource(uuid = true) String uuid, List<RequestAttribute> attributes) throws ConnectorException, NotFoundException {
        tokenInstanceService.activateTokenInstance(SecuredUUID.fromString(uuid), attributes);
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.DEACTIVATE)
    public void deactivateTokenInstance(@LogResource(uuid = true) String uuid) throws ConnectorException, NotFoundException {
        tokenInstanceService.deactivateTokenInstance(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.DELETE)
    public void deleteTokenInstance(@LogResource(uuid = true) List<String> uuids) {
        tokenInstanceService.deleteTokenInstance(SecuredUUID.fromList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.TOKEN, operation = Operation.GET_STATUS)
    public TokenInstanceDetailDto reloadStatus(@LogResource(uuid = true) String uuid) throws ConnectorException, NotFoundException {
        return tokenInstanceService.reloadStatus(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.ATTRIBUTE, name = "tokenProfile", affiliatedResource = Resource.TOKEN, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listTokenProfileAttributes(@LogResource(uuid = true, affiliated = true) String uuid) throws ConnectorException, NotFoundException {
        return tokenInstanceService.listTokenProfileAttributes(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CRYPTOGRAPHIC_KEYS, resource = Resource.ATTRIBUTE, name = "activate", affiliatedResource = Resource.TOKEN, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listTokenInstanceActivationAttributes(@LogResource(uuid = true, affiliated = true) String uuid) throws ConnectorException, NotFoundException {
        return tokenInstanceService.listTokenInstanceActivationAttributes(SecuredUUID.fromString(uuid));
    }
}

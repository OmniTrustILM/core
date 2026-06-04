package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.ProxyController;
import com.czertainly.api.model.client.proxy.ProxyRequestDto;
import com.czertainly.api.model.client.proxy.ProxyUpdateRequestDto;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.proxy.ProxyDto;
import com.czertainly.api.model.core.proxy.ProxyInstallInstructionsDto;
import com.czertainly.api.model.core.proxy.ProxyListDto;
import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ProxyService;
import com.czertainly.core.util.converter.ProxyStatusConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * REST controller implementation for proxy management operations.
 */
@RestController
@RequiredArgsConstructor
public class ProxyControllerImpl implements ProxyController {

    private final ProxyService proxyService;

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(ProxyStatus.class, new ProxyStatusConverter());
    }

    @Override
    @AuthEndpoint(resourceName = Resource.PROXY)
    @AuditLogged(module = Module.CORE, resource = Resource.PROXY, operation = Operation.LIST)
    public List<ProxyListDto> listProxies(ProxyStatus status) {
        return proxyService.listProxies(SecurityFilter.create(), Optional.ofNullable(status));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.PROXY, operation = Operation.DETAIL)
    public ProxyDto getProxy(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return proxyService.getProxy(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.PROXY, operation = Operation.CREATE)
    public ResponseEntity<?> createProxy(ProxyRequestDto request) throws AlreadyExistException {
        ProxyDto proxyDto = proxyService.createProxy(request);

        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{uuid}")
                .buildAndExpand(proxyDto.getUuid()).toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(proxyDto.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.PROXY, operation = Operation.UPDATE)
    public ProxyDto editProxy(@LogResource(uuid = true) String uuid, ProxyUpdateRequestDto request)
            throws NotFoundException {
        return proxyService.editProxy(SecuredUUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.PROXY, operation = Operation.DELETE)
    public void deleteProxy(@LogResource(uuid = true) String uuid) throws NotFoundException {
        proxyService.deleteProxy(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.PROXY, operation = Operation.GET_PROXY_INSTALLATION)
    public ProxyInstallInstructionsDto getInstallationInstructions(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return proxyService.getInstallationInstructions(SecuredUUID.fromString(uuid));
    }
}

package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.proxy.ProxyRequestDto;
import com.czertainly.api.model.client.proxy.ProxyUpdateRequestDto;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.proxy.ProxyDto;
import com.czertainly.api.model.core.proxy.ProxyInstallInstructionsDto;
import com.czertainly.api.model.core.proxy.ProxyListDto;
import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Proxy;
import com.czertainly.core.dao.entity.Proxy_;
import com.czertainly.core.dao.repository.ProxyRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.provisioning.ProxyProvisioningService;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ProxyService;
import com.czertainly.core.util.ProxyCodeHelper;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Implementation of {@link ProxyService} for managing proxy entities.
 */
@Service(Resource.Codes.PROXY)
@Transactional
@RequiredArgsConstructor
public class ProxyServiceImpl implements ProxyService {
    private static final Logger logger = LoggerFactory.getLogger(ProxyServiceImpl.class);

    private final ProxyRepository proxyRepository;
    private final ProxyCodeHelper proxyCodeHelper;
    private final ProxyProvisioningService proxyProvisioningService;

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.LIST)
    public List<ProxyListDto> listProxies(SecurityFilter filter, Optional<ProxyStatus> status) {
        logger.debug("Listing proxies with status filter: {}", status.orElse(null));
        List<ProxyListDto> proxies = proxyRepository.findUsingSecurityFilter(filter).stream().map(Proxy::mapToListDto).toList();
        if (status.isPresent()) {
            proxies = filterByStatus(proxies, status.get());
        }
        logger.debug("Found {} proxies", proxies.size());
        return proxies;
    }

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.DETAIL)
    public ProxyDto getProxy(SecuredUUID uuid) throws NotFoundException {
        logger.debug("Getting proxy with UUID: {}", uuid);
        Proxy proxy = getProxyEntity(uuid);

        return proxy.mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.DETAIL)
    public Proxy getProxyEntity(SecuredUUID uuid) throws NotFoundException {
        return proxyRepository.findByUuid(uuid)
            .orElseThrow(() -> new NotFoundException(Proxy.class, uuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.CREATE)
    public ProxyDto createProxy(ProxyRequestDto request) throws AlreadyExistException {
        logger.info("Creating proxy with name: {}", request.getName());

        if (StringUtils.isBlank(request.getName())) {
            throw new ValidationException(ValidationError.create("name must not be empty"));
        }

        if (proxyRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(Proxy.class, request.getName());
        }

        String proxyCode = proxyCodeHelper.calculateCode(request.getName());
        logger.debug("Generated proxy code: {}", proxyCode);

        Proxy proxy = new Proxy();
        proxy.setName(request.getName());
        proxy.setDescription(request.getDescription());
        proxy.setCode(proxyCode);

        // INITIALIZED and PROVISIONING are currently skipped because the provisioning is synchronous
        proxy.setStatus(ProxyStatus.WAITING_FOR_INSTALLATION);

        proxyRepository.save(proxy);
        logger.debug("Proxy saved with UUID: {}", proxy.getUuid());

        // Provision the proxy using the provisioning service
        proxyProvisioningService.provisionProxy(proxyCode);

        logger.info("Proxy created successfully: {} ({})", proxy.getName(), proxy.getUuid());
        return proxy.mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.UPDATE)
    public ProxyDto editProxy(SecuredUUID uuid, ProxyUpdateRequestDto request) throws NotFoundException {
        logger.info("Editing proxy with UUID: {}", uuid);

        Proxy proxy = proxyRepository.findByUuid(uuid)
            .orElseThrow(() -> new NotFoundException(Proxy.class, uuid));

        if (request.getDescription() != null) {
            proxy.setDescription(request.getDescription());
        }

        proxyRepository.save(proxy);

        logger.info("Proxy updated successfully: {} ({})", proxy.getName(), proxy.getUuid());
        return proxy.mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.DELETE)
    public void deleteProxy(SecuredUUID uuid) throws NotFoundException {
        logger.info("Deleting proxy with UUID: {}", uuid);

        Proxy proxy = proxyRepository.findByUuid(uuid)
            .orElseThrow(() -> new NotFoundException(Proxy.class, uuid));

        String proxyName = proxy.getName();
        String proxyCode = proxy.getCode();

        deleteProxy(proxy);

        proxyProvisioningService.decommissionProxy(proxyCode);

        logger.info("Proxy deleted successfully: {} ({})", proxyName, uuid);
    }

    private void deleteProxy(Proxy proxy) {
        List<String> errors = new ArrayList<>();
        if (!proxy.getConnectors().isEmpty()) {
            errors.add("Dependent connectors: " + String.join(", ", proxy.getConnectors().stream().map(Connector::getName).collect(Collectors.toSet())));
        }

        if (!errors.isEmpty()) {
            throw new ValidationException(ValidationError.create(String.join("\n", errors)));
        }

        proxyRepository.delete(proxy);
    }

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.GET_PROXY_INSTALLATION)
    public ProxyInstallInstructionsDto getInstallationInstructions(SecuredUUID uuid) throws NotFoundException {
        logger.debug("Getting installation instructions for proxy with UUID: {}", uuid);

        Proxy proxy = getProxyEntity(uuid);

        String installInstructions = proxyProvisioningService.getProxyInstallationInstructions(proxy.getCode());

        return new ProxyInstallInstructionsDto(uuid.toString(), installInstructions);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return proxyRepository.findResourceObject(objectUuid, Proxy_.name);
    }

    @Override
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return getResourceObjectInternal(objectUuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return proxyRepository.listResourceObjects(filter, Proxy_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.PROXY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getProxyEntity(uuid);
        // Since there are is no parent to the Proxy, exclusive parent permission evaluation need not be done
    }

    private List<ProxyListDto> filterByStatus(List<ProxyListDto> proxies, ProxyStatus status) {
        return proxies.stream()
            .filter(proxyDto -> proxyDto.getStatus().equals(status))
            .toList();
    }
}

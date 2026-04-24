package com.czertainly.core.service.handler;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.connector.InfoResponse;
import com.czertainly.api.model.client.connector.v2.*;
import com.czertainly.api.model.core.connector.*;
import com.czertainly.api.model.core.connector.v2.ConnectInfo;
import com.czertainly.api.model.core.connector.v2.ConnectInfoV1;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.Endpoint;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.util.MetaDefinitions;
import com.czertainly.core.util.NullUtil;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Component(ConnectorVersion.Codes.V1)
public class ConnectorV1Adapter implements ConnectorAdapter {

    private static final Logger logger = LoggerFactory.getLogger(ConnectorV1Adapter.class);

    private ConnectorApiFactory connectorApiFactory;

    private ConnectorRepository connectorRepository;
    private FunctionGroupRepository functionGroupRepository;
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    @Autowired
    public void setFunctionGroupRepository(FunctionGroupRepository functionGroupRepository) {
        this.functionGroupRepository = functionGroupRepository;
    }

    @Autowired
    public void setConnector2FunctionGroupRepository(Connector2FunctionGroupRepository connector2FunctionGroupRepository) {
        this.connector2FunctionGroupRepository = connector2FunctionGroupRepository;
    }

    @Override
    public ConnectorVersion getVersion() {
        return ConnectorVersion.V1;
    }

    @Override
    public ConnectorInfo getInfo(ApiClientConnectorInfo connectorInfo) {
        throw new UnsupportedOperationException("Getting connector info is not supported for connector version " + getVersion());
    }

    @Override
    public HealthInfo checkHealth(ApiClientConnectorInfo connectorInfo) throws ConnectorException {
        var healthDto = connectorApiFactory.getHealthApiClient(connectorInfo).checkHealth(connectorInfo);

        HealthInfo healthInfo = new HealthInfo();
        healthInfo.setStatus(mapHealthStatus(healthDto.getStatus()));

        if (healthDto.getParts() != null && !healthDto.getParts().isEmpty()) {
            healthInfo.setComponents(new HashMap<>());
            healthDto.getParts().forEach((key, value) -> {
                HealthInfoComponent component = new HealthInfoComponent();
                component.setStatus(mapHealthStatus(value.getStatus()));
                if (!StringUtils.isBlank(value.getDescription())) {
                    component.getDetails().put("description", value.getDescription());
                }
                healthInfo.getComponents().put(key, component);
            });
        }

        return healthInfo;
    }

    @Override
    public ConnectInfoV1 checkConnection(ApiClientConnectorInfo connectorInfo) throws ConnectorException {
        List<InfoResponse> functions = connectorApiFactory.getConnectorApiClient(connectorInfo).listSupportedFunctions(connectorInfo);

        ConnectInfoV1 connectInfo = new ConnectInfoV1();
        connectInfo.setConnectorUuid(NullUtil.parseUuidOrNull(connectorInfo.getUuid()));
        functions.forEach(function -> {
            FunctionGroupDto functionGroupDto = new FunctionGroupDto();
            functionGroupDto.setName(function.getFunctionGroupCode().getLabel());
            functionGroupDto.setFunctionGroupCode(function.getFunctionGroupCode());
            functionGroupDto.setKinds(function.getKinds());
            functionGroupDto.setEndPoints(function.getEndPoints());
            connectInfo.getFunctionGroups().add(functionGroupDto);
        });

        return connectInfo;
    }

    @Override
    public ConnectInfoV1 validateConnection(ApiClientConnectorInfo connectorInfo) throws ConnectorException {
        ConnectInfo connectInfo = checkConnection(connectorInfo);
        return validateConnection(connectInfo);
    }

    @Override
    public ConnectInfoV1 validateConnection(ConnectInfo connectInfoV1) throws ConnectorException {
        ConnectInfoV1 connectInfo = (ConnectInfoV1) connectInfoV1;
        List<FunctionGroupCode> connectFunctionGroupCodeList = new ArrayList<>();
        Map<FunctionGroupCode, List<String>> connectFunctionGroupKindMap = new EnumMap<>(FunctionGroupCode.class);
        connectInfo.getFunctionGroups().forEach(functionGroup -> {
            connectFunctionGroupCodeList.add(functionGroup.getFunctionGroupCode());
            connectFunctionGroupKindMap.put(functionGroup.getFunctionGroupCode(), functionGroup.getKinds());
        });

        List<String> alreadyExistingConnector = new ArrayList<>();
        for (Connector connector : connectorRepository.findAll()) {
            if (connectInfo.getConnectorUuid() != null && connector.getUuid().equals(connectInfo.getConnectorUuid())) {
                continue;
            }
            List<FunctionGroupCode> connectorFunctionGroups = connector.getFunctionGroups().stream().map(Connector2FunctionGroup::getFunctionGroup).toList().stream().map(FunctionGroup::getCode).toList();
            if (connectFunctionGroupCodeList.equals(connectorFunctionGroups)) {
                Map<FunctionGroupCode, List<String>> connectorFunctionGroupKindMap = new EnumMap<>(FunctionGroupCode.class);

                for (Connector2FunctionGroup f : connector.getFunctionGroups()) {
                    connectorFunctionGroupKindMap.put(f.getFunctionGroup().getCode(), MetaDefinitions.deserializeArrayString(f.getKinds()));
                }

                if (connectFunctionGroupKindMap.equals(connectorFunctionGroupKindMap)) {
                    alreadyExistingConnector.add(connector.getName());
                }
            }
        }

        List<ValidationError> errors = new ArrayList<>();
        if (!alreadyExistingConnector.isEmpty()) {
            errors.add(ValidationError.create("Connector(s) with same kinds already exists:" + String.join(",", alreadyExistingConnector)));
        }

        validateFunctionGroups(connectInfo, errors);

        if (!errors.isEmpty()) {
            throw new ValidationException("Connector validation failed.", errors);
        }

        return connectInfo;
    }

    @Override
    public void updateConnectorFunctions(Connector connector, ConnectInfo connectInfo) throws ConnectorException, NotFoundException {
        ConnectInfoV1 connectInfoV1 = (ConnectInfoV1) connectInfo;

        // adding phase
        for (FunctionGroupDto dto : connectInfoV1.getFunctionGroups()) {
            FunctionGroup functionGroup = functionGroupRepository.findByCode(dto.getFunctionGroupCode())
                    .orElseThrow(() -> new NotFoundException(FunctionGroup.class, dto.getFunctionGroupCode().getLabel() + " function group"));

            dto.setUuid(functionGroup.getUuid().toString());
            dto.setName(functionGroup.getName());
            Connector2FunctionGroup c2fg = connector2FunctionGroupRepository.findByConnectorAndFunctionGroup(connector, functionGroup).orElse(null);

            if (c2fg != null) {
                String dtoKinds = MetaDefinitions.serializeArrayString(dto.getKinds());
                if (!dtoKinds.equals(c2fg.getKinds())) {
                    c2fg.setKinds(dtoKinds);
                    connector2FunctionGroupRepository.save(c2fg);
                }
                logger.debug("Connector {} already has function group {} - not added", connector.getName(), functionGroup.getName());

            } else {
                c2fg = new Connector2FunctionGroup();
                c2fg.setConnector(connector);
                c2fg.setFunctionGroup(functionGroup);
                c2fg.setKinds(MetaDefinitions.serializeArrayString(dto.getKinds()));
                connector2FunctionGroupRepository.save(c2fg);

                connector.getFunctionGroups().add(c2fg);
                connectorRepository.save(connector);

                logger.debug("Added function group {} to connector {}", functionGroup.getName(), connector.getName());
            }
        }

        // removing phase
        for (Connector2FunctionGroup c2fg : new HashSet<>(connector.getFunctionGroups())) {
            Optional<FunctionGroupDto> dto = connectInfoV1.getFunctionGroups().stream()
                    .filter(fg -> fg.getUuid().equals(c2fg.getFunctionGroup().getUuid().toString()))
                    .findFirst();

            if (dto.isPresent()) {
                logger.debug("Connector {} still has function group {} - not removed", connector.getName(), dto.get().getName());
            } else {
                Connector2FunctionGroup c2fgExisting = connector2FunctionGroupRepository.findByConnectorAndFunctionGroup(connector, c2fg.getFunctionGroup())
                        .orElseThrow(() -> new NotFoundException(Connector2FunctionGroup.class, "connector=%s, functionGroup=%s".formatted(connector.getName(), c2fg.getFunctionGroup().getName())));

                connector2FunctionGroupRepository.delete(c2fgExisting);

                connector.getFunctionGroups().remove(c2fgExisting);
                connectorRepository.save(connector);
                logger.debug("Removed function group {} from connector {}", c2fg.getFunctionGroup().getName(), connector.getName());
            }
        }

    }

    private HealthStatus mapHealthStatus(com.czertainly.api.model.common.HealthStatus status) {
        if (status == null) {
            return HealthStatus.UNKNOWN;
        }
        return switch (status) {
            case OK -> HealthStatus.UP;
            case NOK -> HealthStatus.DOWN;
            default -> HealthStatus.UNKNOWN;
        };
    }

    private void validateFunctionGroups(ConnectInfoV1 connectInfo, List<ValidationError> errors) {
        for (BaseFunctionGroupDto f : connectInfo.getFunctionGroups()) {
            Optional<FunctionGroup> functionGroup = functionGroupRepository.findByCode(f.getFunctionGroupCode());

            if (functionGroup.isEmpty()) {
                errors.add(ValidationError.create("Function group {} doesn't exist.", f.getFunctionGroupCode()));
                continue;
            }

            for (Endpoint e : functionGroup.get().getEndpoints()) {
                EndpointDto endpoint = findEndpoint(f.getEndPoints(), e.mapToDto());
                if (Boolean.TRUE.equals(e.isRequired()) && endpoint == null) {
                    errors.add(ValidationError.create("Required endpoint {} not supported by connector.", e.getName()));
                }
            }
        }
    }

    private EndpointDto findEndpoint(List<EndpointDto> endpoints, EndpointDto wanted) {
        return endpoints.stream()
                .filter(e ->
                        e.getName().equals(wanted.getName()) &&
                                e.getContext().equals(wanted.getContext()) &&
                                e.getMethod().equals(wanted.getMethod())
                )
                .findFirst()
                .orElse(null);
    }
}

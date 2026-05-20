package com.czertainly.core.service.v2.impl;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("extendedAcmeServiceImpl")
public class ExtendedAttributeServiceImpl implements ExtendedAttributeService {

    private ConnectorApiFactory connectorApiFactory;

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    private ConnectorRepository connectorRepository;

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    private ConnectorService connectorService;

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Override
    public List<BaseAttribute> listIssueCertificateAttributes(RaProfile raProfile) throws ConnectorException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(connector.getUuid());
        return connectorApiFactory.getCertificateApiClientV2(connectorDto).listIssueCertificateAttributes(
                connectorDto,
                authorityRef.getAuthorityInstanceUuid());
    }

    @Override
    public boolean validateIssueCertificateAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(connector.getUuid());
        return connectorApiFactory.getCertificateApiClientV2(connectorDto).validateIssueCertificateAttributes(
                connectorDto,
                authorityRef.getAuthorityInstanceUuid(),
                attributes);
    }

    @Override
    public void mergeAndValidateIssueAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        if (raProfile.getAuthorityInstanceReference().getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        var certificateApiClient = connectorApiFactory.getCertificateApiClientV2(connectorDto);

        // validate first by connector
        if (attributes == null) {
            attributes = new ArrayList<>();
        }
        certificateApiClient.validateIssueCertificateAttributes(connectorDto, raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), attributes);

        // get definitions from connector
        List<BaseAttribute> definitions = certificateApiClient.listIssueCertificateAttributes(connectorDto, raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid());

        // validate and update definitions with attribute engine
        attributeEngine.validateUpdateDataAttributes(raProfile.getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_ISSUE, definitions, attributes);
    }

    @Override
    public List<BaseAttribute> listRevokeCertificateAttributes(RaProfile raProfile) throws ConnectorException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(connector.getUuid());
        return connectorApiFactory.getCertificateApiClientV2(connectorDto).listRevokeCertificateAttributes(
                connectorDto,
                authorityRef.getAuthorityInstanceUuid());
    }

    @Override
    public boolean validateRevokeCertificateAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(connector.getUuid());
        return connectorApiFactory.getCertificateApiClientV2(connectorDto).validateRevokeCertificateAttributes(
                connectorDto,
                authorityRef.getAuthorityInstanceUuid(),
                attributes);
    }

    @Override
    public void mergeAndValidateRevokeAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        if (raProfile.getAuthorityInstanceReference().getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        var certificateApiClient = connectorApiFactory.getCertificateApiClientV2(connectorDto);

        // validate first by connector
        if (attributes == null) {
            attributes = new ArrayList<>();
        }
        certificateApiClient.validateRevokeCertificateAttributes(connectorDto, raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(), attributes);

        // get definitions from connector
        List<BaseAttribute> definitions = certificateApiClient.listRevokeCertificateAttributes(connectorDto, raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid());

        // validate and update definitions with attribute engine
        attributeEngine.validateUpdateDataAttributes(raProfile.getAuthorityInstanceReference().getConnectorUuid(), AttributeOperation.CERTIFICATE_REVOKE, definitions, attributes);
    }

    @Override
    public void validateLegacyConnector(Connector connector) throws NotFoundException {
        for (Connector2FunctionGroup fg : connector.getFunctionGroups()) {
            if (!connectorRepository.findConnectedByFunctionGroupAndKind(fg.getFunctionGroup(), "LegacyEjbca").isEmpty()) {
                throw new NotFoundException("Legacy Authority. V2 Implementation not found on the connector");
            }
        }
    }
}

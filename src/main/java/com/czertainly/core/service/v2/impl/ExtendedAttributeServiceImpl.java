package com.czertainly.core.service.v2.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.service.v2.ExtendedAttributeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("extendedAcmeServiceImpl")
public class ExtendedAttributeServiceImpl implements ExtendedAttributeService {

    @Autowired
    private ConnectorApiFactory connectorApiFactory;
    @Autowired
    private ConnectorRepository connectorRepository;

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

        var connectorDto = connector.mapToApiClientDtoV1();
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

        var connectorDto = connector.mapToApiClientDtoV1();
        return connectorApiFactory.getCertificateApiClientV2(connectorDto).validateIssueCertificateAttributes(
                connectorDto,
                authorityRef.getAuthorityInstanceUuid(),
                attributes);
    }

    @Override
    public void mergeAndValidateIssueAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException {
        if (raProfile.getAuthorityInstanceReference().getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }
        ConnectorApiClientDto connectorDto = raProfile.getAuthorityInstanceReference().getConnector().mapToApiClientDtoV1();
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

        var connectorDto = connector.mapToApiClientDtoV1();
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

        var connectorDto = connector.mapToApiClientDtoV1();
        return connectorApiFactory.getCertificateApiClientV2(connectorDto).validateRevokeCertificateAttributes(
                connectorDto,
                authorityRef.getAuthorityInstanceUuid(),
                attributes);
    }

    @Override
    public void mergeAndValidateRevokeAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException {
        if (raProfile.getAuthorityInstanceReference().getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }

        ConnectorApiClientDto connectorDto = raProfile.getAuthorityInstanceReference().getConnector().mapToApiClientDtoV1();
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

package com.otilm.core.service.v2.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.v2.ConnectorService;
import com.otilm.core.service.v2.ExtendedAttributeService;
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

    private AuthorityProviderAdapterFactory authorityProviderAdapterFactory;

    @Autowired
    public void setAuthorityProviderAdapterFactory(AuthorityProviderAdapterFactory authorityProviderAdapterFactory) {
        this.authorityProviderAdapterFactory = authorityProviderAdapterFactory;
    }

    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Override
    public List<BaseAttribute> listIssueCertificateAttributes(RaProfile raProfile) throws ConnectorException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        if (authorityRef.getConnector() == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        return authorityProviderAdapterFactory.forAuthority(authorityRef).listIssueAttributes(authorityRef, raProfile);
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

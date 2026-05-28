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

    private com.czertainly.core.service.handler.authority.AuthorityProviderAdapterFactory adapterFactory;

    @Autowired
    public void setAdapterFactory(com.czertainly.core.service.handler.authority.AuthorityProviderAdapterFactory adapterFactory) {
        this.adapterFactory = adapterFactory;
    }

    @Override
    public List<BaseAttribute> listIssueCertificateAttributes(RaProfile raProfile) throws ConnectorException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        // Adapter-routed so v3 authorities use the v3 list endpoint, not the v2 one.
        return adapterFactory.forAuthority(authorityRef).listIssueAttributes(authorityRef, raProfile);
    }

    @Override
    public boolean validateIssueCertificateAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        // v2 hits the connector /validate; v3 is a local no-op (contract dropped /validate).
        // A hard validation failure surfaces as ValidationException; success returns true.
        adapterFactory.forAuthority(authorityRef).validateIssueAttributes(authorityRef, attributes);
        return true;
    }

    @Override
    public void mergeAndValidateIssueAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        if (authorityRef.getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }
        if (attributes == null) {
            attributes = new ArrayList<>();
        }
        var adapter = adapterFactory.forAuthority(authorityRef);

        // connector-side validate (v2 → /validate; v3 → no-op)
        adapter.validateIssueAttributes(authorityRef, attributes);

        // version-aware definitions
        List<BaseAttribute> definitions = adapter.listIssueAttributes(authorityRef, raProfile);

        // local structural validation against definitions (both versions)
        attributeEngine.validateUpdateDataAttributes(authorityRef.getConnectorUuid(), AttributeOperation.CERTIFICATE_ISSUE, definitions, attributes);
    }

    @Override
    public List<BaseAttribute> listRevokeCertificateAttributes(RaProfile raProfile) throws ConnectorException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        return adapterFactory.forAuthority(authorityRef).listRevokeAttributes(authorityRef, raProfile);
    }

    @Override
    public boolean validateRevokeCertificateAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        adapterFactory.forAuthority(authorityRef).validateRevokeAttributes(authorityRef, attributes);
        return true;
    }

    @Override
    public void mergeAndValidateRevokeAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        if (authorityRef.getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }
        if (attributes == null) {
            attributes = new ArrayList<>();
        }
        var adapter = adapterFactory.forAuthority(authorityRef);

        // connector-side validate (v2 → /validate; v3 → no-op)
        adapter.validateRevokeAttributes(authorityRef, attributes);

        // version-aware definitions
        List<BaseAttribute> definitions = adapter.listRevokeAttributes(authorityRef, raProfile);

        // local structural validation against definitions (both versions)
        attributeEngine.validateUpdateDataAttributes(authorityRef.getConnectorUuid(), AttributeOperation.CERTIFICATE_REVOKE, definitions, attributes);
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

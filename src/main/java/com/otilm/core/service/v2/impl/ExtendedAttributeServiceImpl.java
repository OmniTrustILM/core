package com.otilm.core.service.v2.impl;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.v2.ExtendedAttributeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("extendedAcmeServiceImpl")
public class ExtendedAttributeServiceImpl implements ExtendedAttributeService {

    private ConnectorRepository connectorRepository;

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
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
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);
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

        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(authorityRef);
        return adapter.validateIssueAttributes(authorityRef, attributes);
    }

    @Override
    public void mergeAndValidateIssueAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        if (raProfile.getAuthorityInstanceReference().getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }
        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());

        // validate first by connector
        if (attributes == null) {
            attributes = new ArrayList<>();
        }
        adapter.validateIssueAttributes(raProfile.getAuthorityInstanceReference(), attributes);

        // get definitions from connector
        List<BaseAttribute> definitions = adapter.listIssueAttributes(raProfile.getAuthorityInstanceReference(), raProfile);

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
        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
        return adapter.listRevokeAttributes(authorityRef, raProfile);
    }

    @Override
    public boolean validateRevokeCertificateAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);
        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
        return adapter.validateRevokeAttributes(authorityRef, attributes);
    }

    @Override
    public void mergeAndValidateRevokeAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        if (raProfile.getAuthorityInstanceReference().getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }
        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());

        // validate first by connector
        if (attributes == null) {
            attributes = new ArrayList<>();
        }
        adapter.validateRevokeAttributes(raProfile.getAuthorityInstanceReference(), attributes);

        // get definitions from connector
        List<BaseAttribute> definitions = adapter.listRevokeAttributes(raProfile.getAuthorityInstanceReference(), raProfile);

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

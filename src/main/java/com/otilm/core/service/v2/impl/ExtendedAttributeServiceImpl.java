package com.otilm.core.service.v2.impl;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.RegisterCapability;
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

    private ConnectorCapabilityService capabilityService;

    @Autowired
    public void setCapabilityService(ConnectorCapabilityService capabilityService) {
        this.capabilityService = capabilityService;
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
    public void validateIssueCertificateAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);

        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(authorityRef);
        adapter.validateIssueAttributes(authorityRef, attributes);
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
    public List<BaseAttribute> listRegisterCertificateAttributes(RaProfile raProfile) throws ConnectorException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        // No legacy-connector check here (unlike issue/revoke): registration is a v3-only capability, so a legacy
        // or v2 authority simply routes to a non-RegisterCapability adapter and the guard below returns an empty
        // set — uniform "no register support" behaviour rather than a v2-framed 404.
        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(authorityRef);
        if (adapter instanceof RegisterCapability registerCapability
                && capabilityService.supports(authorityRef, FeatureFlag.CERTIFICATE_REGISTRATION)) {
            return registerCapability.listRegisterAttributes(authorityRef, raProfile);
        }
        return List.of();
    }

    @Override
    public void mergeAndValidateRegisterAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        if (authorityRef.getConnector() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Authority is not available / deleted"));
        }
        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(authorityRef);
        // Registration is v3-only; a non-register-capable authority carries no register attributes to validate.
        if (!(adapter instanceof RegisterCapability registerCapability)
                || !capabilityService.supports(authorityRef, FeatureFlag.CERTIFICATE_REGISTRATION)) {
            return;
        }
        if (attributes == null) {
            attributes = new ArrayList<>();
        }
        // v3 has no connector-side validate; materialize the register schema and validate structurally via the engine.
        List<BaseAttribute> definitions = registerCapability.listRegisterAttributes(authorityRef, raProfile);
        attributeEngine.validateUpdateDataAttributes(authorityRef.getConnectorUuid(), AttributeOperation.CERTIFICATE_REGISTER, definitions, attributes);
    }

    @Override
    public void validateRevokeCertificateAttributes(RaProfile raProfile, List<RequestAttribute> attributes) throws ConnectorException, ValidationException, NotFoundException {
        var authorityRef = raProfile.getAuthorityInstanceReference();
        var connector = authorityRef.getConnector();
        if (connector == null) {
            throw new NotFoundException("Connector of the Authority is not available / deleted");
        }
        validateLegacyConnector(connector);
        AuthorityProviderAdapter adapter = authorityProviderAdapterFactory.forAuthority(raProfile.getAuthorityInstanceReference());
        adapter.validateRevokeAttributes(authorityRef, attributes);
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

package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.repository.RaProfileProtocolAttributeRepository;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.est.EstProfileReferenceResolver;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.Base64;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Builds the issue requests that EST hands to the platform: the CSR of the client and the issue attributes that the
 * route names.
 */
@Component
public class EstIssueRequests {

    private final AttributeEngine attributeEngine;
    private final RaProfileProtocolAttributeRepository protocolAttributeRepository;

    public EstIssueRequests(AttributeEngine attributeEngine,
            RaProfileProtocolAttributeRepository protocolAttributeRepository) {
        this.attributeEngine = attributeEngine;
        this.protocolAttributeRepository = protocolAttributeRepository;
    }

    /**
     * @param route the route of the request
     * @param csr the request of the client
     * @return the request that issues a new certificate
     */
    public ClientCertificateIssueRequestDto newRequest(EstRoute route, Pkcs10CertificateRequest csr) {
        ClientCertificateIssueRequestDto request = new ClientCertificateIssueRequestDto();
        request.setRequest(Base64.getEncoder().encodeToString(csr.getEncoded()));
        request.setFormat(CertificateRequestFormat.PKCS10);
        request.setAttributes(issueAttributes(route));
        return request;
    }

    /**
     * @param route the route of the request
     * @param csr the request of the client
     * @param authorizationSecret the challenge of the registration that the request completes
     * @return the request that issues the certificate of a registration
     */
    public ClientCertificateIssueRequestDto completionRequest(EstRoute route, Pkcs10CertificateRequest csr,
            @Sensitive String authorizationSecret) {
        ClientCertificateIssueRequestDto request = newRequest(route, csr);
        request.setAuthorizationSecret(authorizationSecret);
        return request;
    }

    /**
     * @param route the route of the request
     * @return the issue attributes of the EST Profile, or of the EST activation of the RA Profile when the label named
     * the RA Profile, which are read by query, as the RA Profile of the route holds them only in a lazy association
     */
    public List<RequestAttribute> issueAttributes(EstRoute route) {
        if (route.raProfileRoute()) {
            String serialized = protocolAttributeRepository
                    .findEstIssueCertificateAttributesByRaProfileUuid(route.raProfile().getUuid())
                    .orElse(null);
            return AttributeDefinitionUtils
                    .getClientAttributes(AttributeDefinitionUtils.deserialize(serialized, BaseAttribute.class));
        }
        return attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.EST_PROFILE, route.estProfile().getUuid())
                        .connector(EstProfileReferenceResolver.issueConnectorUuid(route.raProfile()))
                        .operation(AttributeOperation.CERTIFICATE_ISSUE)
                        .build());
    }
}

package com.otilm.core.security.authz;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.config.OpaSecuredAnnotationMetadataExtractor;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.AttributeRelation;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.AttributeRelationRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.ComplianceExternalService;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authorization.AuthorizationDeniedException;

import java.util.List;
import java.util.UUID;

/**
 * End-to-end tests for the {@link ExternalAuthorizationDynamic} annotation exercised through the real Spring
 * AOP stack: the {@code dynamicAuthorizationManagerBeforeMethodInterception} advisor wired in {@code MethodSecurityConfig},
 * the {@link ExternalMethodAuthorizationManager}, and {@link OpaSecuredAnnotationMetadataExtractor}.
 */
class ExternalAuthorizationDynamicIntegrationTest extends BaseSpringBootTest {

    @Autowired
    private ResourceExternalService resourceService;

    @Autowired
    private ComplianceExternalService complianceService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private AttributeRelationRepository attributeRelationRepository;

    @Test
    void deniesWhenOpaRejectsResolvedResourceAndAnnotationAction() {
        denyResourceAction(Resource.CERTIFICATE, ResourceAction.UPDATE);

        List<BaseAttributeContentV3<?>> content = List.of(new StringAttributeContentV3("value"));
        SecuredResource securedResource = SecuredResource.fromResource(Resource.CERTIFICATE);
        SecuredUUID objectUuid = SecuredUUID.fromUUID(UUID.randomUUID());
        UUID attributeUuid = UUID.randomUUID();
        Assertions.assertThrows(AuthorizationDeniedException.class, () -> resourceService.updateAttributeContentForObject(
                securedResource, objectUuid, attributeUuid, content));
    }

    @Test
    void resolvesResourceFromArgumentSoOtherResourceStaysAuthorized() throws NotFoundException, AttributeException {
        Certificate certificate = persistCertificate();
        UUID attributeUuid = persistCertificateCustomAttribute();
        denyResourceAction(Resource.ATTRIBUTE, ResourceAction.UPDATE);

        List<BaseAttributeContentV3<?>> content = List.of(new StringAttributeContentV3("value"));
        List<ResponseAttribute> updated = resourceService.updateAttributeContentForObject(
                SecuredResource.fromResource(Resource.CERTIFICATE),
                SecuredUUID.fromUUID(certificate.getUuid()),
                attributeUuid,
                content);

        Assertions.assertEquals("value",
                ((ResponseAttributeV3) updated.getFirst()).getContent().getFirst().getData(),
                "CERTIFICATE update must run to completion, proving the resolved resource was authorized");
    }

    /**
     * On a method that takes both a bare {@link Resource} (data, used for repository dispatch) and a
     * {@link SecuredResource} (the auth subject), the interceptor must authorize against the SecuredResource.
     */
    @Test
    void authorizesAgainstSecuredResourceNotBareResourceArgument() {
        denyResourceAction(Resource.SECRET, ResourceAction.DETAIL);

        SecuredResource securedResource = SecuredResource.fromResource(Resource.SECRET);
        UUID objectUuid = UUID.randomUUID();
        Assertions.assertThrows(AuthorizationDeniedException.class, () -> complianceService.getComplianceCheckResult(
                securedResource, null, Resource.CERTIFICATE, objectUuid));
    }

    private void denyResourceAction(Resource resource, ResourceAction action) {
        Mockito.when(opaClient.checkResourceAccess(Mockito.any(),
                        Mockito.argThat(req -> isRequestFor(req, resource, action)), Mockito.any(), Mockito.any()))
                .thenReturn(OpaResourceAccessResult.unauthorized());
    }

    private static boolean isRequestFor(OpaRequestedResource requestedResource, Resource resource, ResourceAction action) {
        return requestedResource != null && requestedResource.getProperties() != null
                && resource.getCode().equals(requestedResource.getProperties().get("name"))
                && action.getCode().equals(requestedResource.getProperties().get("action"));
    }

    private Certificate persistCertificate() {
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("123456");
        certificateContent = certificateContentRepository.save(certificateContent);

        Certificate certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCertificate");
        certificate.setSerialNumber("123456789");
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        return certificateRepository.save(certificate);
    }

    private UUID persistCertificateCustomAttribute() {
        UUID attributeUuid = UUID.fromString("f1982dfe-2523-45cf-9bfe-034ff1659369");

        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(attributeUuid.toString());
        attribute.setName("testAttribute");
        attribute.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setRequired(true);
        attribute.setProperties(properties);

        AttributeDefinition definition = new AttributeDefinition();
        definition.setUuid(attributeUuid);
        definition.setName("testAttribute");
        definition.setAttributeUuid(attributeUuid);
        definition.setContentType(AttributeContentType.STRING);
        definition.setLabel("testAttributeLabel");
        definition.setType(AttributeType.CUSTOM);
        definition.setDefinition(attribute);
        definition.setEnabled(true);
        definition.setVersion(3);
        attributeDefinitionRepository.save(definition);

        AttributeRelation relation = new AttributeRelation();
        relation.setResource(Resource.CERTIFICATE);
        relation.setAttributeDefinitionUuid(definition.getUuid());
        attributeRelationRepository.save(relation);

        return attributeUuid;
    }
}

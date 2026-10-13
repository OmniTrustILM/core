package com.otilm.core.integration.attribute;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Replacing an object's custom attribute content with a value the definition rejects must leave the stored value in
 * place: the rejection is a checked exception, so nothing rolls a delete back.
 */
class CustomAttributeContentReplaceITest extends BaseSpringBootTest {

    private static final String ATTRIBUTE_NAME = "pillar";

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private ResourceExternalService resourceService;
    @Autowired
    private CertificateRepository certificateRepository;

    private UUID certificateUuid;
    private UUID definitionUuid;

    @BeforeEach
    void setUp() throws AttributeException, NotFoundException {
        certificateUuid = certificateRepository.save(new Certificate()).getUuid();

        CustomAttributeV3 pillar = new CustomAttributeV3();
        pillar.setUuid(UUID.randomUUID().toString());
        pillar.setName(ATTRIBUTE_NAME);
        pillar.setType(AttributeType.CUSTOM);
        pillar.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Pillar");
        properties.setList(true);
        properties.setExtensibleList(false);
        pillar.setProperties(properties);
        pillar.setContent(List.of(new StringAttributeContentV3("Retail"), new StringAttributeContentV3("Corporate")));
        definitionUuid = attributeEngine
                .updateCustomAttributeDefinition(pillar, List.of(Resource.CERTIFICATE))
                .getUuid();

        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, definitionUuid, null,
                        List.of(new StringAttributeContentV3("Retail")));
    }

    @Test
    void aValueOutsideThePredefinedListKeepsTheStoredOne() {
        List<BaseAttributeContentV3<?>> rejected = List.of(new StringAttributeContentV3("Unknown"));
        SecuredResource certificates = SecuredResource.fromResource(Resource.CERTIFICATE);
        SecuredUUID certificate = SecuredUUID.fromUUID(certificateUuid);

        Assertions
                .assertThrows(AttributeException.class, () -> resourceService
                        .updateAttributeContentForObject(certificates, certificate, definitionUuid, rejected));

        Assertions.assertEquals(List.of("Retail"), storedValues());
    }

    @Test
    void anAcceptedValueStillReplacesTheStoredOne() throws AttributeException, NotFoundException {
        resourceService
                .updateAttributeContentForObject(SecuredResource.fromResource(Resource.CERTIFICATE),
                        SecuredUUID.fromUUID(certificateUuid), definitionUuid,
                        List.of(new StringAttributeContentV3("Corporate")));

        Assertions.assertEquals(List.of("Corporate"), storedValues());
    }

    @Test
    void emptyContentStillClearsTheStoredValue() throws AttributeException, NotFoundException {
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, definitionUuid, null,
                        List.of());

        Assertions.assertEquals(List.of(), storedValues());
    }

    private List<String> storedValues() {
        return attributeEngine
                .getObjectCustomAttributesContent(Resource.CERTIFICATE, certificateUuid)
                .stream()
                .filter(attribute -> ATTRIBUTE_NAME.equals(attribute.getName()))
                .flatMap(attribute -> ((ResponseAttributeV3) attribute).getContent().stream())
                .map(content -> String.valueOf(content.getData()))
                .toList();
    }
}

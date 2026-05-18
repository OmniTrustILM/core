package com.czertainly.core.service;


import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.cmp.CmpProfileEditRequestDto;
import com.czertainly.api.model.client.cmp.CmpProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.cmp.CmpProfileDetailDto;
import com.czertainly.api.model.core.cmp.CmpProfileDto;
import com.czertainly.api.model.core.cmp.CmpProfileVariant;
import com.czertainly.api.model.core.cmp.ProtectionMethod;
import com.czertainly.api.model.core.protocol.ProtocolCertificateAssociationsRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.ProtocolCertificateAssociations;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.dao.repository.cmp.CmpProfileRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

class CmpProfileServiceTest extends BaseSpringBootTest {

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private CmpProfileService cmpProfileService;

    @Autowired
    private CmpProfileRepository cmpProfileRepository;

    @MockitoSpyBean
    private CmpProfileRepository cmpProfileRepositorySpy;

    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private ProtocolCertificateAssociationsRepository protocolCertificateAssociationsRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    private CmpProfile cmpProfile;
    private RequestAttributeV3 domainAttrRequestAttribute;

    @BeforeEach
    public void setUp() throws AttributeException {
        CustomAttributeV3 domainAttr = new CustomAttributeV3();
        domainAttr.setUuid(UUID.randomUUID().toString());
        domainAttr.setName("domain");
        domainAttr.setType(AttributeType.CUSTOM);
        domainAttr.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties customProps = new CustomAttributeProperties();
        customProps.setLabel("Domain of resource");
        domainAttr.setProperties(customProps);
        attributeEngine.updateCustomAttributeDefinition(domainAttr, List.of(Resource.CERTIFICATE));

        domainAttrRequestAttribute = new RequestAttributeV3();
        domainAttrRequestAttribute.setUuid(UUID.fromString(domainAttr.getUuid()));
        domainAttrRequestAttribute.setName(domainAttr.getName());
        domainAttrRequestAttribute.setContentType(domainAttr.getContentType());
        domainAttrRequestAttribute.setContent(List.of(new StringAttributeContentV3("test")));

        cmpProfile = new CmpProfile();
        cmpProfile.setDescription("sample description");
        cmpProfile.setName("sameName");
        cmpProfile.setEnabled(true);
        ProtocolCertificateAssociations protocolCertificateAssociations = new ProtocolCertificateAssociations();
        protocolCertificateAssociations.setOwnerUuid(UUID.randomUUID());
        protocolCertificateAssociations.setGroupUuids(List.of(UUID.randomUUID()));
        protocolCertificateAssociations.setCustomAttributes(List.of(domainAttrRequestAttribute));
        protocolCertificateAssociationsRepository.save(protocolCertificateAssociations);
        cmpProfile.setCertificateAssociations(protocolCertificateAssociations);
        cmpProfile.setCertificateAssociationsUuid(protocolCertificateAssociations.getUuid());
        cmpProfileRepository.save(cmpProfile);
    }

    @Test
    void testGetCmpProfileByUuid() throws NotFoundException {
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("123456");
        certificateContent = certificateContentRepository.save(certificateContent);

        Certificate certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCertificate");
        certificate.setSerialNumber("123456789");
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRepository.save(certificate);

        cmpProfile.setEnabled(true);
        cmpProfile.setSigningCertificateUuid(certificate.getUuid());
        CmpProfileDetailDto dto = cmpProfileService.getCmpProfile(cmpProfile.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(cmpProfile.getUuid().toString(), dto.getUuid());
        Assertions.assertNotNull(dto.getCertificateAssociations());
        Assertions.assertEquals(cmpProfile.getCertificateAssociations().getOwnerUuid(), dto.getCertificateAssociations().getOwnerUuid());
        Assertions.assertEquals(cmpProfile.getCertificateAssociations().getGroupUuids(), dto.getCertificateAssociations().getGroupUuids());
        Assertions.assertEquals(cmpProfile.getCertificateAssociations().getCustomAttributes().size(), dto.getCertificateAssociations().getCustomAttributes().size());

        certificateService.deleteCertificate(certificate.getSecuredUuid());
        Assertions.assertDoesNotThrow(() -> cmpProfileService.getCmpProfile(cmpProfile.getSecuredUuid()));
    }

    @Test
    void testAddCmpProfile() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        CmpProfileRequestDto request = new CmpProfileRequestDto();
        request.setName("Test");
        request.setDescription("sample");
        request.setVariant(CmpProfileVariant.V2);
        request.setRequestProtectionMethod(ProtectionMethod.SHARED_SECRET);
        request.setResponseProtectionMethod(ProtectionMethod.SHARED_SECRET);
        request.setSharedSecret("secret");

        CmpProfileDto dto = cmpProfileService.createCmpProfile(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertNotNull(dto.getUuid());
        Assertions.assertEquals(request.getDescription(), dto.getDescription());

        request.setName("Test2");
        ProtocolCertificateAssociationsRequestDto certificateAssociations = new ProtocolCertificateAssociationsRequestDto();
        certificateAssociations.setOwnerUuid(UUID.randomUUID());
        certificateAssociations.setGroupUuids(List.of(UUID.randomUUID()));
        certificateAssociations.setCustomAttributes(List.of(domainAttrRequestAttribute));
        request.setCertificateAssociations(certificateAssociations);
        dto = cmpProfileService.createCmpProfile(request);
        CmpProfile cmpProfileNew = cmpProfileRepository.findByUuid(UUID.fromString(dto.getUuid())).orElse(null);
        Assertions.assertNotNull(cmpProfileNew);
        Assertions.assertNotNull(cmpProfileNew.getCertificateAssociations());

    }

    @Test
    void testEditCmpProfile() throws ConnectorException, AttributeException, NotFoundException {

        cmpProfile.setEnabled(false);
        cmpProfileRepository.save(cmpProfile);

        CmpProfileEditRequestDto request = new CmpProfileEditRequestDto();
        request.setDescription("sample");
        request.setVariant(CmpProfileVariant.V2);
        request.setRequestProtectionMethod(ProtectionMethod.SHARED_SECRET);
        request.setResponseProtectionMethod(ProtectionMethod.SHARED_SECRET);
        request.setSharedSecret("secret");


        CmpProfileDetailDto dto = cmpProfileService.editCmpProfile(cmpProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
        Assertions.assertNull(dto.getCertificateAssociations());

        ProtocolCertificateAssociationsRequestDto protocolCertificateAssociationsDto = new ProtocolCertificateAssociationsRequestDto();
        protocolCertificateAssociationsDto.setOwnerUuid(UUID.randomUUID());
        request.setCertificateAssociations(protocolCertificateAssociationsDto);
        dto = cmpProfileService.editCmpProfile(cmpProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getCertificateAssociations());
    }

    @Test
    void testRemoveCmpProfile() throws NotFoundException {
        UUID certificateAssociationsUuid = cmpProfile.getCertificateAssociationsUuid();
        cmpProfileService.deleteCmpProfile(cmpProfile.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> cmpProfileService.getCmpProfile(cmpProfile.getSecuredUuid()));
        Assertions.assertTrue(protocolCertificateAssociationsRepository.findByUuid(SecuredUUID.fromUUID(certificateAssociationsUuid)).isEmpty());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = cmpProfileService.getResourceObjectInternal(cmpProfile.getUuid());
        Assertions.assertEquals(cmpProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(cmpProfile.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = cmpProfileService.getResourceObjectExternal(cmpProfile.getSecuredUuid());
        Assertions.assertEquals(cmpProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(cmpProfile.getName(), nameAndUuidDto.getName());
    }

    @Test
    void testBulkDeleteCmpProfile_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = cmpProfileService.bulkDeleteCmpProfile(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkForceRemoveCmpProfiles_nonExistentUuid_returnsErrorMessage() throws NotFoundException, ValidationException {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = cmpProfileService.bulkForceRemoveCmpProfiles(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDeleteCmpProfile_withAssociatedRaProfile_returnsErrorWithEntityName() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("linkedRaProfile");
        raProfile.setCmpProfile(cmpProfile);
        raProfileRepository.save(raProfile);

        List<BulkActionMessageDto> messages = cmpProfileService.bulkDeleteCmpProfile(
                List.of(cmpProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(cmpProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(cmpProfile.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkForceRemoveCmpProfiles_deleteFailure_returnsErrorWithEntityName() throws NotFoundException, ValidationException {
        doThrow(new RuntimeException("DB delete error"))
                .when(cmpProfileRepositorySpy).delete(any());

        List<BulkActionMessageDto> messages = cmpProfileService.bulkForceRemoveCmpProfiles(
                List.of(cmpProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(cmpProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(cmpProfile.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }
}

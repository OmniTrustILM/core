package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.scep.ScepProfileEditRequestDto;
import com.czertainly.api.model.client.scep.ScepProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.api.model.core.protocol.ProtocolCertificateAssociationsRequestDto;
import com.czertainly.api.model.core.scep.ScepProfileDetailDto;
import com.czertainly.api.model.core.scep.ScepProfileDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.scep.ScepProfileRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.model.SecuredItem;
import com.czertainly.core.service.model.SecuredList;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

class ScepProfileServiceTest extends BaseSpringBootTest {
    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private ScepProfileService scepProfileService;

    @Autowired
    private ScepProfileRepository scepProfileRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private ProtocolCertificateAssociationsRepository protocolCertificateAssociationsRepository;

    @MockitoSpyBean
    private RaProfileService raProfileService;

    @MockitoSpyBean
    private ScepProfileRepository scepProfileRepositorySpy;

    private ScepProfile scepProfile;
    private Certificate certificate;
    private RequestAttributeV3 domainAttrRequestAttribute;

    @BeforeEach
    void setUp() throws AttributeException {
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

        Connector connector = new Connector();
        connector.setUrl("http://localhost:3665");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        TokenInstanceReference tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReferenceRepository.save(tokenInstanceReference);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("profile1");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setDescription("sample description");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("testInstance");
        tokenProfileRepository.save(tokenProfile);

        CryptographicKey key = new CryptographicKey();
        key.setName("testKey1");
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstanceReference);
        key.setDescription("initial description");
        cryptographicKeyRepository.save(key);

        CryptographicKeyItem content = new CryptographicKeyItem();
        content.setLength(1024);
        content.setKey(key);
        content.setKeyUuid(key.getUuid());
        content.setType(KeyType.PRIVATE_KEY);
        content.setKeyData("some/encrypted/data");
        content.setFormat(KeyFormat.PRKI);
        content.setState(KeyState.ACTIVE);
        content.setEnabled(true);
        content.setKeyAlgorithm(KeyAlgorithm.RSA);
        content.setUsage(List.of(KeyUsage.DECRYPT, KeyUsage.SIGN));
        cryptographicKeyItemRepository.save(content);

        CryptographicKeyItem content1 = new CryptographicKeyItem();
        content1.setLength(1024);
        content1.setKey(key);
        content1.setKeyUuid(key.getUuid());
        content1.setType(KeyType.PUBLIC_KEY);
        content1.setKeyData("some/encrypted/data");
        content1.setFormat(KeyFormat.SPKI);
        content1.setState(KeyState.ACTIVE);
        content1.setEnabled(true);
        content1.setKeyAlgorithm(KeyAlgorithm.RSA);
        content1.setUsage(List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY));
        cryptographicKeyItemRepository.save(content1);

        content.setKeyReferenceUuid(content.getUuid());
        content1.setKeyReferenceUuid(content1.getUuid());
        cryptographicKeyItemRepository.save(content);
        cryptographicKeyItemRepository.save(content1);

        Set<CryptographicKeyItem> items = new HashSet<>();
        items.add(content1);
        items.add(content);
        key.setItems(items);
        cryptographicKeyRepository.save(key);

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("123456");
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCertificate");
        certificate.setSerialNumber("123456789");
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setKey(key);
        certificate = certificateRepository.save(certificate);

        scepProfile = new ScepProfile();
        scepProfile.setDescription("sample description");
        scepProfile.setName("sameName");
        scepProfile.setRequireManualApproval(false);
        scepProfile.setChallengePassword("test123");
        scepProfile.setIncludeCaCertificate(true);
        scepProfile.setEnabled(false);
        scepProfile.setCaCertificate(certificate);
        ProtocolCertificateAssociations protocolCertificateAssociations = new ProtocolCertificateAssociations();
        protocolCertificateAssociations.setOwnerUuid(UUID.randomUUID());
        protocolCertificateAssociations.setGroupUuids(List.of(UUID.randomUUID()));
        protocolCertificateAssociations.setCustomAttributes(List.of(domainAttrRequestAttribute));
        protocolCertificateAssociationsRepository.save(protocolCertificateAssociations);
        scepProfile.setCertificateAssociations(protocolCertificateAssociations);
        scepProfile.setCertificateAssociationsUuid(protocolCertificateAssociations.getUuid());
        scepProfileRepository.save(scepProfile);
    }

    @Test
    void testListScepProfiles() {
        scepProfile.setEnabled(true);
        scepProfileRepository.save(scepProfile);
        List<ScepProfileDto> scepProfiles = scepProfileService.listScepProfile(SecurityFilter.create());
        Assertions.assertNotNull(scepProfiles);
        Assertions.assertFalse(scepProfiles.isEmpty());
        Assertions.assertEquals(1, scepProfiles.size());
        Assertions.assertEquals(scepProfile.getUuid().toString(), scepProfiles.get(0).getUuid());
    }

    @Test
    void testGetScepProfileByUuid() throws NotFoundException {
        scepProfile.setEnabled(true);
        scepProfile.setCaCertificateUuid(certificate.getUuid());
        scepProfileRepository.save(scepProfile);
        SecuredUUID scepProfileSecuredUuid = scepProfile.getSecuredUuid();
        ScepProfileDetailDto dto = scepProfileService.getScepProfile(scepProfileSecuredUuid);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(scepProfile.getUuid().toString(), dto.getUuid());
        Assertions.assertNotNull(dto.getCertificateAssociations());

        certificateService.deleteCertificate(certificate.getSecuredUuid());
        Assertions.assertDoesNotThrow(() -> scepProfileService.getScepProfile(scepProfileSecuredUuid));
    }

    @Test
    void testGetScepProfileByUuid_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> scepProfileService.getScepProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddScepProfile() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {

        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("Test");
        request.setDescription("sample");
        request.setChallengePassword("1234");
        request.setCaCertificateUuid(certificate.getUuid().toString());
        certificate.setArchived(true);
        certificateRepository.save(certificate);
        Assertions.assertThrows(ValidationException.class, () -> scepProfileService.createScepProfile(request));
        certificate.setArchived(false);
        certificate.setState(CertificateState.FAILED);
        certificateRepository.save(certificate);
        Assertions.assertThrows(ValidationException.class, () -> scepProfileService.createScepProfile(request));

        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.EXPIRED);
        certificateRepository.save(certificate);
        Assertions.assertThrows(ValidationException.class, () -> scepProfileService.createScepProfile(request));

        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificateRepository.save(certificate);


        ScepProfileDetailDto dto = scepProfileService.createScepProfile(request);
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
        dto = scepProfileService.createScepProfile(request);
        ScepProfile scepProfileNew = scepProfileRepository.findByUuid(UUID.fromString(dto.getUuid())).orElse(null);
        Assertions.assertNotNull(scepProfileNew);
        Assertions.assertNotNull(scepProfileNew.getCertificateAssociations());
    }

    @Test
    void testAddScepProfile_validationFail() {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> scepProfileService.createScepProfile(request));
    }

    @Test
    void testAddScepProfile_alreadyExist() {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("sameName");

        Assertions.assertThrows(AlreadyExistException.class, () -> scepProfileService.createScepProfile(request));
    }

    @Test
    void testEditScepProfile() throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setEnabled(false);
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setDescription("sample11");
        request.setCaCertificateUuid(certificate.getUuid().toString());

        ScepProfileDetailDto dto = scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
        Assertions.assertNull(dto.getCertificateAssociations());

        ProtocolCertificateAssociationsRequestDto protocolCertificateAssociationsDto = new ProtocolCertificateAssociationsRequestDto();
        protocolCertificateAssociationsDto.setOwnerUuid(UUID.randomUUID());
        request.setCertificateAssociations(protocolCertificateAssociationsDto);
        dto = scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getCertificateAssociations());
    }

    @Test
    void testEditScepProfile_validationFail() {
        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> scepProfileService.editScepProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request));
    }

    @Test
    void testRemoveScepProfile() throws NotFoundException {
        scepProfileService.deleteScepProfile(scepProfile.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> scepProfileService.getScepProfile(scepProfile.getSecuredUuid()));
    }

    @Test
    void testRemoveScepProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> scepProfileService.getScepProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testEnableScepProfile() throws NotFoundException {
        scepProfileService.enableScepProfile(scepProfile.getSecuredUuid());
        Assertions.assertTrue(scepProfileService.getScepProfile(scepProfile.getSecuredUuid()).isEnabled());
    }

    @Test
    void testEnableScepProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> scepProfileService.enableScepProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testDisableScepProfile() throws NotFoundException {
        scepProfile.setEnabled(true);
        scepProfileRepository.save(scepProfile);
        scepProfileService.disableScepProfile(scepProfile.getSecuredUuid());
        Assertions.assertFalse(scepProfileService.getScepProfile(scepProfile.getSecuredUuid()).isEnabled());
    }

    @Test
    void testDisableScepProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> scepProfileService.disableScepProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() {
        scepProfileService.bulkDeleteScepProfile(List.of(scepProfile.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> scepProfileService.getScepProfile(scepProfile.getSecuredUuid()));
    }

    @Test
    void testBulkEnable() throws NotFoundException {
        scepProfile.setEnabled(true);
        scepProfileRepository.save(scepProfile);
        scepProfileService.bulkEnableScepProfile(List.of(scepProfile.getSecuredUuid()));
        Assertions.assertTrue(scepProfileService.getScepProfile(scepProfile.getSecuredUuid()).isEnabled());
    }

    @Test
    void testBulkDisable() throws NotFoundException {
        scepProfileService.bulkDisableScepProfile(List.of(scepProfile.getSecuredUuid()));
        Assertions.assertFalse(scepProfileService.getScepProfile(scepProfile.getSecuredUuid()).isEnabled());
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = scepProfileService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = scepProfileService.getResourceObjectInternal(scepProfile.getUuid());
        Assertions.assertEquals(scepProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(scepProfile.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = scepProfileService.getResourceObjectExternal(scepProfile.getSecuredUuid());
        Assertions.assertEquals(scepProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(scepProfile.getName(), nameAndUuidDto.getName());
    }

    @Test
    void testBulkDeleteScepProfile_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = scepProfileService.bulkDeleteScepProfile(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkForceRemoveScepProfiles_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = scepProfileService.bulkForceRemoveScepProfiles(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDeleteScepProfile_withAssociatedRaProfile_returnsErrorWithEntityName() {
        RaProfile linkedRaProfile = new RaProfile();
        linkedRaProfile.setName("linkedRaProfile");
        SecuredList<RaProfile> nonEmptyList = new SecuredList<>(List.of(new SecuredItem<>(linkedRaProfile, true)));
        Mockito.doReturn(nonEmptyList)
                .when(raProfileService)
                .listRaProfilesAssociatedWithScepProfile(scepProfile.getUuid().toString(), SecurityFilter.create());

        List<BulkActionMessageDto> messages = scepProfileService.bulkDeleteScepProfile(
                List.of(scepProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(scepProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(scepProfile.getName(), messages.getFirst().getName());
        Assertions.assertTrue(messages.getFirst().getMessage().contains("Dependent SCEP Profiles"));
    }

    @Test
    void testBulkForceRemoveScepProfiles_deleteFailure_returnsErrorWithEntityName() {
        doThrow(new RuntimeException("DB delete error"))
                .when(scepProfileRepositorySpy).delete(any());

        List<BulkActionMessageDto> messages = scepProfileService.bulkForceRemoveScepProfiles(
                List.of(scepProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(scepProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(scepProfile.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }
}

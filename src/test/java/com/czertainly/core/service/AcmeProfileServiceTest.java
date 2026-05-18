package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.acme.AcmeProfileEditRequestDto;
import com.czertainly.api.model.client.acme.AcmeProfileRequestDto;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.core.acme.AccountStatus;
import com.czertainly.api.model.core.acme.AcmeProfileDto;
import com.czertainly.api.model.core.acme.AcmeProfileListDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.protocol.ProtocolCertificateAssociationsRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.ProtocolCertificateAssociations;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.acme.AcmeAccount;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.acme.AcmeAccountRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
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

class AcmeProfileServiceTest extends BaseSpringBootTest {

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private AcmeProfileService acmeProfileService;

    @Autowired
    private AcmeProfileRepository acmeProfileRepository;

    @MockitoSpyBean
    private AcmeProfileRepository acmeProfileRepositorySpy;

    @Autowired
    private ProtocolCertificateAssociationsRepository protocolCertificateAssociationsRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    ConnectorRepository connectorRepository;
    @Autowired
    private AcmeAccountRepository acmeAccountRepository;

    private AcmeProfile acmeProfile;
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


        acmeProfile = new AcmeProfile();
        acmeProfile.setWebsite("sample website");
        acmeProfile.setTermsOfServiceUrl("sample terms");
        acmeProfile.setValidity(30);
        acmeProfile.setRetryInterval(30);
        acmeProfile.setDescription("sample description");
        acmeProfile.setName("sameName");
        acmeProfile.setDnsResolverPort("53");
        acmeProfile.setDnsResolverIp("localhost");
        acmeProfile.setTermsOfServiceChangeUrl("change url");
        acmeProfile.setEnabled(false);
        ProtocolCertificateAssociations protocolCertificateAssociations = new ProtocolCertificateAssociations();
        protocolCertificateAssociations.setOwnerUuid(UUID.randomUUID());
        protocolCertificateAssociations.setGroupUuids(List.of(UUID.randomUUID()));
        protocolCertificateAssociations.setCustomAttributes(List.of(domainAttrRequestAttribute));
        protocolCertificateAssociationsRepository.save(protocolCertificateAssociations);
        acmeProfile.setCertificateAssociations(protocolCertificateAssociations);
        acmeProfile.setCertificateAssociationsUuid(protocolCertificateAssociations.getUuid());
        acmeProfileRepository.save(acmeProfile);
    }

    @Test
    void testListAcmeProfiles() {
        acmeProfile.setEnabled(true);
        acmeProfileRepository.save(acmeProfile);
        List<AcmeProfileListDto> acmeProfiles = acmeProfileService.listAcmeProfile(SecurityFilter.create());
        Assertions.assertNotNull(acmeProfiles);
        Assertions.assertFalse(acmeProfiles.isEmpty());
        Assertions.assertEquals(1, acmeProfiles.size());
        Assertions.assertEquals(acmeProfile.getUuid().toString(), acmeProfiles.get(0).getUuid());
    }

    @Test
    void testGetAcmeProfileByUuid() throws NotFoundException {
        acmeProfile.setEnabled(true);
        AcmeProfileDto dto = acmeProfileService.getAcmeProfile(acmeProfile.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(acmeProfile.getUuid().toString(), dto.getUuid());
        Assertions.assertNotNull(dto.getCertificateAssociations());
        Assertions.assertEquals(acmeProfile.getCertificateAssociations().getOwnerUuid(), dto.getCertificateAssociations().getOwnerUuid());
        Assertions.assertEquals(acmeProfile.getCertificateAssociations().getGroupUuids(), dto.getCertificateAssociations().getGroupUuids());
        Assertions.assertEquals(acmeProfile.getCertificateAssociations().getCustomAttributes().size(), dto.getCertificateAssociations().getCustomAttributes().size());
    }

    @Test
    void testGetAcmeProfileByUuid_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeProfileService.getAcmeProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddAcmeProfile() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {

        AcmeProfileRequestDto request = new AcmeProfileRequestDto();
        request.setName("Test");
        request.setDescription("sample");
        request.setDnsResolverIp("localhost");
        request.setDnsResolverPort("53");

        AcmeProfileDto dto = acmeProfileService.createAcmeProfile(request);
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
        dto = acmeProfileService.createAcmeProfile(request);
        AcmeProfile acmeProfileNew = acmeProfileRepository.findByUuid(UUID.fromString(dto.getUuid())).orElse(null);
        Assertions.assertNotNull(acmeProfileNew);
        Assertions.assertNotNull(acmeProfileNew.getCertificateAssociations());

    }

    @Test
    void testAddAcmeProfile_validationFail() {
        AcmeProfileRequestDto request = new AcmeProfileRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> acmeProfileService.createAcmeProfile(request));
    }

    @Test
    void testAddAcmeProfile_alreadyExist() {
        AcmeProfileRequestDto request = new AcmeProfileRequestDto();
        request.setName("sameName");

        Assertions.assertThrows(AlreadyExistException.class, () -> acmeProfileService.createAcmeProfile(request));
    }

    @Test
    void testEditAcmeProfile() throws ConnectorException, AttributeException, NotFoundException {

        acmeProfile.setEnabled(false);
        setUpOldConnector();
        acmeProfileRepository.save(acmeProfile);

        AcmeProfileEditRequestDto request = new AcmeProfileEditRequestDto();
        request.setDescription("sample");
        request.setDnsResolverIp("sample");
        request.setDnsResolverPort("32");

        AcmeProfileDto dto = acmeProfileService.editAcmeProfile(acmeProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
        Assertions.assertEquals(request.getDnsResolverIp(), dto.getDnsResolverIp());
        Assertions.assertNull(dto.getCertificateAssociations());

        ProtocolCertificateAssociationsRequestDto protocolCertificateAssociationsDto = new ProtocolCertificateAssociationsRequestDto();
        protocolCertificateAssociationsDto.setOwnerUuid(UUID.randomUUID());
        request.setCertificateAssociations(protocolCertificateAssociationsDto);
        dto = acmeProfileService.editAcmeProfile(acmeProfile.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getCertificateAssociations());
    }

    private void setUpOldConnector() {
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);
        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setConnectorUuid(connector.getUuid());
        authorityInstanceReferenceRepository.save(authorityInstanceReference);
        RaProfile raProfile = new RaProfile();
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfileRepository.save(raProfile);
        acmeProfile.setRaProfile(raProfile);
    }

    @Test
    void testEditAcmeProfile_validationFail() {
        AcmeProfileEditRequestDto request = new AcmeProfileEditRequestDto();
        Assertions.assertThrows(NotFoundException.class, () -> acmeProfileService.editAcmeProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request));
    }

    @Test
    void testRemoveAcmeProfile() throws NotFoundException {
        UUID certificateAssociationsUuid = acmeProfile.getCertificateAssociationsUuid();
        acmeProfileService.deleteAcmeProfile(acmeProfile.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> acmeProfileService.getAcmeProfile(acmeProfile.getSecuredUuid()));
        Assertions.assertTrue(protocolCertificateAssociationsRepository.findByUuid(SecuredUUID.fromUUID(certificateAssociationsUuid)).isEmpty());
    }

    @Test
    void testRemoveAcmeProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeProfileService.getAcmeProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testEnableAcmeProfile() throws NotFoundException {
        acmeProfileService.enableAcmeProfile(acmeProfile.getSecuredUuid());
        Assertions.assertEquals(true, acmeProfileService.getAcmeProfile(acmeProfile.getSecuredUuid()).isEnabled());
    }

    @Test
    void testEnableAcmeProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeProfileService.enableAcmeProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testDisableAcmeProfile() throws NotFoundException {
        acmeProfile.setEnabled(true);
        acmeProfileRepository.save(acmeProfile);
        acmeProfileService.disableAcmeProfile(acmeProfile.getSecuredUuid());
        Assertions.assertEquals(false, acmeProfileService.getAcmeProfile(acmeProfile.getSecuredUuid()).isEnabled());
    }

    @Test
    void testDisableAcmeProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class, () -> acmeProfileService.disableAcmeProfile(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testBulkRemove() {
        acmeProfileService.bulkDeleteAcmeProfile(List.of(acmeProfile.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> acmeProfileService.getAcmeProfile(acmeProfile.getSecuredUuid()));
    }

    @Test
    void testBulkEnable() throws NotFoundException {
        acmeProfile.setEnabled(true);
        acmeProfileRepository.save(acmeProfile);
        acmeProfileService.bulkEnableAcmeProfile(List.of(acmeProfile.getSecuredUuid()));
        Assertions.assertEquals(true, acmeProfileService.getAcmeProfile(acmeProfile.getSecuredUuid()).isEnabled());
    }

    @Test
    void testBulkDisable() throws NotFoundException {
        acmeProfileService.bulkDisableAcmeProfile(List.of(acmeProfile.getSecuredUuid()));
        Assertions.assertEquals(false, acmeProfileService.getAcmeProfile(acmeProfile.getSecuredUuid()).isEnabled());
    }

    @Test
    void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = acmeProfileService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = acmeProfileService.getResourceObjectInternal(acmeProfile.getUuid());
        Assertions.assertNotNull(nameAndUuidDto);
        Assertions.assertEquals(acmeProfile.getName(), nameAndUuidDto.getName());
        Assertions.assertEquals(acmeProfile.getUuid().toString(), nameAndUuidDto.getUuid());

        nameAndUuidDto = acmeProfileService.getResourceObjectExternal(acmeProfile.getSecuredUuid());
        Assertions.assertNotNull(nameAndUuidDto);
        Assertions.assertEquals(acmeProfile.getName(), nameAndUuidDto.getName());
        Assertions.assertEquals(acmeProfile.getUuid().toString(), nameAndUuidDto.getUuid());
    }

    @Test
    void testBulkForceRemove() {
        // Prepare
        AcmeProfile acmeProfile2 = new AcmeProfile();
        acmeProfile2.setName("acmeProfile2");
        acmeProfileRepository.save(acmeProfile2);

        RaProfile raProfile = new RaProfile();
        raProfile.setName("raProfile");
        raProfile.setAcmeProfile(acmeProfile2);
        raProfileRepository.save(raProfile);

        // Act
        List<BulkActionMessageDto> messages = acmeProfileService.bulkForceRemoveACMEProfiles(List.of(acmeProfile2.getSecuredUuid()));

        // Verify
        Assertions.assertTrue(messages.isEmpty());
        Assertions.assertThrows(NotFoundException.class, () -> acmeProfileService.getAcmeProfile(acmeProfile2.getSecuredUuid()));
        RaProfile updatedRaProfile = raProfileRepository.findByUuid(raProfile.getUuid()).orElseThrow();
        Assertions.assertNull(updatedRaProfile.getAcmeProfile());
    }

    @Test
    void testEditAcmeProfile_cannotSetRaProfileToNull_whenAccountsWithDefaultRaProfileExist() {
        // Prepare an ACME account with a default RA profile.
        setUpOldConnector();
        acmeProfileRepository.save(acmeProfile);

        AcmeAccount acmeAccount = new AcmeAccount();
        acmeAccount.setAccountId("test-account-id");
        acmeAccount.setPublicKey("test-public-key");
        acmeAccount.setDefaultRaProfile(true);
        acmeAccount.setEnabled(true);
        acmeAccount.setStatus(AccountStatus.VALID);
        acmeAccount.setTermsOfServiceAgreed(true);
        acmeAccount.setAcmeProfileUuid(acmeProfile.getUuid().toString());
        acmeAccount.setRaProfileUuid(acmeProfile.getRaProfile().getUuid().toString());
        acmeAccountRepository.save(acmeAccount);

        // Act
        AcmeProfileEditRequestDto request = new AcmeProfileEditRequestDto();
        request.setRaProfileUuid(null);
        SecuredUUID acmeProfileUuid = acmeProfile.getSecuredUuid();
        ValidationException exception = Assertions.assertThrows(ValidationException.class,
                () -> acmeProfileService.editAcmeProfile(acmeProfileUuid, request)
        );

        // Verify the error message
        Assertions.assertTrue(exception.getMessage().contains("Cannot remove the RA Profile"));
        Assertions.assertTrue(exception.getMessage().contains("because there are existing ACME accounts"));
    }

    @Test
    void testBulkDeleteAcmeProfile_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = acmeProfileService.bulkDeleteAcmeProfile(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkForceRemoveACMEProfiles_nonExistentUuid_returnsErrorMessage() {
        SecuredUUID nonExistent = SecuredUUID.fromUUID(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        List<BulkActionMessageDto> messages = acmeProfileService.bulkForceRemoveACMEProfiles(List.of(nonExistent));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals("00000000-0000-0000-0000-000000000001", messages.getFirst().getUuid());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkDeleteAcmeProfile_withAssociatedRaProfile_returnsErrorWithEntityName() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("linkedRaProfile");
        raProfile.setAcmeProfile(acmeProfile);
        raProfileRepository.save(raProfile);

        List<BulkActionMessageDto> messages = acmeProfileService.bulkDeleteAcmeProfile(
                List.of(acmeProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(acmeProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(acmeProfile.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }

    @Test
    void testBulkForceRemoveACMEProfiles_deleteFailure_returnsErrorWithEntityName() {
        doThrow(new RuntimeException("DB delete error"))
                .when(acmeProfileRepositorySpy).delete(any());

        List<BulkActionMessageDto> messages = acmeProfileService.bulkForceRemoveACMEProfiles(
                List.of(acmeProfile.getSecuredUuid()));

        Assertions.assertEquals(1, messages.size());
        Assertions.assertEquals(acmeProfile.getUuid().toString(), messages.getFirst().getUuid());
        Assertions.assertEquals(acmeProfile.getName(), messages.getFirst().getName());
        Assertions.assertNotNull(messages.getFirst().getMessage());
    }
}

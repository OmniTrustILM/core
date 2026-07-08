package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.scep.ScepProfileEditRequestDto;
import com.otilm.api.model.client.scep.ScepProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.protocol.ProtocolCertificateAssociationsRequestDto;
import com.otilm.api.model.core.scep.ScepProfileDetailDto;
import com.otilm.api.model.core.scep.ScepProfileDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.repository.*;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.intune.scepvalidation.IntuneConfigProperties;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.model.SecuredItem;
import com.otilm.core.service.model.SecuredList;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.*;
import java.util.stream.Stream;

class ScepProfileServiceTest extends BaseSpringBootTest {
    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private CertificateExternalService certificateService;

    @Autowired
    private ScepProfileExternalService scepProfileService;

    @Autowired
    private ScepProfileInternalService scepProfileInternalService;

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

    @Autowired
    private IntuneConfigProperties intuneConfigProperties;

    @MockitoSpyBean
    private RaProfileInternalService raProfileService;

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
    void testEditScepProfile_keepsSecretsWhenOmitted() throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setChallengePassword("originalChallenge");
        scepProfile.setIntuneEnabled(true);
        scepProfile.setIntuneTenant("tenant");
        scepProfile.setIntuneApplicationId("appId");
        scepProfile.setIntuneApplicationKey("originalKey");
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(true);
        request.setIntuneTenant("tenant");
        request.setIntuneApplicationId("appId");
        // challengePassword and intuneApplicationKey omitted (form does not prefill secrets)

        scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);

        ScepProfile updated = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertEquals("originalChallenge", updated.getChallengePassword());
        Assertions.assertEquals("originalKey", updated.getIntuneApplicationKey());
    }

    static Stream<Arguments> challengePasswordEditCases() {
        return Stream.of(
                //         stored,         toggle, requestValue,   expectedStored
                arguments("originalPass",  null,  "newPass",       "newPass"),       // null toggle + value -> set
                arguments("originalPass",  null,  null,            "originalPass"),  // null toggle + omitted -> keep
                arguments("originalPass",  null,  "",              "originalPass"),  // null toggle + blank -> keep
                arguments("originalPass",  null,  "   ",           "originalPass"),  // null toggle + whitespace -> keep
                arguments("originalPass",  false, "ignoredValue",  null),            // false -> clear, wins over value
                arguments(null,            true,  "newPass",       "newPass"),       // true + value, nothing stored -> set
                arguments("originalPass",  true,  null,            "originalPass"),  // true + blank + stored -> keep
                arguments("originalPass",  true,  "   ",           "originalPass")   // true + whitespace + stored -> keep
        );
    }

    @ParameterizedTest
    @MethodSource("challengePasswordEditCases")
    void testEditScepProfile_challengePasswordMatrix(String stored, Boolean toggle, String requestValue, String expectedStored)
            throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setChallengePassword(stored);
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableChallengePassword(toggle);
        request.setChallengePassword(requestValue);

        scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);

        ScepProfile updated = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertEquals(expectedStored, updated.getChallengePassword());
    }

    @Test
    void testEditScepProfile_clearsChallengePasswordWhenToggleFalse() throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setChallengePassword("originalChallenge");
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableChallengePassword(false);

        ScepProfileDetailDto dto = scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);

        ScepProfile updated = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertNull(updated.getChallengePassword());
        Assertions.assertFalse(dto.isEnableChallengePassword());
    }

    @Test
    void testEditScepProfile_setsChallengePasswordWhenToggleTrueWithValue() throws ConnectorException, AttributeException, NotFoundException {
        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableChallengePassword(true);
        request.setChallengePassword("newChallenge");

        ScepProfileDetailDto dto = scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);

        ScepProfile updated = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertEquals("newChallenge", updated.getChallengePassword());
        Assertions.assertTrue(dto.isEnableChallengePassword());
    }

    @Test
    void testEditScepProfile_rejectsToggleTrueWhenNothingStored() {
        scepProfile.setChallengePassword(null);
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableChallengePassword(true);
        // no value and nothing stored -> reject

        SecuredUUID uuid = scepProfile.getSecuredUuid();
        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> scepProfileService.editScepProfile(uuid, request));
        Assertions.assertTrue(ex.getMessage().contains("Challenge password is required"), ex.getMessage());
    }

    @Test
    void testEditScepProfile_nullToggleOnPasswordlessProfileKeepsNullWithoutError() throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setChallengePassword(null);
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        // enableChallengePassword omitted (legacy client) -> no clear, no 400

        ScepProfileDetailDto dto = scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);

        ScepProfile updated = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertNull(updated.getChallengePassword());
        Assertions.assertFalse(dto.isEnableChallengePassword());
    }

    @Test
    void testEditScepProfile_disablingIntuneClearsStoredConfig() throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setIntuneEnabled(true);
        scepProfile.setIntuneTenant("tenant");
        scepProfile.setIntuneApplicationId("appId");
        scepProfile.setIntuneApplicationKey("originalKey");
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(false);

        scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);

        ScepProfile updated = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertFalse(updated.isIntuneEnabled());
        Assertions.assertNull(updated.getIntuneTenant());
        Assertions.assertNull(updated.getIntuneApplicationId());
        Assertions.assertNull(updated.getIntuneApplicationKey());
    }

    @Test
    void testEditScepProfile_omittedEnableIntuneClearsStoredConfig() throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setIntuneEnabled(true);
        scepProfile.setIntuneTenant("tenant");
        scepProfile.setIntuneApplicationId("appId");
        scepProfile.setIntuneApplicationKey("originalKey");
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        // enableIntune omitted entirely: PUT full-replace semantics collapse it to false -> clear sub-config

        scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);

        ScepProfile updated = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertFalse(updated.isIntuneEnabled());
        Assertions.assertNull(updated.getIntuneTenant());
        Assertions.assertNull(updated.getIntuneApplicationId());
        Assertions.assertNull(updated.getIntuneApplicationKey());
    }

    @Test
    void testCreateScepProfile_rejectsToggleTrueWithoutPassword() {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("ToggleNoPassword");
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableChallengePassword(true);
        // enabled but no password supplied -> reject

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> scepProfileService.createScepProfile(request));
        Assertions.assertTrue(ex.getMessage().contains("Challenge password is required"), ex.getMessage());
    }

    @Test
    void testCreateScepProfile_setsChallengePasswordWhenToggleTrue() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("ToggleWithPassword");
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableChallengePassword(true);
        request.setChallengePassword("createdPass");

        ScepProfileDetailDto dto = scepProfileService.createScepProfile(request);

        ScepProfile created = scepProfileRepository.findByUuid(UUID.fromString(dto.getUuid())).orElseThrow();
        Assertions.assertEquals("createdPass", created.getChallengePassword());
        Assertions.assertTrue(dto.isEnableChallengePassword());
    }

    @Test
    void testEditScepProfile_updatesIntuneKeyWhenProvided() throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setIntuneEnabled(true);
        scepProfile.setIntuneTenant("tenant");
        scepProfile.setIntuneApplicationId("appId");
        scepProfile.setIntuneApplicationKey("originalKey");
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(true);
        request.setIntuneTenant("tenant");
        request.setIntuneApplicationId("appId");
        request.setIntuneApplicationKey("newKey");

        scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), request);

        ScepProfile updated = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertEquals("newKey", updated.getIntuneApplicationKey());
    }

    @Test
    void testEditScepProfile_rejectsWhenIntuneEnabledAndNoKeyStored() {
        scepProfile.setIntuneEnabled(false);
        scepProfile.setIntuneApplicationKey(null);
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(true);
        request.setIntuneTenant("tenant");
        request.setIntuneApplicationId("appId");
        // key omitted and none stored -> reject

        SecuredUUID uuid = scepProfile.getSecuredUuid();
        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> scepProfileService.editScepProfile(uuid, request));
        Assertions.assertTrue(ex.getMessage().contains("Invalid Intune configuration"), ex.getMessage());
    }

    @Test
    void testEditScepProfile_rejectsBlankIntuneTenant() {
        ScepProfileEditRequestDto request = new ScepProfileEditRequestDto();
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(true);
        request.setIntuneTenant("   "); // whitespace-only tenant -> reject
        request.setIntuneApplicationId("appId");
        request.setIntuneApplicationKey("key");

        SecuredUUID uuid = scepProfile.getSecuredUuid();
        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> scepProfileService.editScepProfile(uuid, request));
        Assertions.assertTrue(ex.getMessage().contains("Invalid Intune configuration"), ex.getMessage());
    }

    @Test
    void testCreateScepProfile_rejectsWhitespaceChallengeWhenToggleTrue() {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("WhitespaceChallenge");
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableChallengePassword(true);
        request.setChallengePassword("   "); // whitespace -> blank, nothing stored -> reject

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> scepProfileService.createScepProfile(request));
        Assertions.assertTrue(ex.getMessage().contains("Challenge password is required"), ex.getMessage());
    }

    @Test
    void testCreateScepProfile_doesNotPersistIntuneWhenDisabled() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("IntuneDisabledOnCreate");
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(false);
        request.setIntuneTenant("tenant");
        request.setIntuneApplicationId("appId");
        request.setIntuneApplicationKey("leakedKey");

        ScepProfileDetailDto dto = scepProfileService.createScepProfile(request);

        ScepProfile created = scepProfileRepository.findByUuid(UUID.fromString(dto.getUuid())).orElseThrow();
        Assertions.assertFalse(created.isIntuneEnabled());
        Assertions.assertNull(created.getIntuneTenant());
        Assertions.assertNull(created.getIntuneApplicationId());
        Assertions.assertNull(created.getIntuneApplicationKey());
    }

    @Test
    void testCreateScepProfile_withIntuneEnabledStoresConfig() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("IntuneEnabledCreate");
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(true);
        request.setIntuneTenant("tenant");
        request.setIntuneApplicationId("appId");
        request.setIntuneApplicationKey("appKey");

        ScepProfileDetailDto dto = scepProfileService.createScepProfile(request);

        ScepProfile created = scepProfileRepository.findByUuid(UUID.fromString(dto.getUuid())).orElseThrow();
        Assertions.assertTrue(created.isIntuneEnabled());
        Assertions.assertEquals("tenant", created.getIntuneTenant());
        Assertions.assertEquals("appId", created.getIntuneApplicationId());
        Assertions.assertEquals("appKey", created.getIntuneApplicationKey());
    }

    @Test
    void testCreateScepProfile_rejectsIntuneEnabledWithoutKey() {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("IntuneNoKey");
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(true);
        request.setIntuneTenant("tenant");
        request.setIntuneApplicationId("appId");
        // application key missing -> reject

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> scepProfileService.createScepProfile(request));
        Assertions.assertTrue(ex.getMessage().contains("Invalid Intune configuration"), ex.getMessage());
    }

    @Test
    void testCreateScepProfile_rejectsIntuneEnabledBlankApplicationId() {
        ScepProfileRequestDto request = new ScepProfileRequestDto();
        request.setName("IntuneBlankAppId");
        request.setCaCertificateUuid(certificate.getUuid().toString());
        request.setEnableIntune(true);
        request.setIntuneTenant("tenant");
        request.setIntuneApplicationId("   "); // blank application id -> reject
        request.setIntuneApplicationKey("appKey");

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> scepProfileService.createScepProfile(request));
        Assertions.assertTrue(ex.getMessage().contains("Invalid Intune configuration"), ex.getMessage());
    }

    @Test
    void testEditScepProfile_intuneDisableThenReEnableWithFreshKey() throws ConnectorException, AttributeException, NotFoundException {
        scepProfile.setIntuneEnabled(true);
        scepProfile.setIntuneTenant("tenant");
        scepProfile.setIntuneApplicationId("appId");
        scepProfile.setIntuneApplicationKey("originalKey");
        scepProfileRepository.save(scepProfile);

        ScepProfileEditRequestDto disable = new ScepProfileEditRequestDto();
        disable.setCaCertificateUuid(certificate.getUuid().toString());
        disable.setEnableIntune(false);
        scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), disable);
        ScepProfile cleared = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertNull(cleared.getIntuneApplicationKey());

        ScepProfileEditRequestDto reEnable = new ScepProfileEditRequestDto();
        reEnable.setCaCertificateUuid(certificate.getUuid().toString());
        reEnable.setEnableIntune(true);
        reEnable.setIntuneTenant("tenant2");
        reEnable.setIntuneApplicationId("appId2");
        reEnable.setIntuneApplicationKey("freshKey");
        scepProfileService.editScepProfile(scepProfile.getSecuredUuid(), reEnable);

        ScepProfile reEnabled = scepProfileRepository.findByUuid(scepProfile.getUuid()).orElseThrow();
        Assertions.assertTrue(reEnabled.isIntuneEnabled());
        Assertions.assertEquals("freshKey", reEnabled.getIntuneApplicationKey());
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
        List<NameAndUuidDto> dtos = scepProfileInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = scepProfileInternalService.getResourceObjectInternal(scepProfile.getUuid());
        Assertions.assertEquals(scepProfile.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(scepProfile.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = scepProfileInternalService.getResourceObjectExternal(scepProfile.getSecuredUuid());
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

    @Test
    void testIntuneConfigProperties() {
        scepProfile.setIntuneTenant("tenant123");
        scepProfile.setIntuneApplicationId("appId123");
        scepProfile.setIntuneApplicationKey("appKey123");
        scepProfileRepository.save(scepProfile);
        Properties properties = intuneConfigProperties.forScepProfile(scepProfile);
        Assertions.assertEquals(scepProfile.getIntuneApplicationId(), properties.get("AAD_APP_ID"));
        Assertions.assertEquals(scepProfile.getIntuneApplicationKey(), properties.get("AAD_APP_KEY"));
        Assertions.assertEquals(scepProfile.getIntuneTenant(), properties.get("TENANT"));
        Assertions.assertNotNull(properties.get("PROVIDER_NAME_AND_VERSION"));
    }
}

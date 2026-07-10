package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserRequestDto;
import com.otilm.api.model.core.auth.UserUpdateRequestDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.service.UserManagementExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.SessionTableHelper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.TestInstance;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.jdbc.core.JdbcTemplate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserManagementServiceITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private UserManagementExternalService userManagementService;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private FindByIndexNameSessionRepository sessionRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    UserManagementApiClient userManagementApiClient;

    @MockitoBean
    CertificateUploadService certificateUploadService;

    @AfterAll
    void tearDownSessionTables() {
        SessionTableHelper.dropSessionTables(jdbcTemplate);
    }

    @Test
    void testDoNotUseArchivedCertificates() {
        Certificate archivedCertificate = new Certificate();
        archivedCertificate.setArchived(true);
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("content");
        certificateContentRepository.save(certificateContent);
        archivedCertificate.setCertificateContent(certificateContent);
        certificateRepository.save(archivedCertificate);

        AddUserRequestDto addUserRequestDto = new AddUserRequestDto();
        addUserRequestDto.setCertificateUuid(archivedCertificate.getUuid().toString());
        addUserRequestDto.setUsername("username");

        Assertions.assertThrows(ValidationException.class, () -> userManagementService.createUser(addUserRequestDto));
    }

    @Test
    void testCreateUserForwardsCertificateCustomAttributesToUpload() throws Exception {
        X509Certificate x509Certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=uploaded-user-cert");
        String certificateData = Base64.getEncoder().encodeToString(x509Certificate.getEncoded());

        // A fingerprint different from the submitted certificate's thumbprint, so the initial inventory
        // lookup misses and the upload path is taken; the mocked upload then "produces" this row.
        Certificate uploadedCertificate = saveCertificate("uploaded-fingerprint");
       when(certificateUploadService.upload(anyString(), anyList(), anyBoolean()))
                .thenReturn(uploadedCertificate.getFingerprint());
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        List<RequestAttribute> certificateCustomAttributes = List.of(certificateCustomAttribute());
        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithUploadedCertificate");
        request.setCertificateData(certificateData);
        request.setCertificateCustomAttributes(certificateCustomAttributes);

        userManagementService.createUser(request);

        verify(certificateUploadService).upload(certificateData, certificateCustomAttributes, true);
    }

    @Test
    void testCertificateCustomAttributesIgnoredForExistingCertificateReferencedByUuid() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-by-uuid-fingerprint");
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithExistingCertificateByUuid");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(certificateCustomAttribute()));

        userManagementService.createUser(request);

        verify(certificateUploadService, never()).upload(any(),any(), anyBoolean());
        Assertions.assertTrue(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid()).isEmpty());
    }

    @Test
    void testCertificateCustomAttributesIgnoredForExistingCertificateMatchedByFingerprint() throws Exception {
        X509Certificate x509Certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=existing-user-cert");
        Certificate existingCertificate = saveCertificate(CertificateUtil.getThumbprint(x509Certificate));
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithExistingCertificateByFingerprint");
        request.setCertificateData(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        request.setCertificateCustomAttributes(List.of(certificateCustomAttribute()));

        userManagementService.createUser(request);

        verify(certificateUploadService, never()).upload(any(), any(), anyBoolean());
        Assertions.assertTrue(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid()).isEmpty());
    }

    @Test
    void testCreateUserWithoutGroupUuidsCreatesUserWithEmptyGroups() {
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithoutGroups");
        Assertions.assertNull(request.getGroupUuids());

        Assertions.assertDoesNotThrow(() -> userManagementService.createUser(request));

        ArgumentCaptor<UserRequestDto> requestCaptor = ArgumentCaptor.forClass(UserRequestDto.class);
        verify(userManagementApiClient).createUser(requestCaptor.capture());
        Assertions.assertTrue(requestCaptor.getValue().getGroups().isEmpty());
    }

    @Test
    void testUploadValidationErrorPropagatesAsValidationException() throws Exception {
        X509Certificate x509Certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=rejected-user-cert");
        when(certificateUploadService.upload(anyString(), anyList(), anyBoolean()))
                .thenThrow(new ValidationException("Certificate custom attributes are not valid."));

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithRejectedCertificate");
        request.setCertificateData(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        request.setCertificateCustomAttributes(List.of(certificateCustomAttribute()));

        Assertions.assertThrows(ValidationException.class, () -> userManagementService.createUser(request));
    }

    @Test
    void testUpdateUserWithExistingCertificate() throws Exception {
        Certificate existingCertificate = saveCertificate("update-existing-fingerprint");
        when(userManagementApiClient.updateUser(anyString(), any())).thenReturn(userDetailDto());

        UpdateUserRequestDto request = new UpdateUserRequestDto();
        request.setCertificateUuid(existingCertificate.getUuid().toString());

        String userUuid = UUID.randomUUID().toString();
        userManagementService.updateUser(userUuid, request);

        ArgumentCaptor<UserUpdateRequestDto> requestCaptor = ArgumentCaptor.forClass(UserUpdateRequestDto.class);
        verify(userManagementApiClient).updateUser(eq(userUuid), requestCaptor.capture());
        Assertions.assertEquals(existingCertificate.getUuid().toString(), requestCaptor.getValue().getCertificateUuid());
        Assertions.assertEquals(existingCertificate.getFingerprint(), requestCaptor.getValue().getCertificateFingerprint());
    }

    @Test
    void testUpdateUserWithGroupUuidsResolvesGroups() throws Exception {
        Group firstGroup = saveGroup("first-group");
        Group secondGroup = saveGroup("second-group");
        when(userManagementApiClient.updateUser(anyString(), any())).thenReturn(userDetailDto());

        UpdateUserRequestDto request = new UpdateUserRequestDto();
        request.setGroupUuids(List.of(firstGroup.getUuid().toString(), secondGroup.getUuid().toString()));

        String userUuid = UUID.randomUUID().toString();
        userManagementService.updateUser(userUuid, request);

        ArgumentCaptor<UserUpdateRequestDto> requestCaptor = ArgumentCaptor.forClass(UserUpdateRequestDto.class);
        verify(userManagementApiClient).updateUser(eq(userUuid), requestCaptor.capture());
        Assertions.assertEquals(
                List.of(new NameAndUuidDto(firstGroup.getUuid(), firstGroup.getName()), new NameAndUuidDto(secondGroup.getUuid(), secondGroup.getName())),
                requestCaptor.getValue().getGroups());
    }

    private Group saveGroup(String name) {
        Group group = new Group();
        group.setName(name);
        groupRepository.save(group);
        return group;
    }

    private Certificate saveCertificate(String fingerprint) {
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("content-" + fingerprint);
        certificateContentRepository.save(certificateContent);
        Certificate certificate = new Certificate();
        certificate.setState(CertificateState.ISSUED);
        certificate.setFingerprint(fingerprint);
        certificate.setCertificateContent(certificateContent);
        certificateRepository.save(certificate);
        return certificate;
    }

    private static RequestAttribute certificateCustomAttribute() {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.randomUUID());
        attribute.setName("criticality");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3("Low")));
        return attribute;
    }

    private static UserDetailDto userDetailDto() {
        UserDetailDto dto = new UserDetailDto();
        dto.setUuid(UUID.randomUUID().toString());
        dto.setUsername("user-" + dto.getUuid());
        dto.setRoles(List.of());
        return dto;
    }

    @Test
    void removeDisabledAndDeletedUserSession() {
        SessionTableHelper.createSessionTables(jdbcTemplate);
        UUID userUuid = UUID.randomUUID();
        createSession(userUuid);
        Assertions.assertFalse(sessionRepository.findByPrincipalName(userUuid.toString()).isEmpty());
        userManagementService.deleteUser(userUuid.toString());
        Assertions.assertTrue(sessionRepository.findByPrincipalName(userUuid.toString()).isEmpty());

        createSession(userUuid);
        userManagementService.disableUser(userUuid.toString());
        Assertions.assertTrue(sessionRepository.findByPrincipalName(userUuid.toString()).isEmpty());
    }

    private void createSession(UUID userUuid) {
        Session s = sessionRepository.createSession();
        s.setAttribute(
                FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
                userUuid.toString()
        );
        sessionRepository.save(s);
    }
}

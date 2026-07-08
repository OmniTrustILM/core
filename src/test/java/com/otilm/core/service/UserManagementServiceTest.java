package com.otilm.core.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserRequestDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.security.authn.client.UserManagementApiClient;
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

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserManagementServiceTest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

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
        Mockito.when(certificateUploadService.upload(Mockito.anyString(), Mockito.anyList(), Mockito.anyBoolean()))
                .thenReturn(uploadedCertificate.getFingerprint());
        Mockito.when(userManagementApiClient.createUser(Mockito.any())).thenReturn(userDetailDto());

        List<RequestAttribute> certificateCustomAttributes = List.of(certificateCustomAttribute());
        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithUploadedCertificate");
        request.setCertificateData(certificateData);
        request.setCertificateCustomAttributes(certificateCustomAttributes);

        userManagementService.createUser(request);

        Mockito.verify(certificateUploadService).upload(certificateData, certificateCustomAttributes, true);
    }

    @Test
    void testCertificateCustomAttributesIgnoredForExistingCertificateReferencedByUuid() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-by-uuid-fingerprint");
        Mockito.when(userManagementApiClient.createUser(Mockito.any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithExistingCertificateByUuid");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(certificateCustomAttribute()));

        userManagementService.createUser(request);

        Mockito.verify(certificateUploadService, Mockito.never()).upload(Mockito.any(), Mockito.any(), Mockito.anyBoolean());
        Assertions.assertTrue(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid()).isEmpty());
    }

    @Test
    void testCertificateCustomAttributesIgnoredForExistingCertificateMatchedByFingerprint() throws Exception {
        X509Certificate x509Certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=existing-user-cert");
        Certificate existingCertificate = saveCertificate(CertificateUtil.getThumbprint(x509Certificate));
        Mockito.when(userManagementApiClient.createUser(Mockito.any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithExistingCertificateByFingerprint");
        request.setCertificateData(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        request.setCertificateCustomAttributes(List.of(certificateCustomAttribute()));

        userManagementService.createUser(request);

        Mockito.verify(certificateUploadService, Mockito.never()).upload(Mockito.any(), Mockito.any(), Mockito.anyBoolean());
        Assertions.assertTrue(attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid()).isEmpty());
    }

    @Test
    void testCreateUserWithoutGroupUuidsCreatesUserWithEmptyGroups() {
        Mockito.when(userManagementApiClient.createUser(Mockito.any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithoutGroups");
        Assertions.assertNull(request.getGroupUuids());

        Assertions.assertDoesNotThrow(() -> userManagementService.createUser(request));

        ArgumentCaptor<UserRequestDto> requestCaptor = ArgumentCaptor.forClass(UserRequestDto.class);
        Mockito.verify(userManagementApiClient).createUser(requestCaptor.capture());
        Assertions.assertTrue(requestCaptor.getValue().getGroups().isEmpty());
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

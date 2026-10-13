package com.otilm.core.integration.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.auth.AddUserRequestDto;
import com.otilm.api.model.client.auth.UpdateUserRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserRequestDto;
import com.otilm.api.model.core.auth.UserUpdateRequestDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.ListView;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.ListViewRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.service.UserManagementExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.SessionTableHelper;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserManagementServiceITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private ListViewRepository listViewRepository;

    @Autowired
    private UserManagementExternalService userManagementService;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private AttributeExternalService attributeService;

    @Autowired
    private FindByIndexNameSessionRepository sessionRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    UserManagementApiClient userManagementApiClient;

    @MockitoBean
    CertificateUploadService certificateUploadService;

    @MockitoBean
    AuthenticationCache authenticationCache;

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
        X509Certificate x509Certificate = CertificateGeneratorHelper
                .generateCACertificate(null, "CN=uploaded-user-cert");
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
    void testCertificateCustomAttributesAppliedToExistingCertificateReferencedByUuid() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-by-uuid-fingerprint");
        RequestAttribute attribute = registerCertificateCustomAttribute("criticalityByUuid", "Low");
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithExistingCertificateByUuid");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(attribute));

        userManagementService.createUser(request);

        verify(certificateUploadService, never()).upload(any(), any(), anyBoolean());
        Assertions
                .assertEquals(List.of("Low"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityByUuid"));
    }

    @Test
    void testCertificateCustomAttributesAppliedToExistingCertificateMatchedByFingerprint() throws Exception {
        X509Certificate x509Certificate = CertificateGeneratorHelper
                .generateCACertificate(null, "CN=existing-user-cert");
        Certificate existingCertificate = saveCertificate(CertificateUtil.getThumbprint(x509Certificate));
        RequestAttribute attribute = registerCertificateCustomAttribute("criticalityByFingerprint", "High");
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithExistingCertificateByFingerprint");
        request.setCertificateData(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        request.setCertificateCustomAttributes(List.of(attribute));

        userManagementService.createUser(request);

        verify(certificateUploadService, never()).upload(any(), any(), anyBoolean());
        Assertions
                .assertEquals(List.of("High"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityByFingerprint"));
    }

    @Test
    void testAuthenticationCacheEvictedWhenCertificateAttributesRefused() throws Exception {
        Certificate existingCertificate = saveCertificate("update-cache-eviction-fingerprint");
        RequestAttribute allowed = registerCertificateCustomAttribute("criticalityCacheAllowed", "Medium");
        RequestAttribute forbidden = registerCertificateCustomAttribute("criticalityCacheForbidden", "High");
        when(userManagementApiClient.updateUser(anyString(), any())).thenReturn(userDetailDto());
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(allowed.getUuid()));

        UpdateUserRequestDto request = new UpdateUserRequestDto();
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(forbidden));

        String userUuid = UUID.randomUUID().toString();
        Assertions.assertThrows(CertificateException.class, () -> userManagementService.updateUser(userUuid, request));

        verify(userManagementApiClient, never()).updateUser(anyString(), any());
        verify(authenticationCache).evictByUserUuid(UUID.fromString(userUuid));
    }

    @Test
    void testUpdateUserAppliesCertificateCustomAttributesToExistingCertificate() throws Exception {
        Certificate existingCertificate = saveCertificate("update-existing-attributes-fingerprint");
        RequestAttribute attribute = registerCertificateCustomAttribute("criticalityOnUpdate", "High");
        when(userManagementApiClient.updateUser(anyString(), any())).thenReturn(userDetailDto());

        UpdateUserRequestDto request = new UpdateUserRequestDto();
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(attribute));

        userManagementService.updateUser(UUID.randomUUID().toString(), request);

        Assertions
                .assertEquals(List.of("High"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityOnUpdate"));
    }

    @Test
    void testUpdateUserRefusesCertificateCustomAttributesWithoutCertificateUpdatePermission() throws Exception {
        Certificate existingCertificate = saveCertificate("update-unauthorized-fingerprint");
        RequestAttribute attribute = registerCertificateCustomAttribute("criticalityUpdateDenied", "Low");
        when(userManagementApiClient.updateUser(anyString(), any())).thenReturn(userDetailDto());
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.UPDATE);

        UpdateUserRequestDto request = new UpdateUserRequestDto();
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(attribute));

        String userUuid = UUID.randomUUID().toString();
        Assertions.assertThrows(AccessDeniedException.class, () -> userManagementService.updateUser(userUuid, request));
        verify(userManagementApiClient, never()).updateUser(anyString(), any());
        Assertions
                .assertTrue(certificateCustomAttributeValues(existingCertificate, "criticalityUpdateDenied").isEmpty());
    }

    @Test
    void testInvalidCertificateCustomAttributesRejectedBeforeUserIsCreated() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-invalid-attribute-fingerprint");
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithInvalidCertificateAttribute");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(certificateCustomAttribute()));

        Assertions.assertThrows(ValidationException.class, () -> userManagementService.createUser(request));
        verify(userManagementApiClient, never()).createUser(any());
    }

    @Test
    void testCertificateCustomAttributesNotWrittenWhenAuthServiceCallFails() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-auth-failure-fingerprint");
        RequestAttribute alreadySet = registerCertificateCustomAttribute("criticalityBeforeAuthFailure", "Medium");
        RequestAttribute submitted = registerCertificateCustomAttribute("criticalityAfterAuthFailure", "High");
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid(),
                        List.of(alreadySet));
        when(userManagementApiClient.createUser(any())).thenThrow(new IllegalStateException("auth service down"));

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userRejectedByAuthService");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(submitted));

        Assertions.assertThrows(IllegalStateException.class, () -> userManagementService.createUser(request));

        Assertions
                .assertEquals(List.of("Medium"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityBeforeAuthFailure"));
        Assertions
                .assertTrue(
                        certificateCustomAttributeValues(existingCertificate, "criticalityAfterAuthFailure").isEmpty());
    }

    @Test
    void testFailedUserAttributeWriteKeepsTheCertificateAttributes() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-user-attribute-failure-fingerprint");
        RequestAttribute certificateAttribute = registerCertificateCustomAttribute("criticalityKeptOnUserFailure",
                "High");
        RequestAttribute userAttribute = registerCustomAttribute(Resource.USER, "departmentForbidden", "Sales");
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());
        // The caller may edit the certificate attribute but not the user one, which the content validation filters
        // out silently -- so the refusal only happens once the user attributes are written.
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(certificateAttribute.getUuid()));

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithForbiddenUserAttribute");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(certificateAttribute));
        request.setCustomAttributes(List.of(userAttribute));

        Assertions.assertThrows(AttributeException.class, () -> userManagementService.createUser(request));

        Assertions
                .assertEquals(List.of("High"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityKeptOnUserFailure"));
    }

    @Test
    void testMismatchedAttributeIdentityRefusedBeforeUserIsCreated() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-mismatched-identity-fingerprint");
        RequestAttribute allowed = registerCertificateCustomAttribute("criticalityAllowedIdentity", "Medium");
        RequestAttribute forbidden = registerCertificateCustomAttribute("criticalityForbiddenIdentity", "High");
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid(),
                        List.of(allowed));
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(allowed.getUuid()));

        // The forbidden attribute's uuid carried under the allowed attribute's name: content validation filters on
        // the uuid and drops it, so only the permission preflight can catch the mismatch.
        RequestAttributeV3 disguised = new RequestAttributeV3();
        disguised.setUuid(forbidden.getUuid());
        disguised.setName("criticalityAllowedIdentity");
        disguised.setContentType(AttributeContentType.STRING);
        disguised.setContent(List.of(new StringAttributeContentV3("Low")));

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithMismatchedAttributeIdentity");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(disguised));

        Assertions.assertThrows(CertificateException.class, () -> userManagementService.createUser(request));
        verify(userManagementApiClient, never()).createUser(any());
        Assertions
                .assertEquals(List.of("Medium"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityAllowedIdentity"));
    }

    @Test
    void testForbiddenCustomAttributePreservesExistingCertificateContent() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-forbidden-attribute-fingerprint");
        RequestAttribute allowed = registerCertificateCustomAttribute("criticalityAllowed", "Medium");
        RequestAttribute forbidden = registerCertificateCustomAttribute("criticalityForbidden", "High");
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid(),
                        List.of(allowed));
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());
        // The caller may edit the attribute the certificate already carries, but not the one being submitted. The
        // preflight refuses that before the auth call, so the engine's scoped delete never runs on this path.
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS, List.of(allowed.getUuid()));

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithForbiddenCertificateAttribute");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(forbidden));

        Assertions.assertThrows(CertificateException.class, () -> userManagementService.createUser(request));
        verify(userManagementApiClient, never()).createUser(any());
        Assertions
                .assertEquals(List.of("Medium"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityAllowed"));
    }

    @Test
    void testCertificateCustomAttributesUntouchedWhenGroupResolutionFails() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-untouched-by-group-failure-fingerprint");
        RequestAttribute alreadySet = registerCertificateCustomAttribute("criticalityBeforeRollback", "Medium");
        RequestAttribute submitted = registerCertificateCustomAttribute("criticalityNotApplied", "High");
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid(),
                        List.of(alreadySet));

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithUnknownGroup");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(submitted));
        request.setGroupUuids(List.of(UUID.randomUUID().toString()));

        Assertions.assertThrows(NotFoundException.class, () -> userManagementService.createUser(request));

        Assertions
                .assertEquals(List.of("Medium"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityBeforeRollback"));
        Assertions.assertTrue(certificateCustomAttributeValues(existingCertificate, "criticalityNotApplied").isEmpty());
    }

    @Test
    void testCertificateCustomAttributesRefusedWithoutCertificateUpdatePermission() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-unauthorized-fingerprint");
        RequestAttribute attribute = registerCertificateCustomAttribute("criticalityUnauthorized", "Low");
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.UPDATE);

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithoutCertificateUpdatePermission");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(attribute));

        Assertions.assertThrows(AccessDeniedException.class, () -> userManagementService.createUser(request));
        verify(userManagementApiClient, never()).createUser(any());
        Assertions
                .assertTrue(certificateCustomAttributeValues(existingCertificate, "criticalityUnauthorized").isEmpty());
    }

    @Test
    void testSubmittedCustomAttributesReplaceThoseAlreadyOnExistingCertificate() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-replaced-fingerprint");
        RequestAttribute alreadySet = registerCertificateCustomAttribute("criticalityAlreadySet", "Medium");
        RequestAttribute submitted = registerCertificateCustomAttribute("criticalitySubmitted", "High");
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid(),
                        List.of(alreadySet));
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithExistingCertificateAndReplacedAttributes");
        request.setCertificateUuid(existingCertificate.getUuid().toString());
        request.setCertificateCustomAttributes(List.of(submitted));

        userManagementService.createUser(request);

        Assertions
                .assertEquals(List.of("High"),
                        certificateCustomAttributeValues(existingCertificate, "criticalitySubmitted"));
        Assertions.assertTrue(certificateCustomAttributeValues(existingCertificate, "criticalityAlreadySet").isEmpty());
    }

    @Test
    void testExistingCertificateKeepsItsCustomAttributesWhenRequestCarriesNone() throws Exception {
        Certificate existingCertificate = saveCertificate("existing-untouched-fingerprint");
        RequestAttribute attribute = registerCertificateCustomAttribute("criticalityUntouched", "Medium");
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CERTIFICATE, existingCertificate.getUuid(),
                        List.of(attribute));
        when(userManagementApiClient.createUser(any())).thenReturn(userDetailDto());

        AddUserRequestDto request = new AddUserRequestDto();
        request.setUsername("userWithExistingCertificateAndNoAttributes");
        request.setCertificateUuid(existingCertificate.getUuid().toString());

        userManagementService.createUser(request);

        Assertions
                .assertEquals(List.of("Medium"),
                        certificateCustomAttributeValues(existingCertificate, "criticalityUntouched"));
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
        X509Certificate x509Certificate = CertificateGeneratorHelper
                .generateCACertificate(null, "CN=rejected-user-cert");
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
        Assertions
                .assertEquals(existingCertificate.getUuid().toString(), requestCaptor.getValue().getCertificateUuid());
        Assertions
                .assertEquals(existingCertificate.getFingerprint(),
                        requestCaptor.getValue().getCertificateFingerprint());
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
        Assertions
                .assertEquals(
                        List
                                .of(new NameAndUuidDto(firstGroup.getUuid(), firstGroup.getName()),
                                        new NameAndUuidDto(secondGroup.getUuid(), secondGroup.getName())),
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

    private RequestAttribute registerCertificateCustomAttribute(String name, String value) throws Exception {
        return registerCustomAttribute(Resource.CERTIFICATE, name, value);
    }

    private RequestAttribute registerCustomAttribute(Resource resource, String name, String value) throws Exception {
        CustomAttributeCreateRequestDto definition = new CustomAttributeCreateRequestDto();
        definition.setName(name);
        definition.setLabel(name);
        definition.setResources(List.of(resource));
        definition.setContentType(AttributeContentType.STRING);
        String uuid = attributeService.createCustomAttribute(definition).getUuid();

        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return attribute;
    }

    private List<String> certificateCustomAttributeValues(Certificate certificate, String name) {
        List<String> values = new ArrayList<>();
        for (ResponseAttribute attribute : attributeEngine
                .getObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid())) {
            if (!attribute.getName().equals(name)) {
                continue;
            }
            List<AttributeContent> content = attribute.getContent();
            content.forEach(item -> {
                Object data = item.getData();
                values.add(String.valueOf(data));
            });
        }
        return values;
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

    /**
     * A saved list view is keyed by the user UUID with no foreign key to cascade from, so the rows only go away if the
     * deletion path removes them itself.
     */
    @Test
    void deleteUserRemovesTheirSavedListViews() {
        SessionTableHelper.createSessionTables(jdbcTemplate);
        UUID deletedUser = UUID.randomUUID();
        UUID survivingUser = UUID.randomUUID();
        saveListView(deletedUser, "Theirs");
        saveListView(survivingUser, "Mine");

        userManagementService.deleteUser(deletedUser.toString());

        Assertions.assertTrue(listViewRepository.findByUserUuidOrderByCreatedAscUuidAsc(deletedUser).isEmpty());
        Assertions.assertEquals(1, listViewRepository.findByUserUuidOrderByCreatedAscUuidAsc(survivingUser).size());
    }

    private void saveListView(UUID userUuid, String name) {
        ListView view = new ListView();
        view.setUserUuid(userUuid);
        view.setResource(Resource.CERTIFICATE);
        view.setName(name);
        view.setColumns(List.of(new ListViewColumnDto(FilterFieldSource.PROPERTY, "COMMON_NAME", null)));
        listViewRepository.save(view);
    }

    private void createSession(UUID userUuid) {
        Session s = sessionRepository.createSession();
        s.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, userUuid.toString());
        sessionRepository.save(s);
    }
}

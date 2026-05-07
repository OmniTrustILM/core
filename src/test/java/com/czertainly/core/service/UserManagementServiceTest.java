package com.czertainly.core.service;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.auth.AddUserRequestDto;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.SessionTableHelper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.UUID;

class UserManagementServiceTest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private UserManagementService userManagementService;

    @Autowired
    private FindByIndexNameSessionRepository sessionRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    UserManagementApiClient userManagementApiClient;

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
    void removeDisabledAndDeletedUserSession() {
        setupSessionTables();
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

    private void setupSessionTables() {
        SessionTableHelper.createSessionTables(jdbcTemplate);
    }
}

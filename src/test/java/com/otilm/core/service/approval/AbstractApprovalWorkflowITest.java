package com.otilm.core.service.approval;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileRequestDto;
import com.otilm.api.model.client.approvalprofile.ApprovalStepRequestDto;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.service.ApprovalExternalService;
import com.otilm.core.service.ApprovalInternalService;
import com.otilm.core.service.ApprovalProfileExternalService;
import com.otilm.core.service.CertificateEventHistoryExternalService;
import com.otilm.core.util.BaseMessagingIntTest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Shared scaffolding for end-to-end approval-workflow integration tests that drive the full async path:
 * ApprovalService → JMS (real RabbitMQ) → listeners → ClientOperationService / certificate history.
 *
 * <p>{@code inheritProfiles = false} is required to activate the JMS listener endpoint beans, which are
 * excluded under the {@code "test"} profile via {@code @Profile("!test")}.</p>
 */
@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
abstract class AbstractApprovalWorkflowITest extends BaseMessagingIntTest {

    /**
     * Fixed UUID used for the approver so the approval profile step can reference it. Each test uses a
     * different random creator UUID to satisfy the "can't self-approve" constraint.
     */
    protected static final UUID APPROVER_UUID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    @Autowired
    protected ApprovalExternalService approvalService;

    @Autowired
    protected ApprovalInternalService approvalInternalService;

    @Autowired
    protected ApprovalProfileExternalService approvalProfileService;

    @Autowired
    protected CertificateEventHistoryExternalService certHistoryService;

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected CertificateContentRepository certificateContentRepository;

    @Autowired
    protected ApprovalRepository approvalRepository;

    /**
     * Authenticate as the stable approver with an empty (non-null) roles list.
     */
    @Override
    protected Authentication getAuthentication() {
        UserProfileDto userProfileDto = new UserProfileDto();

        UserDto userDto = new UserDto();
        userDto.setUuid(APPROVER_UUID.toString());
        userDto.setUsername("test-approver");
        userDto.setFirstName("Test");
        userDto.setLastName("Approver");
        userDto.setSystemUser(true);
        userProfileDto.setUser(userDto);
        userProfileDto.setRoles(List.of()); // must be non-null — see validateAndSetPendingApprovalRecipient

        String rawData;
        try {
            rawData = new ObjectMapper().writeValueAsString(userProfileDto);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, APPROVER_UUID.toString(), "test-approver", List.of(), rawData);
        return new PlatformAuthenticationToken(new PlatformUserDetails(info));
    }

    /**
     * Persists a certificate in {@link CertificateState#PENDING_APPROVAL} — the state an action is parked
     * in while its approval is pending.
     */
    protected Certificate persistPendingApprovalCertificate(String subjectDn, String serialNumber, String contentText) {
        CertificateContent content = new CertificateContent();
        content.setContent(contentText);
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        certificate.setSubjectDn(subjectDn);
        certificate.setIssuerDn("CN=test-issuer");
        certificate.setSerialNumber(serialNumber);
        certificate.setState(CertificateState.PENDING_APPROVAL);
        certificate.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        certificate.setCertificateType(CertificateType.X509);
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        certificate.setNotBefore(Date.from(Instant.now().minus(1, ChronoUnit.DAYS)));
        certificate.setNotAfter(Date.from(Instant.now().plus(365, ChronoUnit.DAYS)));
        return certificateRepository.save(certificate);
    }

    /**
     * Creates a single-step approval profile whose only step targets {@link #APPROVER_UUID}.
     */
    protected ApprovalProfile singleStepApprovalProfile(String name) throws AlreadyExistException, NotFoundException {
        ApprovalStepRequestDto stepDto = new ApprovalStepRequestDto();
        stepDto.setOrder(1);
        stepDto.setUserUuid(APPROVER_UUID);
        stepDto.setRequiredApprovals(1);

        ApprovalProfileRequestDto profileDto = new ApprovalProfileRequestDto();
        profileDto.setName(name);
        profileDto.setEnabled(true);
        profileDto.setExpiry(24);
        profileDto.getApprovalSteps().add(stepDto);

        return approvalProfileService.createApprovalProfile(profileDto);
    }
}

package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.approval.ApprovalStatusEnum;
import com.czertainly.api.model.client.approval.UserApprovalDto;
import com.czertainly.api.model.client.approvalprofile.ApprovalProfileRequestDto;
import com.czertainly.api.model.client.approvalprofile.ApprovalStepRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserDto;
import com.czertainly.api.model.core.auth.UserProfileDto;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventHistoryDto;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateType;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.logging.enums.AuthMethod;
import com.czertainly.core.dao.entity.Approval;
import com.czertainly.core.dao.entity.ApprovalProfile;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.repository.ApprovalRepository;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.security.authn.CzertainlyUserDetails;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseMessagingIntTest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * End-to-end integration test for the approval flow, exercising the full async path:
 * ApprovalService → JMS (real RabbitMQ) → ApprovalClosedEventHandler → certificate event history.
 *
 * <p>{@code inheritProfiles = false} is required to activate JMS listener endpoint beans,
 * which are excluded under the {@code "test"} profile via {@code @Profile("!test")}.</p>
 */
@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
class ApprovalFlowITest extends BaseMessagingIntTest {

    /**
     * Fixed UUID used for the approver so the approval profile step can reference it.
     * The creator uses a different random UUID to satisfy the "can't self-approve" constraint.
     */
    private static final UUID APPROVER_UUID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    @Autowired
    private ApprovalService approvalService;

    @Autowired
    private ApprovalProfileService approvalProfileService;

    @Autowired
    private CertificateEventHistoryService certHistoryService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private ApprovalRepository approvalRepository;

    /**
     * Override to inject a stable approver UUID and an empty (non-null) roles list.
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
        return new CzertainlyAuthenticationToken(new CzertainlyUserDetails(info));
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void fullApprovalFlow_bothEventsLandInCertHistory_afterDatabaseTransactionCommits() throws AlreadyExistException, NotFoundException {
        // --- 1. Setup: persisted PENDING_APPROVAL certificate the approval is linked to ---
        CertificateContent content = new CertificateContent();
        content.setContent("e2e-test-cert-content");
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        certificate.setSubjectDn("CN=e2e-test");
        certificate.setIssuerDn("CN=test-issuer");
        certificate.setSerialNumber("e2e-serial-001");
        certificate.setState(CertificateState.PENDING_APPROVAL);
        certificate.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        certificate.setCertificateType(CertificateType.X509);
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        certificate.setNotBefore(Date.from(Instant.now().minus(1, ChronoUnit.DAYS)));
        certificate.setNotAfter(Date.from(Instant.now().plus(365, ChronoUnit.DAYS)));
        certificate = certificateRepository.save(certificate);
        UUID certUuid = certificate.getUuid();

        // --- 2. Setup: single-step approval profile targeting the test approver ---
        ApprovalStepRequestDto stepDto = new ApprovalStepRequestDto();
        stepDto.setOrder(1);
        stepDto.setUserUuid(APPROVER_UUID);
        stepDto.setRequiredApprovals(1);

        ApprovalProfileRequestDto profileDto = new ApprovalProfileRequestDto();
        profileDto.setName("e2e-test-profile");
        profileDto.setEnabled(true);
        profileDto.setExpiry(24);
        profileDto.getApprovalSteps().add(stepDto);

        ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(profileDto);
        UUID creatorUuid = UUID.randomUUID();

        // --- 3. Create approval — fires APPROVAL_REQUESTED event via JMS ---
        Approval approval = approvalService.createApproval(
                approvalProfile.getTheLatestApprovalProfileVersion(),
                Resource.CERTIFICATE,
                ResourceAction.ISSUE,
                certUuid,
                creatorUuid,
                null
        );

        assertThat(approval.getStatus()).isEqualTo(ApprovalStatusEnum.PENDING);

        // Wait for the async APPROVAL_REQUESTED event to land in cert history
        await("APPROVAL_REQUEST history entry written")
                .atMost(5, TimeUnit.SECONDS)
                .untilAsserted(() -> {
                    List<CertificateEventHistoryDto> history = certHistoryService.getCertificateEventHistory(certUuid);
                    assertThat(history)
                            .as("Certificate history should contain APPROVAL_REQUEST event after createApproval()")
                            .anyMatch(h -> h.getEvent() == CertificateEvent.APPROVAL_REQUEST);
                });

        // Verify APPROVAL_REQUEST message format
        List<CertificateEventHistoryDto> historyAfterRequest = certHistoryService.getCertificateEventHistory(certUuid);
        CertificateEventHistoryDto requestEvent = historyAfterRequest.stream()
                .filter(h -> h.getEvent() == CertificateEvent.APPROVAL_REQUEST)
                .findFirst()
                .orElseThrow();
        assertThat(requestEvent.getMessage())
                .contains("issue")           // action code
                .contains("e2e-test-profile"); // profile name

        // --- 4. Approver approves — fires APPROVAL_CLOSED event via JMS ---
        UserApprovalDto userApprovalDto = new UserApprovalDto();
        userApprovalDto.setComment("Approved in e2e test");

        approvalService.approveApprovalRecipient(approval.getUuid().toString(), userApprovalDto);

        // The approval entity must be APPROVED after the service call returns
        Optional<Approval> updatedApproval = approvalRepository.findByUuid(SecuredUUID.fromUUID(approval.getUuid()));
        assertThat(updatedApproval).isPresent();
        assertThat(updatedApproval.get().getStatus())
                .as("Approval entity status should be APPROVED after approveApprovalRecipient()")
                .isEqualTo(ApprovalStatusEnum.APPROVED);

        // Wait for the async APPROVAL_CLOSED event to land in cert history
        await("APPROVAL_CLOSE history entry written")
                .atMost(5, TimeUnit.SECONDS)
                .untilAsserted(() -> {
                    List<CertificateEventHistoryDto> history = certHistoryService.getCertificateEventHistory(certUuid);
                    assertThat(history)
                            .as("Certificate history should contain APPROVAL_CLOSE event after approveApprovalRecipient()")
                            .anyMatch(h -> h.getEvent() == CertificateEvent.APPROVAL_CLOSE);
                });

        // --- Assertions on the final state ---
        List<CertificateEventHistoryDto> finalHistory = certHistoryService.getCertificateEventHistory(certUuid);

        assertThat(finalHistory)
                .filteredOn(h -> h.getEvent() == CertificateEvent.APPROVAL_REQUEST || h.getEvent() == CertificateEvent.APPROVAL_CLOSE)
                .as("Certificate history should contain exactly one APPROVAL_REQUEST and one APPROVAL_CLOSE event")
                .hasSize(2)
                .anyMatch(h -> h.getEvent() == CertificateEvent.APPROVAL_REQUEST)
                .anyMatch(h -> h.getEvent() == CertificateEvent.APPROVAL_CLOSE);

        CertificateEventHistoryDto closeEvent = finalHistory.stream()
                .filter(h -> h.getEvent() == CertificateEvent.APPROVAL_CLOSE)
                .findFirst()
                .orElseThrow();

        assertThat(closeEvent.getMessage())
                .as("APPROVAL_CLOSE message must reflect the final approved status — not the stale pre-commit 'Pending' state")
                .contains("Approved")
                .doesNotContain("Pending")
                .contains("issue")            // action code
                .contains("e2e-test-profile"); // profile name
    }
}

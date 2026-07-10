package com.otilm.core.integration.service.approval;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.client.approval.UserApprovalDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventHistoryDto;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.approval.AbstractApprovalWorkflowITest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * End-to-end integration test for the approval-granted path: ApprovalService → JMS (real RabbitMQ) →
 * ApprovalClosedEventHandler → certificate event history. Verifies that both the request and the close
 * events land in the certificate history, with the close message reflecting the committed approved state.
 */
class ApprovalGrantedITest extends AbstractApprovalWorkflowITest {

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void approvalGranted_bothEventsLandInCertHistory_afterDatabaseTransactionCommits() throws AlreadyExistException, NotFoundException {
        Certificate certificate = persistPendingApprovalCertificate("CN=e2e-test", "e2e-serial-001", "e2e-test-cert-content");
        UUID certUuid = certificate.getUuid();

        ApprovalProfile approvalProfile = singleStepApprovalProfile("e2e-test-profile");
        UUID creatorUuid = UUID.randomUUID();

        // --- Create approval — fires APPROVAL_REQUESTED event via JMS ---
        Approval approval = approvalInternalService.createApproval(
                approvalProfile.getTheLatestApprovalProfileVersion(),
                Resource.CERTIFICATE,
                ResourceAction.ISSUE,
                certUuid,
                creatorUuid,
                null
        );

        assertThat(approval.getStatus()).isEqualTo(ApprovalStatusEnum.PENDING);

        await("APPROVAL_REQUEST history entry written")
                .pollInSameThread()
                .atMost(5, TimeUnit.SECONDS)
                .untilAsserted(() -> {
                    List<CertificateEventHistoryDto> history = certHistoryService.getCertificateEventHistory(certUuid);
                    assertThat(history)
                            .as("Certificate history should contain APPROVAL_REQUEST event after createApproval()")
                            .anyMatch(h -> h.getEvent() == CertificateEvent.APPROVAL_REQUEST);
                });

        List<CertificateEventHistoryDto> historyAfterRequest = certHistoryService.getCertificateEventHistory(certUuid);
        CertificateEventHistoryDto requestEvent = historyAfterRequest.stream()
                .filter(h -> h.getEvent() == CertificateEvent.APPROVAL_REQUEST)
                .findFirst()
                .orElseThrow();
        assertThat(requestEvent.getMessage())
                .contains("issue")             // action code
                .contains("e2e-test-profile"); // profile name

        // --- Approver approves — fires APPROVAL_CLOSED event via JMS ---
        UserApprovalDto userApprovalDto = new UserApprovalDto();
        userApprovalDto.setComment("Approved in e2e test");

        approvalService.approveApprovalRecipient(approval.getUuid().toString(), userApprovalDto);

        Optional<Approval> updatedApproval = approvalRepository.findByUuid(SecuredUUID.fromUUID(approval.getUuid()));
        assertThat(updatedApproval).isPresent();
        assertThat(updatedApproval.get().getStatus())
                .as("Approval entity status should be APPROVED after approveApprovalRecipient()")
                .isEqualTo(ApprovalStatusEnum.APPROVED);

        await("APPROVAL_CLOSE history entry written")
                .pollInSameThread()
                .atMost(5, TimeUnit.SECONDS)
                .untilAsserted(() -> {
                    List<CertificateEventHistoryDto> history = certHistoryService.getCertificateEventHistory(certUuid);
                    assertThat(history)
                            .as("Certificate history should contain APPROVAL_CLOSE event after approveApprovalRecipient()")
                            .anyMatch(h -> h.getEvent() == CertificateEvent.APPROVAL_CLOSE);
                });

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
                .contains("issue")             // action code
                .contains("e2e-test-profile"); // profile name
    }
}

package com.otilm.core.integration.service.approval;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.client.approval.UserApprovalDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventHistoryDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.approval.AbstractApprovalWorkflowITest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.Mockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * End-to-end integration test for the certificate revocation approval workflow, exercising the full async
 * path: ApprovalService → JMS (real RabbitMQ) → ActionsListener → ClientOperationService.
 */
class RevocationApprovalRejectedITest extends AbstractApprovalWorkflowITest {

    /**
     * The action message produced when an approval is closed is processed asynchronously by
     * {@code ActionsListener}, which re-authenticates as the approval creator via
     * {@code AuthHelper#authenticateAsUser} → this client. The real client reaches out to the auth service
     * (unavailable in tests), so it is stubbed to return a valid profile for the creator UUID. The mock is
     * scoped to this subclass so it does not alter the action-message behavior of other tests.
     */
    @MockitoBean
    private PlatformAuthenticationClient authenticationClient;

    @BeforeEach
    void stubActionMessageAuthentication() {
        Mockito.when(authenticationClient.authenticateByUserUuid(Mockito.any()))
                .thenAnswer(invocation -> userProxyAuthInfo(invocation.getArgument(0, UUID.class)));
    }

    private static AuthenticationInfo userProxyAuthInfo(UUID userUuid) {
        UserProfileDto userProfileDto = new UserProfileDto();
        UserDto userDto = new UserDto();
        userDto.setUuid(userUuid.toString());
        userDto.setUsername("action-creator");
        userDto.setSystemUser(true);
        userProfileDto.setUser(userDto);
        userProfileDto.setRoles(List.of());

        String rawData;
        try {
            rawData = new ObjectMapper().writeValueAsString(userProfileDto);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid.toString(), "action-creator", List.of(), rawData);
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void rejectedRevocationApproval_revertsCertificateToIssued() throws AlreadyExistException, NotFoundException {
        Certificate certificate = persistPendingApprovalCertificate("CN=revoke-approval-test", "revoke-approval-serial-001", "revoke-approval-cert-content");
        UUID certUuid = certificate.getUuid();

        ApprovalProfile approvalProfile = singleStepApprovalProfile("revoke-approval-test-profile");
        UUID creatorUuid = UUID.randomUUID();

        // --- Create the REVOKE approval linked to the certificate ---
        Approval approval = approvalInternalService.createApproval(
                approvalProfile.getTheLatestApprovalProfileVersion(),
                Resource.CERTIFICATE,
                ResourceAction.REVOKE,
                certUuid,
                creatorUuid,
                null
        );

        assertThat(approval.getStatus()).isEqualTo(ApprovalStatusEnum.PENDING);

        // --- Approver rejects the revocation approval ---
        UserApprovalDto userApprovalDto = new UserApprovalDto();
        userApprovalDto.setComment("Revocation not approved");

        approvalService.rejectApprovalRecipient(approval.getUuid().toString(), userApprovalDto);

        Optional<Approval> updatedApproval = approvalRepository.findByUuid(SecuredUUID.fromUUID(approval.getUuid()));
        assertThat(updatedApproval).isPresent();
        assertThat(updatedApproval.get().getStatus())
                .as("Approval entity status should be REJECTED after rejectApprovalRecipient()")
                .isEqualTo(ApprovalStatusEnum.REJECTED);

        // The async APPROVAL_CLOSE history entry confirms the close pipeline has been processed.
        await("APPROVAL_CLOSE history entry written")
                .pollInSameThread()
                .atMost(10, TimeUnit.SECONDS)
                .untilAsserted(() -> {
                    List<CertificateEventHistoryDto> history = certHistoryService.getCertificateEventHistory(certUuid);
                    assertThat(history)
                            .as("Certificate history should contain APPROVAL_CLOSE event after rejectApprovalRecipient()")
                            .anyMatch(h -> h.getEvent() == CertificateEvent.APPROVAL_CLOSE);
                });

        // --- The revocation is not performed: the certificate leaves PENDING_APPROVAL and returns to ISSUED ---
        await("certificate reverts to ISSUED after rejected revocation approval")
                .pollInSameThread()
                .atMost(10, TimeUnit.SECONDS)
                .untilAsserted(() -> {
                    Certificate refreshed = certificateRepository.findByUuid(certUuid)
                            .orElseThrow(() -> new NotFoundException(Certificate.class, certUuid));
                    assertThat(refreshed.getState())
                            .as("A rejected revocation approval must return the certificate to its prior ISSUED state")
                            .isEqualTo(CertificateState.ISSUED);
                });
    }
}

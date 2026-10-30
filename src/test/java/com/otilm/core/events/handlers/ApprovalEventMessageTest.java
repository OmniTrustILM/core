package com.otilm.core.events.handlers;

import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.client.approvalprofile.ApprovalStepDto;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Both approval events publish an {@code UpdateCertificateHistoryEvent}, so the certificate's history gains a row for
 * the request and for the close. Those rows are written on a JMS listener thread, so the acting user has to travel in
 * the event message or the row ends up attributed to the system user.
 */
class ApprovalEventMessageTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * The "Approval requested" row is written only for the first step, produced from {@code createApproval} on the
     * actions-listener thread, which returns before that listener authenticates — so the requester must be supplied.
     */
    @Test
    void requestedEventCarriesTheSuppliedRequesterOnAnUnauthenticatedThread() {
        UUID requester = UUID.randomUUID();
        SecurityContextHolder.clearContext();

        EventMessage message = ApprovalRequestedEventHandler
                .constructEventMessage(UUID.randomUUID(), new ApprovalStepDto(), requester);

        assertThat(message.getUserUuid()).isEqualTo(requester);
    }

    @Test
    void requestedEventFallsBackToTheActingUserWhenNoRequesterIsSupplied() {
        UUID requester = UUID.randomUUID();
        authenticateAs(requester);

        EventMessage message = ApprovalRequestedEventHandler
                .constructEventMessage(UUID.randomUUID(), new ApprovalStepDto());

        assertThat(message.getUserUuid()).isEqualTo(requester);
    }

    @Test
    void closedEventCarriesTheApprovingUser() {
        UUID approver = UUID.randomUUID();
        authenticateAs(approver);

        EventMessage message = ApprovalClosedEventHandler
                .constructEventMessage(UUID.randomUUID(), ApprovalStatusEnum.APPROVED);

        assertThat(message.getUserUuid()).isEqualTo(approver);
    }

    @Test
    void closedEventCarriesTheRejectingUser() {
        UUID rejecter = UUID.randomUUID();
        authenticateAs(rejecter);

        EventMessage message = ApprovalClosedEventHandler
                .constructEventMessage(UUID.randomUUID(), ApprovalStatusEnum.REJECTED);

        assertThat(message.getUserUuid()).isEqualTo(rejecter);
    }

    /** An approval that lapsed was closed by nobody; the sweep's job user took no action on it. */
    @Test
    void expiredEventCarriesNoUserEvenWhenTheSweepIsAuthenticated() {
        authenticateAs(UUID.randomUUID());

        EventMessage message = ApprovalClosedEventHandler
                .constructEventMessage(UUID.randomUUID(), ApprovalStatusEnum.EXPIRED);

        assertThat(message.getUserUuid()).isNull();
    }

    @Test
    void eventsCarryNoUserWhenNobodyIsAuthenticated() {
        assertThat(ApprovalRequestedEventHandler
                .constructEventMessage(UUID.randomUUID(), new ApprovalStepDto())
                .getUserUuid()).isNull();
        assertThat(ApprovalClosedEventHandler
                .constructEventMessage(UUID.randomUUID(), ApprovalStatusEnum.APPROVED)
                .getUserUuid()).isNull();
    }

    private void authenticateAs(UUID userUuid) {
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid.toString(), "actor",
                List.of());
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }
}

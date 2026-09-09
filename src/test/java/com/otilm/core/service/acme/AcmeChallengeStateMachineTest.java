package com.otilm.core.service.acme;

import com.otilm.api.model.core.acme.AuthorizationStatus;
import com.otilm.api.model.core.acme.ChallengeStatus;
import com.otilm.api.model.core.acme.ChallengeType;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.core.dao.entity.acme.AcmeAuthorization;
import com.otilm.core.dao.entity.acme.AcmeChallenge;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AcmeChallengeStateMachineTest {

    private static final String FAILURE_DETAIL = "No TXT record found at _acme-challenge.example.org";

    @Test
    void successfulValidationMarksTheChallengeAuthorizationAndOrder() {
        AcmeChallenge challenge = pendingChallenge();

        AcmeChallengeStateMachine.applyValidationResult(challenge, ChallengeValidationResult.success());

        Assertions.assertEquals(ChallengeStatus.VALID, challenge.getStatus());
        Assertions.assertNotNull(challenge.getValidated());
        Assertions.assertEquals(AuthorizationStatus.VALID, challenge.getAuthorization().getStatus());
        Assertions.assertEquals(OrderStatus.READY, challenge.getAuthorization().getOrder().getStatus());
    }

    @Test
    void successfulValidationRecordsNoError() {
        AcmeChallenge challenge = pendingChallenge();

        AcmeChallengeStateMachine.applyValidationResult(challenge, ChallengeValidationResult.success());

        Assertions.assertNull(challenge.getErrorProblem());
        Assertions.assertNull(challenge.getErrorDetail());
    }

    /**
     * A failed challenge invalidates its authorization and order (RFC 8555 section 7.1.6). Without this the client
     * polls a permanently pending authorization until its own request deadline expires.
     */
    @Test
    void failedValidationInvalidatesTheAuthorizationAndOrder() {
        AcmeChallenge challenge = pendingChallenge();

        AcmeChallengeStateMachine.applyValidationResult(challenge, dnsFailure());

        Assertions.assertEquals(ChallengeStatus.INVALID, challenge.getStatus());
        Assertions.assertNull(challenge.getValidated());
        Assertions.assertEquals(AuthorizationStatus.INVALID, challenge.getAuthorization().getStatus());
        Assertions.assertEquals(OrderStatus.INVALID, challenge.getAuthorization().getOrder().getStatus());
    }

    @Test
    void failedValidationRecordsTheReasonOnTheChallenge() {
        AcmeChallenge challenge = pendingChallenge();

        AcmeChallengeStateMachine.applyValidationResult(challenge, dnsFailure());

        Assertions.assertEquals(Problem.DNS, challenge.getErrorProblem());
        Assertions.assertEquals(FAILURE_DETAIL, challenge.getErrorDetail());
    }

    /**
     * An order invalidated through one of its authorizations is final. A multi-identifier order has an authorization
     * per identifier, and one of them validating later may not move the order back to ready.
     */
    @Test
    void successfulValidationDoesNotReviveAnInvalidatedOrder() {
        AcmeChallenge challenge = pendingChallenge();
        challenge.getAuthorization().getOrder().setStatus(OrderStatus.INVALID);

        AcmeChallengeStateMachine.applyValidationResult(challenge, ChallengeValidationResult.success());

        Assertions.assertEquals(ChallengeStatus.VALID, challenge.getStatus());
        Assertions.assertEquals(AuthorizationStatus.VALID, challenge.getAuthorization().getStatus());
        Assertions.assertEquals(OrderStatus.INVALID, challenge.getAuthorization().getOrder().getStatus());
    }

    /**
     * A certificate that has already been requested or issued exists regardless of a later challenge failure on the
     * order, so the order keeps its status.
     */
    @Test
    void failedValidationLeavesAnOrderWithARequestedCertificateAlone() {
        AcmeChallenge challenge = pendingChallenge();
        challenge.getAuthorization().getOrder().setStatus(OrderStatus.PROCESSING);

        AcmeChallengeStateMachine.applyValidationResult(challenge, dnsFailure());

        Assertions.assertEquals(AuthorizationStatus.INVALID, challenge.getAuthorization().getStatus());
        Assertions.assertEquals(OrderStatus.PROCESSING, challenge.getAuthorization().getOrder().getStatus());
    }

    /**
     * An authorization left pending behind a failed challenge, by an instance that did not yet propagate the failure,
     * is settled the way the failure would have been recorded.
     */
    @Test
    void settlesAPendingAuthorizationBehindAFailedChallenge() {
        AcmeChallenge failed = pendingChallenge();
        failed.setStatus(ChallengeStatus.INVALID);
        AcmeAuthorization authorization = failed.getAuthorization();
        authorization.setChallenges(Set.of(failed, siblingChallenge(authorization)));
        authorization.getOrder().setStatus(OrderStatus.READY);

        Assertions
                .assertEquals(List.of(authorization), AcmeChallengeStateMachine.settleOrder(authorization.getOrder()));

        Assertions.assertEquals(AuthorizationStatus.INVALID, authorization.getStatus());
        Assertions.assertEquals(OrderStatus.INVALID, authorization.getOrder().getStatus());
    }

    @Test
    void leavesAPendingAuthorizationWithOnlyPendingChallengesAlone() {
        AcmeChallenge pending = pendingChallenge();
        AcmeAuthorization authorization = pending.getAuthorization();
        authorization.setChallenges(Set.of(pending));

        Assertions.assertTrue(AcmeChallengeStateMachine.settleOrder(authorization.getOrder()).isEmpty());

        Assertions.assertEquals(AuthorizationStatus.PENDING, authorization.getStatus());
        Assertions.assertEquals(OrderStatus.PENDING, authorization.getOrder().getStatus());
    }

    /**
     * An authorization that became valid through its other challenge type after one failed has settled, and stays
     * valid.
     */
    @Test
    void leavesASettledAuthorizationAlone() {
        AcmeChallenge failed = pendingChallenge();
        failed.setStatus(ChallengeStatus.INVALID);
        AcmeAuthorization authorization = failed.getAuthorization();
        authorization.setStatus(AuthorizationStatus.VALID);
        authorization.setChallenges(Set.of(failed));
        authorization.getOrder().setStatus(OrderStatus.VALID);

        Assertions.assertTrue(AcmeChallengeStateMachine.settleOrder(authorization.getOrder()).isEmpty());

        Assertions.assertEquals(AuthorizationStatus.VALID, authorization.getStatus());
        Assertions.assertEquals(OrderStatus.VALID, authorization.getOrder().getStatus());
    }

    @Test
    void settlesAnOrderLeftReadyBehindAFailedAuthorization() {
        AcmeOrder order = orderWithAuthorizations(OrderStatus.READY, AuthorizationStatus.INVALID,
                AuthorizationStatus.VALID);

        Assertions.assertTrue(AcmeChallengeStateMachine.settleOrder(order).isEmpty());

        Assertions.assertEquals(OrderStatus.INVALID, order.getStatus());
    }

    /**
     * The shape an instance without failure propagation leaves behind is a failed challenge under an authorization that
     * is still pending. Settling the order settles that authorization first, so an order asked for directly is not
     * reported open, nor finalized, behind a failed challenge.
     */
    @Test
    void settlesAnOrderWhoseAuthorizationIsStillPendingBehindAFailedChallenge() {
        AcmeChallenge failed = pendingChallenge();
        failed.setStatus(ChallengeStatus.INVALID);
        AcmeAuthorization authorization = failed.getAuthorization();
        authorization.setChallenges(Set.of(failed));
        AcmeOrder order = authorization.getOrder();
        order.setStatus(OrderStatus.READY);
        order.setAuthorizations(Set.of(authorization));

        Assertions.assertEquals(List.of(authorization), AcmeChallengeStateMachine.settleOrder(order));

        Assertions.assertEquals(AuthorizationStatus.INVALID, authorization.getStatus());
        Assertions.assertEquals(OrderStatus.INVALID, order.getStatus());
    }

    @Test
    void leavesAnOrderWithoutAFailedAuthorizationAlone() {
        AcmeOrder order = orderWithAuthorizations(OrderStatus.PENDING, AuthorizationStatus.PENDING,
                AuthorizationStatus.VALID);

        Assertions.assertTrue(AcmeChallengeStateMachine.settleOrder(order).isEmpty());

        Assertions.assertEquals(OrderStatus.PENDING, order.getStatus());
    }

    @Test
    void leavesAnOrderWithARequestedCertificateAlone() {
        AcmeOrder order = orderWithAuthorizations(OrderStatus.PROCESSING, AuthorizationStatus.INVALID);

        Assertions.assertTrue(AcmeChallengeStateMachine.settleOrder(order).isEmpty());

        Assertions.assertEquals(OrderStatus.PROCESSING, order.getStatus());
    }

    private static AcmeChallenge siblingChallenge(AcmeAuthorization authorization) {
        AcmeChallenge sibling = new AcmeChallenge();
        sibling.setType(ChallengeType.HTTP01);
        sibling.setStatus(ChallengeStatus.PENDING);
        sibling.setAuthorization(authorization);
        return sibling;
    }

    private static AcmeOrder orderWithAuthorizations(OrderStatus orderStatus, AuthorizationStatus... statuses) {
        AcmeOrder order = new AcmeOrder();
        order.setStatus(orderStatus);
        Set<AcmeAuthorization> authorizations = new HashSet<>();
        for (AuthorizationStatus status : statuses) {
            AcmeAuthorization authorization = new AcmeAuthorization();
            authorization.setStatus(status);
            authorization.setOrder(order);
            authorizations.add(authorization);
        }
        order.setAuthorizations(authorizations);
        return order;
    }

    /**
     * A multi-identifier order has an authorization per identifier and may be finalized only once all of them are
     * proven, so validating one of them leaves the order pending while another is still open.
     */
    @Test
    void successfulValidationLeavesTheOrderPendingWhileASiblingAuthorizationIsStillOpen() {
        AcmeChallenge challenge = pendingChallenge();
        AcmeOrder order = challenge.getAuthorization().getOrder();
        order.getAuthorizations().add(siblingAuthorization(order, AuthorizationStatus.PENDING));

        AcmeChallengeStateMachine.applyValidationResult(challenge, ChallengeValidationResult.success());

        Assertions.assertEquals(AuthorizationStatus.VALID, challenge.getAuthorization().getStatus());
        Assertions.assertEquals(OrderStatus.PENDING, order.getStatus());
    }

    @Test
    void successfulValidationOfTheLastOpenAuthorizationMakesTheOrderReady() {
        AcmeChallenge challenge = pendingChallenge();
        AcmeOrder order = challenge.getAuthorization().getOrder();
        order.getAuthorizations().add(siblingAuthorization(order, AuthorizationStatus.VALID));

        AcmeChallengeStateMachine.applyValidationResult(challenge, ChallengeValidationResult.success());

        Assertions.assertEquals(OrderStatus.READY, order.getStatus());
    }

    @Test
    void reportsAStaleStatusOnlyForTheShapesAnOldInstanceLeavesBehind() {
        AcmeChallenge failed = pendingChallenge();
        failed.setStatus(ChallengeStatus.INVALID);
        failed.getAuthorization().setChallenges(Set.of(failed));
        Assertions.assertTrue(AcmeChallengeStateMachine.hasStaleStatus(failed.getAuthorization().getOrder()));

        AcmeOrder openBehindFailure = orderWithAuthorizations(OrderStatus.READY, AuthorizationStatus.INVALID);
        Assertions.assertTrue(AcmeChallengeStateMachine.hasStaleStatus(openBehindFailure));

        AcmeOrder consistent = orderWithAuthorizations(OrderStatus.PENDING, AuthorizationStatus.PENDING);
        Assertions.assertFalse(AcmeChallengeStateMachine.hasStaleStatus(consistent));

        AcmeOrder issued = orderWithAuthorizations(OrderStatus.VALID, AuthorizationStatus.INVALID);
        Assertions.assertFalse(AcmeChallengeStateMachine.hasStaleStatus(issued));
    }

    /**
     * A deactivated authorization can never become valid, so the order behind it cannot complete either.
     */
    @Test
    void deactivatingAnAuthorizationInvalidatesAnOpenOrder() {
        AcmeChallenge challenge = pendingChallenge();
        AcmeOrder order = challenge.getAuthorization().getOrder();
        order.setStatus(OrderStatus.READY);

        AcmeChallengeStateMachine.deactivate(challenge.getAuthorization());

        Assertions.assertEquals(AuthorizationStatus.DEACTIVATED, challenge.getAuthorization().getStatus());
        Assertions.assertEquals(OrderStatus.INVALID, order.getStatus());
    }

    @Test
    void deactivatingAnAuthorizationLeavesAnOrderWithARequestedCertificateAlone() {
        AcmeChallenge challenge = pendingChallenge();
        challenge.getAuthorization().getOrder().setStatus(OrderStatus.PROCESSING);

        AcmeChallengeStateMachine.deactivate(challenge.getAuthorization());

        Assertions.assertEquals(OrderStatus.PROCESSING, challenge.getAuthorization().getOrder().getStatus());
    }

    @Test
    void settlesAnOrderLeftOpenBehindADeactivatedAuthorization() {
        AcmeOrder order = orderWithAuthorizations(OrderStatus.PENDING, AuthorizationStatus.DEACTIVATED);

        Assertions.assertTrue(AcmeChallengeStateMachine.hasStaleStatus(order));
        AcmeChallengeStateMachine.settleOrder(order);

        Assertions.assertEquals(OrderStatus.INVALID, order.getStatus());
    }

    /**
     * An order finalized before failures were propagated can still read ready although its certificate exists; neither
     * settlement nor a late failure may invalidate it.
     */
    @Test
    void leavesAnOrderWithAnIssuedCertificateAloneWhateverItsStoredStatusSays() {
        AcmeOrder settled = orderWithAuthorizations(OrderStatus.READY, AuthorizationStatus.INVALID);
        settled.setCertificateReferenceUuid(UUID.randomUUID());

        Assertions.assertFalse(AcmeChallengeStateMachine.hasStaleStatus(settled));
        AcmeChallengeStateMachine.settleOrder(settled);
        Assertions.assertEquals(OrderStatus.READY, settled.getStatus());

        AcmeChallenge challenge = pendingChallenge();
        challenge.getAuthorization().getOrder().setStatus(OrderStatus.READY);
        challenge.getAuthorization().getOrder().setCertificateReferenceUuid(UUID.randomUUID());
        AcmeChallengeStateMachine.applyValidationResult(challenge, dnsFailure());
        Assertions.assertEquals(OrderStatus.READY, challenge.getAuthorization().getOrder().getStatus());
    }

    private static AcmeAuthorization siblingAuthorization(AcmeOrder order, AuthorizationStatus status) {
        AcmeAuthorization sibling = new AcmeAuthorization();
        sibling.setStatus(status);
        sibling.setOrder(order);
        return sibling;
    }

    private static ChallengeValidationResult dnsFailure() {
        return ChallengeValidationResult.failure(Problem.DNS, FAILURE_DETAIL);
    }

    private static AcmeChallenge pendingChallenge() {
        AcmeOrder order = new AcmeOrder();
        order.setStatus(OrderStatus.PENDING);

        AcmeAuthorization authorization = new AcmeAuthorization();
        authorization.setStatus(AuthorizationStatus.PENDING);
        authorization.setOrder(order);
        order.setAuthorizations(new HashSet<>(Set.of(authorization)));

        AcmeChallenge challenge = new AcmeChallenge();
        challenge.setType(ChallengeType.DNS01);
        challenge.setStatus(ChallengeStatus.PENDING);
        challenge.setAuthorization(authorization);
        return challenge;
    }

}

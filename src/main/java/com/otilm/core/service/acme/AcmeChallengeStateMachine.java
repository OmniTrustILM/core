package com.otilm.core.service.acme;

import com.otilm.api.model.core.acme.AuthorizationStatus;
import com.otilm.api.model.core.acme.ChallengeStatus;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.acme.AcmeAuthorization;
import com.otilm.core.dao.entity.acme.AcmeChallenge;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * Status transitions a challenge validation attempt implies for the challenge, its authorization and its order (RFC
 * 8555 section 7.1.6).
 */
public final class AcmeChallengeStateMachine {

    private AcmeChallengeStateMachine() {
    }

    /**
     * Records the outcome on the challenge and propagates it to the authorization and the order.
     *
     * <p>
     * A failed attempt invalidates both. An authorization left pending behind a failed challenge can never settle, so a
     * client waiting for it to reach a final status waits until its own request deadline expires instead of learning
     * that validation failed.
     *
     * <p>
     * Both final statuses are terminal, so this may only be applied to a pending challenge of a pending authorization.
     * Applying it to an authorization that has already settled would move it back out of a final status, which the
     * protocol does not allow.
     *
     * @param challenge the validated challenge, reached from its authorization and order
     * @param result verdict to apply
     */
    public static void applyValidationResult(AcmeChallenge challenge, ChallengeValidationResult result) {
        AcmeAuthorization authorization = challenge.getAuthorization();
        AcmeOrder order = authorization.getOrder();

        if (result.valid()) {
            challenge.setValidated(OffsetDateTime.now(ZoneOffset.UTC));
            challenge.setStatus(ChallengeStatus.VALID);
            authorization.setStatus(AuthorizationStatus.VALID);
            // An order carries an authorization per identifier and is ready to finalize only once all of them
            // have been proven (RFC 8555 section 7.1.6).
            if (order.getStatus() == OrderStatus.PENDING && order
                    .getAuthorizations()
                    .stream()
                    .allMatch(candidate -> candidate.getStatus() == AuthorizationStatus.VALID)) {
                order.setStatus(OrderStatus.READY);
            }
            return;
        }

        challenge.setStatus(ChallengeStatus.INVALID);
        challenge.setErrorProblem(result.problem());
        challenge.setErrorDetail(result.detail());
        authorization.setStatus(AuthorizationStatus.INVALID);
        invalidateOrder(order);
    }

    /**
     * Whether the order holds a status an instance without failure propagation left behind: an authorization still
     * pending behind a failed challenge, or the order still open behind a failed authorization.
     */
    public static boolean hasStaleStatus(AcmeOrder order) {
        boolean authorizationBehindFailedChallenge = order
                .getAuthorizations()
                .stream()
                .anyMatch(authorization -> authorization.getStatus() == AuthorizationStatus.PENDING && authorization
                        .getChallenges()
                        .stream()
                        .anyMatch(challenge -> challenge.getStatus() == ChallengeStatus.INVALID));
        boolean openBehindFailedAuthorization = isOpen(order)
                && order.getAuthorizations().stream().anyMatch(AcmeChallengeStateMachine::hasFailed);
        return authorizationBehindFailedChallenge || openBehindFailedAuthorization;
    }

    /**
     * Settles the authorizations of an order that are left pending behind a failed challenge, then the order itself if
     * any of its authorizations has failed.
     *
     * @return the authorizations that were settled; the order's own change shows in its status
     */
    public static List<AcmeAuthorization> settleOrder(AcmeOrder order) {
        List<AcmeAuthorization> settled = new ArrayList<>();
        for (AcmeAuthorization authorization : order.getAuthorizations()) {
            if (settleAuthorizationBehindFailedChallenge(authorization)) {
                settled.add(authorization);
            }
        }
        if (order.getAuthorizations().stream().anyMatch(AcmeChallengeStateMachine::hasFailed)) {
            invalidateOrder(order);
        }
        return settled;
    }

    private static boolean settleAuthorizationBehindFailedChallenge(AcmeAuthorization authorization) {
        if (authorization.getStatus() != AuthorizationStatus.PENDING || authorization
                .getChallenges()
                .stream()
                .noneMatch(challenge -> challenge.getStatus() == ChallengeStatus.INVALID)) {
            return false;
        }
        authorization.setStatus(AuthorizationStatus.INVALID);
        return true;
    }

    /**
     * Deactivates an authorization at the client's request (RFC 8555 section 7.5.2). The order can no longer be
     * completed, so an open order is invalidated with it.
     */
    public static void deactivate(AcmeAuthorization authorization) {
        authorization.setStatus(AuthorizationStatus.DEACTIVATED);
        invalidateOrder(authorization.getOrder());
    }

    /**
     * An authorization that has failed or been deactivated can never become valid, so its order cannot complete.
     */
    private static boolean hasFailed(AcmeAuthorization authorization) {
        return authorization.getStatus() == AuthorizationStatus.INVALID
                || authorization.getStatus() == AuthorizationStatus.DEACTIVATED;
    }

    /**
     * An order is invalidated only while it is still open. Once a certificate has been requested or issued for it, the
     * certificate exists regardless of a later failure, so the order keeps the status that reflects it.
     */
    private static boolean invalidateOrder(AcmeOrder order) {
        if (!isOpen(order)) {
            return false;
        }
        order.setStatus(OrderStatus.INVALID);
        return true;
    }

    /**
     * The status an order takes from the certificate requested for it.
     */
    public static OrderStatus statusFromCertificate(CertificateState certificateState) {
        if (certificateState == CertificateState.ISSUED) {
            return OrderStatus.VALID;
        }
        if (certificateState == CertificateState.REQUESTED || certificateState == CertificateState.PENDING_APPROVAL
                || certificateState == CertificateState.PENDING_ISSUE) {
            return OrderStatus.PROCESSING;
        }
        return OrderStatus.INVALID;
    }

    /**
     * An order is open while nothing has been issued for it. The stored status alone does not tell: an order finalized
     * before failures were propagated can still read {@code READY} although its certificate exists.
     */
    private static boolean isOpen(AcmeOrder order) {
        return order.getCertificateReferenceUuid() == null
                && (order.getStatus() == OrderStatus.PENDING || order.getStatus() == OrderStatus.READY);
    }

}

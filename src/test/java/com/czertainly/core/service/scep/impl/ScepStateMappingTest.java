package com.czertainly.core.service.scep.impl;

import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.scep.PkiStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pure unit test for {@link ScepServiceImpl#pkiStatusForCertState(CertificateState)}.
 * Verifies the SCEP {@link PkiStatus} produced for every {@link CertificateState}, including
 * the {@code PENDING_ISSUE} and {@code PENDING_REVOKE} states a connector can drive a cert into
 * by returning {@code 202 Accepted} on issue/revoke (operation accepted, completion is
 * asynchronous).
 *
 * <p>Regression guard: any future change that accidentally maps a non-terminal state to
 * something other than {@link PkiStatus#PENDING} (for example a NullPointerException
 * downstream) will fail this test.</p>
 */
class ScepStateMappingTest {

    // RFC 8894 §3.3.2 — pkiStatus values
    //   0 = SUCCESS, 2 = FAILURE, 3 = PENDING

    @Test
    void issued_maps_to_success() {
        assertEquals(PkiStatus.SUCCESS, ScepServiceImpl.pkiStatusForCertState(CertificateState.ISSUED));
    }

    @Test
    void rejected_maps_to_failure() {
        assertEquals(PkiStatus.FAILURE, ScepServiceImpl.pkiStatusForCertState(CertificateState.REJECTED));
    }

    @Test
    void failed_maps_to_failure() {
        assertEquals(PkiStatus.FAILURE, ScepServiceImpl.pkiStatusForCertState(CertificateState.FAILED));
    }

    @Test
    void requested_maps_to_pending() {
        assertEquals(PkiStatus.PENDING, ScepServiceImpl.pkiStatusForCertState(CertificateState.REQUESTED));
    }

    @Test
    void pending_approval_maps_to_pending() {
        assertEquals(PkiStatus.PENDING, ScepServiceImpl.pkiStatusForCertState(CertificateState.PENDING_APPROVAL));
    }

    @Test
    void pending_issue_maps_to_pending() {
        // Connector returned 202 on issue → cert in PENDING_ISSUE → SCEP poll must report
        // pkiPending so the client retries, not a hard failure or NPE.
        assertEquals(PkiStatus.PENDING, ScepServiceImpl.pkiStatusForCertState(CertificateState.PENDING_ISSUE));
    }

    @Test
    void pending_revoke_maps_to_pending() {
        // Connector accepted revocation with 202 → cert in PENDING_REVOKE.
        assertEquals(PkiStatus.PENDING, ScepServiceImpl.pkiStatusForCertState(CertificateState.PENDING_REVOKE));
    }

    @Test
    void revoked_maps_to_failure() {
        // REVOKED is a terminal negative state — once revoked, a SCEP-polled cert no longer
        // represents a successful issuance, so the response is FAILURE rather than PENDING
        // (which would invite the client to keep polling indefinitely).
        assertEquals(PkiStatus.FAILURE, ScepServiceImpl.pkiStatusForCertState(CertificateState.REVOKED));
    }

    @Test
    void mapping_covers_every_state_value() {
        // Sanity: ensure we have a mapping for every known state. Adding a new
        // CertificateState without updating the mapping should fail this test.
        for (CertificateState state : CertificateState.values()) {
            PkiStatus mapped = ScepServiceImpl.pkiStatusForCertState(state);
            // SUCCESS, FAILURE, and PENDING are the only valid SCEP pkiStatus values.
            assertEquals(true,
                    mapped == PkiStatus.SUCCESS || mapped == PkiStatus.FAILURE || mapped == PkiStatus.PENDING,
                    "unexpected PkiStatus " + mapped + " for state " + state);
        }
    }
}

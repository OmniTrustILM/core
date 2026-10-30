package com.otilm.core.service.scep.impl;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.core.dao.entity.scep.ScepProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the challenge password gate {@link ScepServiceImpl#validateChallengePassword}. A renewal PKCSReq
 * carries no challengePassword attribute (RFC 8894 §3.3.1.2) — it authenticates with the existing certificate's key
 * instead — so the gate must tolerate an absent request password for an authenticated renewal and reject it otherwise,
 * never dereference it blindly.
 */
class ScepServiceImplChallengePasswordTest {

    private static final String PROFILE_PASSWORD = "mysecretpassword";

    private ScepServiceImpl service;
    private ScepProfile profile;

    @BeforeEach
    void setUp() {
        service = new ScepServiceImpl();
        profile = mock(ScepProfile.class);
        ReflectionTestUtils.setField(service, "scepProfile", profile);
    }

    /** A profile that configures no challenge password never requires one. */
    @ParameterizedTest(name = "profile password [{0}]")
    @NullAndEmptySource
    void profileWithoutChallengePassword_passes(String profileChallengePassword) {
        when(profile.getChallengePassword()).thenReturn(profileChallengePassword);

        assertDoesNotThrow(() -> service.validateChallengePassword(null, false));
    }

    /**
     * The waiver covers an absent password — including a present-but-empty attribute, which clients (and our own jscep
     * guide) are commonly configured to send on renewal. A password carrying a value is accepted only when it matches.
     */
    @ParameterizedTest(name = "request password [{0}], authenticated renewal {1}")
    @CsvSource(nullValues = "NULL", value = {
            // matches PROFILE_PASSWORD on an initial enrollment
            "mysecretpassword, false",
            // renewal omits the attribute
            "NULL,             true",
            // renewal sends the attribute empty
            "'',               true"})
    void acceptedChallengePassword(String requestChallengePassword, boolean authenticatedRenewal) {
        when(profile.getChallengePassword()).thenReturn(PROFILE_PASSWORD);

        assertDoesNotThrow(() -> service.validateChallengePassword(requestChallengePassword, authenticatedRenewal));
    }

    /**
     * A wrong password is rejected whether or not the request is a renewal: the waiver never silently accepts a
     * supplied credential that does not match. An empty attribute is rejected wherever the shared secret is actually
     * required.
     */
    @ParameterizedTest(name = "request password [{0}], authenticated renewal {1}")
    @CsvSource(nullValues = "NULL", value = {
            // wrong password on an initial enrollment
            "wrong, false",
            // wrong password on an otherwise authenticated renewal
            "wrong, true",
            // empty attribute where the shared secret is required
            "'',    false"})
    void rejectedChallengePassword(String requestChallengePassword, boolean authenticatedRenewal) {
        when(profile.getChallengePassword()).thenReturn(PROFILE_PASSWORD);

        ScepException thrown = assertThrows(ScepException.class,
                () -> service.validateChallengePassword(requestChallengePassword, authenticatedRenewal));
        assertEquals(FailInfo.BAD_MESSAGE_CHECK, thrown.getFailInfo());
    }

    /**
     * The reported crash (issue #1887): a renewal-style PKCSReq without a challengePassword against a profile that has
     * one configured must yield a SCEP rejection, not a {@code NullPointerException}.
     */
    @Test
    void absentRequestPassword_notARenewal_rejectedWithBadMessageCheck() {
        when(profile.getChallengePassword()).thenReturn(PROFILE_PASSWORD);

        ScepException thrown = assertThrows(ScepException.class, () -> service.validateChallengePassword(null, false));
        assertEquals(FailInfo.BAD_MESSAGE_CHECK, thrown.getFailInfo());
    }
}

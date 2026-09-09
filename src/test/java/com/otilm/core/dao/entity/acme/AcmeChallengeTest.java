package com.otilm.core.dao.entity.acme;

import com.otilm.api.model.core.acme.Challenge;
import com.otilm.api.model.core.acme.ChallengeStatus;
import com.otilm.api.model.core.acme.ChallengeType;
import com.otilm.api.model.core.acme.Problem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class AcmeChallengeTest {

    private static final String FAILURE_DETAIL = "No TXT record found at _acme-challenge.example.org";

    @BeforeEach
    void bindRequest() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    @AfterEach
    void unbindRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * A failed challenge carries the reason as a problem document so the client can report why validation failed (RFC
     * 8555 section 8).
     */
    @Test
    void reportsTheRecordedFailureAsAProblemDocument() {
        AcmeChallenge challenge = challenge();
        challenge.setStatus(ChallengeStatus.INVALID);
        challenge.setErrorProblem(Problem.DNS);
        challenge.setErrorDetail(FAILURE_DETAIL);

        Challenge dto = challenge.mapToDto();

        Assertions.assertNotNull(dto.getError());
        Assertions.assertEquals(Problem.DNS.getType(), dto.getError().getType());
        Assertions.assertEquals(Problem.DNS.getTitle(), dto.getError().getTitle());
        Assertions.assertEquals(FAILURE_DETAIL, dto.getError().getDetail());
    }

    @Test
    void reportsNoErrorWhenNoFailureWasRecorded() {
        Assertions.assertNull(challenge().mapToDto().getError());
    }

    /**
     * The shared {@link Problem} constants must keep their own detail, so recording a challenge failure may not write
     * through to them.
     */
    @Test
    void leavesTheSharedProblemConstantUntouched() {
        String detailBefore = Problem.DNS.getDetail();
        AcmeChallenge challenge = challenge();
        challenge.setErrorProblem(Problem.DNS);
        challenge.setErrorDetail(FAILURE_DETAIL);

        challenge.mapToDto();

        Assertions.assertEquals(detailBefore, Problem.DNS.getDetail());
    }

    private static AcmeChallenge challenge() {
        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setName("test-profile");

        AcmeAccount acmeAccount = new AcmeAccount();
        acmeAccount.setAcmeProfile(acmeProfile);

        AcmeOrder order = new AcmeOrder();
        order.setAcmeAccount(acmeAccount);

        AcmeAuthorization authorization = new AcmeAuthorization();
        authorization.setOrder(order);

        AcmeChallenge challenge = new AcmeChallenge();
        challenge.setChallengeId("challenge-1");
        challenge.setType(ChallengeType.DNS01);
        challenge.setStatus(ChallengeStatus.PENDING);
        challenge.setToken("token");
        challenge.setAuthorization(authorization);
        return challenge;
    }

}

package com.otilm.core.service.acme;

import com.otilm.api.model.core.acme.Problem;

/**
 * Verdict of a single challenge validation attempt.
 *
 * <p>
 * A failed attempt carries the reason to record on the challenge, which the client reads back as a problem document.
 * The detail is therefore authored text, never a resolver response, a served response body or an exception message.
 *
 * @param valid whether the client proved control of the identifier
 * @param problem ACME problem type of a failed attempt, {@code null} when valid
 * @param detail reason of a failed attempt, {@code null} when valid
 */
public record ChallengeValidationResult(boolean valid, Problem problem, String detail) {

    private static final ChallengeValidationResult SUCCESS = new ChallengeValidationResult(true, null, null);

    public static ChallengeValidationResult success() {
        return SUCCESS;
    }

    public static ChallengeValidationResult failure(Problem problem, String detail) {
        return new ChallengeValidationResult(false, problem, detail);
    }

}

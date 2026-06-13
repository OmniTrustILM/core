package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.model.signing.TspProfileModel;
import jakarta.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.List;

/**
 * Writes the {@code 401 Unauthorized} response for a TSP request, advertising via {@code WWW-Authenticate}
 * only the HTTP-level authentication schemes the client can actually retry with — {@code Basic} / {@code Bearer}.
 *
 * <p>When the TSP Profile accepts only a client certificate or cannot be resolved, there is no honest, client-actionable
 * HTTP challenge: the response is still 401, but the {@code WWW-Authenticate} header is omitted.
 */
public class TspChallengeWriter {

    public void send401(HttpServletResponse response, TspProfileModel profile) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String challenge = buildChallenge(profile);
        if (challenge != null) {
            response.setHeader("WWW-Authenticate", challenge);
        }
    }

    private String buildChallenge(TspProfileModel profile) {
        List<TspAuthenticationMethod> methods = profile == null ? List.of() : profile.allowedAuthenticationMethods();
        List<String> challenges = new ArrayList<>();
        if (methods.contains(TspAuthenticationMethod.BASIC_PASSWORD)) {
            challenges.add("Basic realm=\"" + profile.name() + "\"");
        }
        if (methods.contains(TspAuthenticationMethod.BEARER_TOKEN)) {
            challenges.add("Bearer");
        }
        return challenges.isEmpty() ? null : String.join(", ", challenges);
    }
}

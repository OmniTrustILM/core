package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.model.signing.TspProfileModel;
import jakarta.servlet.http.HttpServletRequest;

/**
 * One TSP authentication method (certificate / bearer token / basic password). Each strategy detects whether
 * its method is presented on the request and, if so, attempts to authenticate it — populating the
 * {@link org.springframework.security.core.context.SecurityContext} on success.
 */
public interface TspAuthenticator {

    /** The authentication method this strategy handles, matched against the TSP Profile's allowed set. */
    TspAuthenticationMethod method();

    /** Whether this method is the one presented on the request (header-based detection). */
    boolean canHandle(HttpServletRequest request);

    /**
     * Attempts authentication for the presented method against the governing profile. On success the
     * {@link org.springframework.security.core.context.SecurityContext} is populated. Must fail closed
     * (return {@code false}) on any malformed input or upstream failure.
     */
    boolean authenticate(HttpServletRequest request, TspProfileModel profile);
}

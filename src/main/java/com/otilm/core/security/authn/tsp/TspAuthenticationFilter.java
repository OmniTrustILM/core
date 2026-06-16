package com.otilm.core.security.authn.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Security filter for the TSP timestamping endpoints. Runs before any {@link SecurityContext} exists and is the sole
 * gate deciding <em>which</em> authentication method a given TSP Profile accepts.
 *
 * <p>It orchestrates three collaborators, each with a single responsibility:
 * <ol>
 *   <li>{@link TspRouteResolver} — resolve the governing TSP Profile from the request path.</li>
 *   <li>{@link TspAuthenticator} strategies — detect the presented method and resolve identity, populating the
 *       {@link SecurityContext} with a {@link PlatformAuthenticationToken} on success.</li>
 *   <li>{@link TspChallengeWriter} — on any failure, write 401 with a {@code WWW-Authenticate} header listing the
 *       acceptable methods, and do <strong>not</strong> continue the chain.</li>
 * </ol>
 *
 * <p>The authenticator order matters: the first whose {@link TspAuthenticator#canHandle} matches wins, so a
 * presented client certificate takes precedence over an {@code Authorization} header.
 */
public class TspAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TspAuthenticationFilter.class);

    private final TspRouteResolver routeResolver;
    private final List<TspAuthenticator> authenticators;
    private final TspChallengeWriter challengeWriter;

    public TspAuthenticationFilter(TspRouteResolver routeResolver, List<TspAuthenticator> authenticators,
                                   TspChallengeWriter challengeWriter) {
        this.routeResolver = routeResolver;
        this.authenticators = authenticators;
        this.challengeWriter = challengeWriter;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        return !routeResolver.matches(request.getServletPath());
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        TspProfileModel profile;
        try {
            Optional<TspProfileModel> resolved = routeResolver.resolve(request);
            if (resolved.isEmpty()) {
                reject(response, null);
                return;
            }
            profile = resolved.get();
        } catch (NotFoundException e) {
            log.warn("TSP authentication: TSP profile not found for '{}': {}", request.getRequestURI(), e.getMessage());
            reject(response, null);
            return;
        }

        TspAuthenticator authenticator = authenticators.stream()
                .filter(candidate -> candidate.canHandle(request))
                .findFirst()
                .orElse(null);
        if (authenticator == null || !profile.allowedAuthenticationMethods().contains(authenticator.method())) {
            TspAuthenticationMethod presented = authenticator == null ? null : authenticator.method();
            log.warn("TSP authentication: presented authentication method '{}' not allowed for profile '{}'.", presented, profile.name());
            reject(response, profile);
            return;
        }

        if (!authenticator.authenticate(request, profile)) {
            reject(response, profile);
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Clears any {@link SecurityContext} and actor MDC attribution an authenticator may have partially populated, so a
     * rejected request leaks no identity onto the request thread, then writes the 401 challenge.
     */
    private void reject(HttpServletResponse response, TspProfileModel profile) {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
        challengeWriter.send401(response, profile);
    }
}

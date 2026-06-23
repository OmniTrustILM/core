package com.otilm.core.security.authn.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.service.SigningProfileService;
import com.otilm.core.service.TspProfileService;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

/**
 * Maps a TSP timestamping request path to the governing {@link TspProfileModel}. This is the single place
 * that understands the endpoint layout:
 * <ul>
 *   <li>direct route {@code /v1/protocols/tsp/{name}} → the named TSP Profile, and</li>
 *   <li>indirect route {@code /v1/protocols/tsp/signingProfiles/{name}} → the TSP Profile linked to the
 *       named Signing Profile.</li>
 * </ul>
 * Both resolution methods are cache-backed and run before any {@code SecurityContext} exists.
 */
public class TspRouteResolver {

    private static final String TSP_PATH_PREFIX = "/v1/protocols/tsp/";
    private static final String SIGNING_PROFILES_SEGMENT = "signingProfiles/";

    private final TspProfileService tspProfileService;
    private final SigningProfileService signingProfileService;

    public TspRouteResolver(TspProfileService tspProfileService, SigningProfileService signingProfileService) {
        this.tspProfileService = tspProfileService;
        this.signingProfileService = signingProfileService;
    }

    /** Whether the given servlet path is a TSP timestamping endpoint this filter must gate. */
    public boolean matches(String servletPath) {
        return extractPathName(servletPath) != null;
    }

    public Optional<TspProfileModel> resolve(HttpServletRequest request) throws NotFoundException {
        String pathName = extractPathName(request.getServletPath());
        if (pathName == null) {
            return Optional.empty();
        }
        if (pathName.startsWith(SIGNING_PROFILES_SEGMENT)) {
            String signingProfileName = pathName.substring(SIGNING_PROFILES_SEGMENT.length());
            return signingProfileService.resolveTspProfileForSigningProfileAuthentication(signingProfileName);
        }
        return Optional.of(tspProfileService.resolveTspProfileForAuthentication(pathName));
    }

    /**
     * Extracts the single profile-name segment from the servlet path, anchoring on the exact {@code /v1/protocols/tsp/}.
     * Returns:
     * <ul>
     *   <li>the TSP Profile name for the direct route {@code /v1/protocols/tsp/{name}}, or</li>
     *   <li>{@code signingProfiles/<signingProfileName>} for the indirect route
     *       {@code /v1/protocols/tsp/signingProfiles/{name}}, or</li>
     *   <li>{@code null} when the path is not a single-segment TSP timestamping endpoint.</li>
     * </ul>
     */
    private String extractPathName(String servletPath) {
        if (servletPath == null || !servletPath.startsWith(TSP_PATH_PREFIX)) {
            return null;
        }
        String middle = servletPath.substring(TSP_PATH_PREFIX.length());
        if (middle.startsWith(SIGNING_PROFILES_SEGMENT)) {
            String signingProfileName = middle.substring(SIGNING_PROFILES_SEGMENT.length());
            return isSingleSegment(signingProfileName) ? middle : null;
        }
        return isSingleSegment(middle) ? middle : null;
    }

    private boolean isSingleSegment(String name) {
        return !name.isBlank() && name.indexOf('/') < 0;
    }
}

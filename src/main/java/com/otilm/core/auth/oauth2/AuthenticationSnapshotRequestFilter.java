package com.otilm.core.auth.oauth2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Bounds the lifetime of {@link AuthenticationSnapshotRequestHolder} to a single request.
 *
 * <p>
 * Registered as the outermost filter so that it encloses every filter chain that can publish a snapshot - the
 * resource-server chain that runs {@link PlatformJwtDecoder} for bearer tokens and the TSP chain that calls the decoder
 * directly. It clears on the way in as well as in a {@code finally} block on the way out, so the holder is empty both
 * before any component of this request can read it and after this request is done with the pooled thread, whatever the
 * outcome of the chain.
 */
public class AuthenticationSnapshotRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        AuthenticationSnapshotRequestHolder.clear();
        try {
            filterChain.doFilter(request, response);
        } finally {
            AuthenticationSnapshotRequestHolder.clear();
        }
    }
}

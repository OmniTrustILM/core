package com.otilm.core.config.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Bounds the lifetime of the MDC to a single request.
 *
 * <p>
 * Registered as the outermost filter so that it encloses the authentication filters that name the request's actor in
 * the MDC as well as the handler whose audit records read it. It clears the MDC on the way in as well as in a
 * {@code finally} block on the way out, so a request neither sees what its pooled thread held before it nor leaves
 * anything there, whatever the outcome - a handler that threw, or a refusal before any handler was reached.
 */
public class MdcRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        MDC.clear();
        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.clear();
        }
    }
}

package com.otilm.core.config;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.util.AuthHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Component
public class ProtocolValidationFilter extends OncePerRequestFilter {

    private HandlerExceptionResolver resolver;

    private AuthHelper authHelper;

    @Autowired
    public void setAuthHelper(AuthHelper authHelper) {
        this.authHelper = authHelper;
    }

    @Autowired
    public void setHandlerExceptionResolver(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Value("${server.servlet.context-path}")
    private String context;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        String prefixRegex = "^%s/v\\d*/protocols/".formatted(context);

        if (!requestUri.matches(prefixRegex + ".*$")) {
            filterChain.doFilter(request, response);
        } else if (requestUri.matches(prefixRegex + "scep/.*$")) {
            logger.info("SCEP Request from " + request.getRemoteAddr() + " for " + requestUri);
            authHelper.authenticateAsSystemUser(AuthHelper.SCEP_USERNAME);
            filterChain.doFilter(request, response);
        } else if (requestUri.matches(prefixRegex + "acme/.*$")) {
            logger.info("ACME Request from " + request.getRemoteAddr() + " for " + requestUri);
            authHelper.authenticateAsSystemUser(AuthHelper.ACME_USERNAME);
            filterChain.doFilter(request, response);
        } else if (requestUri.matches(prefixRegex + "cmp/.*$")) {
            logger.info("CMPv2 Request from " + request.getRemoteAddr() + " for " + requestUri);
            authHelper.authenticateAsSystemUser(AuthHelper.CMP_USERNAME);
            filterChain.doFilter(request, response);
        } else if (requestUri.matches(prefixRegex + "tsp/.*$")) {
            // TSP requests are authenticated by the dedicated TSP security chain.
            filterChain.doFilter(request, response);
        } else {
            resolver.resolveException(request, response, null, new ValidationException("Invalid protocol request"));
        }

    }
}

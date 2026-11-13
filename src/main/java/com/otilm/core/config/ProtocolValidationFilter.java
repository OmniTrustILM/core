package com.otilm.core.config;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.service.est.message.EstBoundedRequest;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstRequestGuard;
import com.otilm.core.service.est.message.EstResponses;
import com.otilm.core.util.AuthHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Slf4j
@Component
public class ProtocolValidationFilter extends OncePerRequestFilter {

    private static final String EST_PATH_REGEX = "\\.well-known/est/";

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
        } else if (requestUri.matches(prefixRegex + EST_PATH_REGEX + ".*$")) {
            logger.info("EST Request from " + request.getRemoteAddr() + " for " + requestUri);
            String operationPath = requestUri.replaceFirst(prefixRegex + EST_PATH_REGEX, "");
            filterEstRequest(request, response, filterChain, operationPath);
        } else if (requestUri.matches(prefixRegex + "tsp/.*$")) {
            // TSP requests are authenticated by the dedicated TSP security chain.
            filterChain.doFilter(request, response);
        } else {
            resolver.resolveException(request, response, null, new ValidationException("Invalid protocol request"));
        }

    }

    private void filterEstRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain,
            String operationPath) throws ServletException, IOException {
        String method = request.getMethod();
        Optional<EstError> refusal = EstRequestGuard
                .check(method, operationPath, request.getContentType(), request.getContentLengthLong());
        if (refusal.isPresent()) {
            EstError error = refusal.get();
            // the INFO line above already names the path, so the refusal adds only the reason and the method
            log.warn("EST request refused as {} for method {}", error, method);
            EstResponses.write(response, error, EstRequestGuard.allowedMethod(operationPath));
            return;
        }
        authHelper.authenticateAsSystemUser(AuthHelper.EST_USERNAME);
        filterChain.doFilter(new EstBoundedRequest(request, EstRequestGuard.MAX_BODY_BYTES), response);
    }
}

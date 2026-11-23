package com.otilm.core.security.ai;

import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.RuntimeErrorCode;
import com.otilm.ai.runtime.protocol.RuntimeErrorReply;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/** A separate closed chain never invokes ordinary bearer, cookie or platform authentication. */
@Configuration(proxyBeanMethods = false)
public class AiRuntimeRunnerSecurityConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(AiRuntimeRunnerSecurityConfiguration.class);
    private static final String BOOTSTRAP = "/internal/ai-runtime/v1/runner/bootstrap";
    private static final String HEARTBEAT = "/internal/ai-runtime/v1/runner/claims/heartbeat";
    private static final String REDEEM = "/internal/ai-runtime/v1/gateway/run/redeem";
    private static final String OUTCOME = "/internal/ai-runtime/v1/gateway/run/outcomes";
    private static final String MANAGEMENT_REDEEM = "/internal/ai-management/v1/gateway/redeem";
    private static final String MANAGEMENT_OUTCOME = "/internal/ai-management/v1/gateway/outcomes";
    private static final String REGISTRATION = "/internal/ai-runtime/v1/gateway/run/registration";
    private static final String MANAGEMENT_REGISTRATION = "/internal/ai-management/v1/gateway/registration";
    private static final String CONTROLLER_RECONCILE = "/internal/ai-runtime/v1/controller/launches/reconcile";
    private static final String CONTROLLER_REGISTER = "/internal/ai-runtime/v1/controller/workloads/register";
    private static final String CONTROLLER_STATUS = "/internal/ai-runtime/v1/controller/workloads/status";
    private static final String CONTROLLER_CLEANUP = "/internal/ai-runtime/v1/controller/cleanup/reconcile";
    private static final String CONTROLLER_GATEWAY_RUN = "/internal/ai-runtime/v1/controller/gateways/run/observe";
    private static final String CONTROLLER_GATEWAY_MANAGEMENT = "/internal/ai-management/v1/controller/gateway/observe";
    private static final Pattern JSON_UTF8 = Pattern
            .compile("(?i)[ \\t]*application/json[ \\t]*(?:;[ \\t]*charset[ \\t]*=[ \\t]*(?:UTF-8|\"UTF-8\")[ \\t]*)?");
    private final ProtocolCodec codec = new ProtocolCodec();

    @Bean
    @Order(0)
    public SecurityFilterChain runtimeRunnerSecurityFilterChain(HttpSecurity http) {
        http
                .securityMatcher("/internal/ai-runtime/**", "/internal/ai-management/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, BOOTSTRAP, HEARTBEAT, REDEEM, OUTCOME, MANAGEMENT_REDEEM,
                                MANAGEMENT_OUTCOME, CONTROLLER_RECONCILE, CONTROLLER_REGISTER, CONTROLLER_STATUS,
                                CONTROLLER_CLEANUP, CONTROLLER_GATEWAY_RUN, CONTROLLER_GATEWAY_MANAGEMENT)
                        .access((authentication, context) -> new AuthorizationDecision(
                                context.getRequest().getDispatcherType() == DispatcherType.REQUEST
                                        && matchingPeer(context.getRequest())))
                        .requestMatchers(HttpMethod.GET, REGISTRATION, MANAGEMENT_REGISTRATION)
                        .access((authentication, context) -> new AuthorizationDecision(
                                context.getRequest().getDispatcherType() == DispatcherType.REQUEST
                                        && matchingPeer(context.getRequest())))
                        .anyRequest()
                        .denyAll())
                .sessionManagement(AbstractHttpConfigurer::disable)
                .securityContext(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .oauth2Login(AbstractHttpConfigurer::disable)
                .oauth2Client(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(AbstractHttpConfigurer::disable)
                .x509(AbstractHttpConfigurer::disable)
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, failure) -> denied(request, response))
                        .accessDeniedHandler((request, response, failure) -> denied(request, response)))
                .addFilterBefore(new MetadataGate(), AuthorizationFilter.class);
        return http.build();
    }

    private void denied(HttpServletRequest request, HttpServletResponse response) throws IOException {
        boolean peer = RuntimeProxyTransport.currentWorkloadPeer().isPresent();
        error(request, response, peer ? RuntimeErrorCode.DENIED : RuntimeErrorCode.UNAUTHENTICATED, peer ? 403 : 401);
    }

    private void error(HttpServletRequest request, HttpServletResponse response, RuntimeErrorCode code, int status)
            throws IOException {
        UUID correlation = UUID.randomUUID();
        byte[] bytes = codec.writeRuntimeError(new RuntimeErrorReply(1, code, correlation));
        String operation = operation(request);
        if (operation != null) {
            LOG.debug("AI runtime operation={} code={} correlation={}", operation, code.name(), correlation);
        }
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }

    private static String operation(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if ("GET".equals(request.getMethod())) {
            return switch (path) {
                case REGISTRATION -> "registration";
                case MANAGEMENT_REGISTRATION -> "management-registration";
                default -> null;
            };
        }
        if (!"POST".equals(request.getMethod())) {
            return null;
        }
        return switch (path) {
            case BOOTSTRAP -> "bootstrap";
            case HEARTBEAT -> "heartbeat";
            case REDEEM -> "redeem";
            case OUTCOME -> "outcome";
            case MANAGEMENT_REDEEM -> "management-redeem";
            case MANAGEMENT_OUTCOME -> "management-outcome";
            case CONTROLLER_RECONCILE -> "controller-reconcile";
            case CONTROLLER_REGISTER -> "controller-register";
            case CONTROLLER_STATUS -> "controller-status";
            case CONTROLLER_CLEANUP -> "controller-cleanup";
            case CONTROLLER_GATEWAY_RUN -> "controller-gateway-run";
            case CONTROLLER_GATEWAY_MANAGEMENT -> "controller-gateway-management";
            default -> null;
        };
    }

    private static boolean matchingPeer(HttpServletRequest request) {
        String operation = operation(request);
        if (operation == null) {
            return false;
        }
        RuntimePeerRole expected = switch (operation) {
            case "bootstrap", "heartbeat" -> RuntimePeerRole.RUNNER_PROXY;
            case "management-redeem", "management-outcome", "management-registration" ->
                RuntimePeerRole.GATEWAY_MANAGEMENT;
            case "controller-reconcile", "controller-register", "controller-status", "controller-cleanup",
                    "controller-gateway-run", "controller-gateway-management" ->
                RuntimePeerRole.CONTROLLER;
            default -> RuntimePeerRole.GATEWAY_RUN;
        };
        return RuntimeProxyTransport.currentWorkloadPeer().filter(peer -> peer.role() == expected).isPresent();
    }

    private static int maximumBody(HttpServletRequest request) {
        return switch (operation(request)) {
            case "redeem", "management-redeem" -> 8192;
            case "outcome", "management-outcome" -> 1_500_000;
            default -> 4096;
        };
    }

    private static boolean jsonUtf8(HttpServletRequest request) {
        var values = request.getHeaders("Content-Type");
        if (values == null || !values.hasMoreElements()) {
            return false;
        }
        String value = values.nextElement();
        return !values.hasMoreElements() && value.length() <= 128 && JSON_UTF8.matcher(value).matches();
    }

    private final class MetadataGate extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!matchingPeer(request) || request.getDispatcherType() != DispatcherType.REQUEST) {
                chain.doFilter(request, response);
                return;
            }
            String operation = operation(request);
            if ("controller-gateway-run".equals(operation) || "controller-gateway-management".equals(operation)) {
                if (request.getQueryString() != null || request.getContentLengthLong() > 0
                        || request.getHeader("Transfer-Encoding") != null
                        || request.getHeader("Content-Encoding") != null || request.getHeader("Authorization") != null
                        || request.getHeader("Cookie") != null || request.getHeader("Cookie2") != null
                        || request.getHeader("Content-Type") != null && !jsonUtf8(request)) {
                    error(request, response, RuntimeErrorCode.INVALID_REQUEST, 400);
                    return;
                }
                chain.doFilter(request, response);
                return;
            }
            if ("GET".equals(request.getMethod())) {
                if (request.getQueryString() != null || request.getContentLengthLong() > 0
                        || request.getHeader("Transfer-Encoding") != null || request.getHeader("Content-Type") != null
                        || request.getHeader("Content-Encoding") != null || request.getHeader("Authorization") != null
                        || request.getHeader("Cookie") != null || request.getHeader("Cookie2") != null) {
                    error(request, response, RuntimeErrorCode.INVALID_REQUEST, 400);
                    return;
                }
                chain.doFilter(request, response);
                return;
            }
            if (request.getContentLengthLong() > maximumBody(request)) {
                error(request, response, RuntimeErrorCode.LIMIT_EXCEEDED, 413);
                return;
            }
            if (request.getHeader("Content-Encoding") != null || !jsonUtf8(request)) {
                error(request, response, RuntimeErrorCode.INVALID_REQUEST, 400);
                return;
            }
            chain.doFilter(request, response);
        }
    }
}

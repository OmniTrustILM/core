package com.czertainly.core.security.authn;

import com.czertainly.api.model.core.logging.enums.AuthMethod;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authn.client.CzertainlyAuthenticationClient;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.CertificateUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

public class CzertainlyAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CzertainlyAuthenticationFilter.class);

    private final String certificateHeaderName;
    private final CzertainlyAuthenticationClient authClient;

    private final String context;


    public CzertainlyAuthenticationFilter(CzertainlyAuthenticationClient authClient, final String certificateHeaderName, final String context) {
        this.authClient = authClient;
        this.context = context;
        this.certificateHeaderName = certificateHeaderName;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (isAuthenticationNeeded(request)) {
            log.trace("Going to authenticate the '{}' request on '{}'.", request.getMethod(), request.getRequestURI());

            try {
                AuthenticationInfo authInfo;
                String rawCertHeader = request.getHeader(certificateHeaderName);
                if (rawCertHeader != null) {
                    authInfo = authenticateByCertificate(rawCertHeader);
                } else {
                    authInfo = authClient.authenticate(AuthMethod.NONE, null, isLocalhostAddress(request));
                }

                Authentication authentication;
                if (authInfo.isAnonymous()) {
                    authentication = new CzertainlyAnonymousToken(UUID.randomUUID().toString(), new CzertainlyUserDetails(authInfo), authInfo.getAuthorities());
                } else {
                    authentication = new CzertainlyAuthenticationToken(new CzertainlyUserDetails(authInfo));
                }

                updateSecurityContext(authentication);

            } catch (AuthenticationException e) {
                SecurityContextHolder.clearContext();
                if (e instanceof CzertainlyAuthenticationException) {
                    log.warn("Authentication request for '{}' failed: {}", request.getRequestURI(), e.getMessage());
                } else {
                    throw e;
                }
            }
        }
        filterChain.doFilter(request, response);
    }

    private static void updateSecurityContext(Authentication authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
        CzertainlyUserDetails userDetails = (CzertainlyUserDetails) authentication.getPrincipal();
        if (userDetails.getAuthMethod() == AuthMethod.CERTIFICATE) {
            log.debug("User with username '{}' has been successfully authenticated with certificate.", userDetails.getUsername());
        } else {
            log.debug("User has not been identified, using anonymous user.");
        }
    }

    private AuthenticationInfo authenticateByCertificate(String rawCertHeader) {
        AuthenticationInfo authInfo;
        try {
            String decoded = URLDecoder.decode(rawCertHeader, StandardCharsets.UTF_8);
            byte[] derBytes = Base64.getDecoder().decode(CertificateUtil.normalizeCertificateContent(decoded));
            String thumbprint = CertificateUtil.getThumbprint(derBytes);
            authInfo = authClient.authenticateByCertificate(rawCertHeader, thumbprint);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        } catch (IllegalArgumentException e) {
            throw new CzertainlyAuthenticationException("Invalid certificate header: " + e.getMessage(), e);
        }
        return authInfo;
    }

    private boolean isAuthenticationNeeded(final HttpServletRequest request) {
        SecurityContext securityContext = SecurityContextHolder.getContext();

        if (AuthHelper.permitAllEndpointInRequest(request.getRequestURI(), context) || (AuthHelper.oauth2EndpointInRequest(request.getRequestURI(), context) && securityContext.getAuthentication() == null)) {
            log.trace("Endpoint {} does not need authentication, using anonymous user.", request.getRequestURI());
            AuthenticationInfo authenticationInfo = AuthenticationInfo.getAnonymousAuthenticationInfo();
            CzertainlyAnonymousToken authentication = new CzertainlyAnonymousToken(UUID.randomUUID().toString(), new CzertainlyUserDetails(authenticationInfo), authenticationInfo.getAuthorities());
            authentication.setAccessingPermitAllEndpoint(true);
            SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
            emptyContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(emptyContext);
            return false;
        }

        // User is already authenticated and is not anonymous user
        if (securityContext != null && securityContext.getAuthentication() != null && securityContext.getAuthentication().isAuthenticated()) {
            log.trace("The user {} is already authenticated. Will not re-authenticate.", securityContext.getAuthentication().getName());
            return false;
        }

        // If there is no token header, user will need to be authenticated in this filter
        return request.getHeader("Authorization") == null || request.getHeader(certificateHeaderName) != null;

    }

    private boolean isLocalhostAddress(HttpServletRequest request) {
        boolean isLocalhostAddress;
        String ipAddress = AuthHelper.getClientIPAddress(request);
        try {
            InetAddress address = InetAddress.getByName(ipAddress);
            isLocalhostAddress = address.isAnyLocalAddress() || address.isLoopbackAddress();
        } catch (UnknownHostException ignored) {
            isLocalhostAddress = false;
        }
        return isLocalhostAddress;
    }

}


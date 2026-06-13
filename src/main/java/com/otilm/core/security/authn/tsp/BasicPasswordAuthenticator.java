package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authn.client.CredentialVerificationCache;
import com.otilm.core.util.SecretsUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * Authenticates a TSP request presenting HTTP Basic credentials. Verifies the presented password against the
 * stored credential fingerprint (positive results cached), then proxies as the mapped user. Never touches
 * secret values beyond computing the verification fingerprint.
 */
public class BasicPasswordAuthenticator implements TspAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(BasicPasswordAuthenticator.class);
    private static final String BASIC_PREFIX = "Basic ";

    private final CredentialVerificationCache credentialVerificationCache;
    private final TspSecurityContextWriter contextWriter;

    public BasicPasswordAuthenticator(CredentialVerificationCache credentialVerificationCache,
                                      TspSecurityContextWriter contextWriter) {
        this.credentialVerificationCache = credentialVerificationCache;
        this.contextWriter = contextWriter;
    }

    @Override
    public TspAuthenticationMethod method() {
        return TspAuthenticationMethod.BASIC_PASSWORD;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        return authorization != null && authorization.startsWith(BASIC_PREFIX);
    }

    @Override
    public boolean authenticate(HttpServletRequest request, TspProfileModel profile) {
        String[] credentials = decodeBasicCredentials(request.getHeader(HttpHeaders.AUTHORIZATION));
        if (credentials == null) {
            return false;
        }
        String username = credentials[0];
        String password = credentials[1];
        if (username.isBlank() || password.isBlank()) {
            log.warn("TSP authentication: blank Basic username or password for profile '{}'.", profile.name());
            return false;
        }

        TspProfileModel.BasicCredentialRef credential = profile.basicCredentials().stream()
                .filter(ref -> ref.username().equals(username))
                .findFirst()
                .orElse(null);
        if (credential == null) {
            // Compute and discard a fingerprint to prevent side-channel timing attacks.
            computeFingerprint(username, password, profile);
            log.warn("TSP authentication: no Basic credential for the presented username on profile '{}'.", profile.name());
            return false;
        }

        UUID secretUuid = credential.secretUuid();

        Optional<UUID> cached = credentialVerificationCache.getMappedUser(secretUuid, password);
        if (cached.isPresent()) {
            return contextWriter.authenticateAsUser(cached.get());
        }

        String candidate = computeFingerprint(username, password, profile);
        if (candidate == null) {
            return false;
        }

        String stored = credential.fingerprint();
        if (stored == null || !MessageDigest.isEqual(
                candidate.getBytes(StandardCharsets.UTF_8),
                stored.getBytes(StandardCharsets.UTF_8))) {
            log.warn("TSP authentication: Basic credential fingerprint mismatch for profile '{}'.", profile.name());
            return false;
        }

        credentialVerificationCache.putSuccess(secretUuid, password, credential.mappedUserUuid());
        return contextWriter.authenticateAsUser(credential.mappedUserUuid());
    }

    private String computeFingerprint(String username, String password, TspProfileModel profile) {
        try {
            return SecretsUtil.calculateSecretContentFingerprint(new BasicAuthSecretContent(username, password));
        } catch (Exception e) {
            log.warn("TSP authentication: failed to compute credential fingerprint for profile '{}': {}", profile.name(), e.getMessage());
            return null;
        }
    }

    private String[] decodeBasicCredentials(String authorization) {
        try {
            String encoded = authorization.substring(BASIC_PREFIX.length()).trim();
            String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                return null;
            }
            return new String[]{decoded.substring(0, separator), decoded.substring(separator + 1)};
        } catch (IllegalArgumentException e) {
            log.warn("TSP authentication: malformed Basic credentials.");
            return null;
        }
    }
}

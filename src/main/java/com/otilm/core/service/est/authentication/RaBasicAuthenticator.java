package com.otilm.core.service.est.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClientCredentials.BasicCredentials;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.SecretsUtil;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Authenticates a client by the HTTP Basic credentials it presents, checked against the Secrets that the EST Profile
 * references. The client is identified by the Secret it matched. A client certificate is not read, as a policy never
 * falls back to another one.
 * <p>
 * A Secret is eligible when it is a Basic authentication Secret, is enabled and is active, and the vault profile it is
 * sourced from is enabled, as reading the content of a Secret requires too. The credentials match it when the SHA-256
 * fingerprint of the user name and password equals the fingerprint that Core keeps for the latest version of the
 * Secret, so no vault is asked. Nothing is cached: disabling, deleting or changing a Secret, or disabling its vault
 * profile, applies to the next request.
 * <p>
 * The presented fingerprint is computed once, whether or not a Secret is referenced, and compared in constant time with
 * every eligible Secret, without stopping at a match. The comparison does not reveal which Secret matched, or how much
 * of a fingerprint was right.
 */
@Slf4j
@Component
public class RaBasicAuthenticator implements EstAuthenticator {

    private final SecretRepository secretRepository;

    public RaBasicAuthenticator(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    @Override
    public EstAuthenticationPolicy policy() {
        return EstAuthenticationPolicy.RA_BASIC;
    }

    /**
     * @return the client, identified as {@code secret:<uuid>} by the Secret that the credentials match; of two Secrets
     * with the same credentials, the one listed first on the EST Profile
     * @throws EstException {@link EstError#UNAUTHORIZED}, whose challenge names the realm of the route, when the client
     * presented no Basic credentials or ones that cannot be read, or when they match no eligible Secret
     */
    @Override
    public EstClient authenticate(EstRoute route, @Sensitive EstClientCredentials credentials, CertificateRequest csr) {
        BasicCredentials basic = credentials
                .basic()
                .orElseThrow(() -> refused(route,
                        credentials.basicMalformed()
                                ? "the Basic credentials are malformed"
                                : "no Basic credentials were presented"));
        byte[] presented = fingerprintOf(basic);
        Secret matched = null;
        for (Secret candidate : eligibleSecrets(route)) {
            boolean equal = MessageDigest.isEqual(presented, storedFingerprintOf(candidate));
            if (equal && matched == null) {
                matched = candidate;
            }
        }
        if (matched == null) {
            throw refused(route, "the credentials match no eligible Secret");
        }
        return new EstClient(EstAuthenticationPolicy.RA_BASIC, "secret:" + matched.getUuid(), null);
    }

    /**
     * The referenced Secrets that are eligible, in the order of the EST Profile. The read runs outside the caller's
     * transaction, so nothing may load lazily afterwards: one query reads the Secrets with their latest version and
     * source vault profile, and the type, state and flags are those of the Secrets and vault profiles now.
     */
    private List<Secret> eligibleSecrets(EstRoute route) {
        List<UUID> referenced = route.estProfile().getBasicCredentialSecretUuids();
        List<Secret> eligible = secretRepository
                .findWithLatestVersionAndSourceVaultProfileByUuidIn(referenced)
                .stream()
                .filter(RaBasicAuthenticator::isEligible)
                .sorted(Comparator.comparingInt(secret -> referenced.indexOf(secret.getUuid())))
                .toList();
        log
                .debug("{} of the {} Secrets referenced by realm {} are eligible as RA credentials", eligible.size(),
                        referenced.size(), route.realm());
        return eligible;
    }

    private static boolean isEligible(Secret secret) {
        return secret.getType() == SecretType.BASIC_AUTH && secret.isEnabled()
                && secret.getState() == SecretState.ACTIVE && secret.getSourceVaultProfile().isEnabled();
    }

    private static byte[] storedFingerprintOf(Secret secret) {
        return secret.getLatestVersion().getFingerprint().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] fingerprintOf(BasicCredentials basic) {
        try {
            String fingerprint = SecretsUtil
                    .calculateSecretContentFingerprint(new BasicAuthSecretContent(basic.username(), basic.password()));
            return fingerprint.getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("The fingerprint of Basic credentials cannot be computed.", e);
        }
    }

    private static EstException refused(EstRoute route, String reason) {
        log.debug("EST client refused under the raBasic policy for realm {}: {}", route.realm(), reason);
        return new EstException(EstError.UNAUTHORIZED, route.realm());
    }
}

package com.otilm.core.service.registration;

import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.util.SecretEncodingVersion;
import com.otilm.core.util.SecretsUtil;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Encrypts, verifies, and reveals the registration challenge of a {@link CertificateRegistrationAuthorization}.
 * It is the only collaborator that touches the plaintext challenge: the entity stores ciphertext, and the
 * plaintext is confined to this service so it cannot leak through entity accessors or {@code toString}.
 */
@Service
public class RegistrationChallengeStore {

    /**
     * Encrypts {@code plaintext} and writes the ciphertext onto {@code row}. Does not persist — the caller saves
     * the row within its own transaction.
     */
    public void store(CertificateRegistrationAuthorization row, String plaintext) {
        // Fail fast: a null/blank challenge would encode to null and only surface as an opaque NOT NULL
        // violation when the row is saved.
        if (plaintext == null || plaintext.isBlank()) {
            throw new IllegalArgumentException("A registration challenge is required");
        }
        row.setChallenge(SecretsUtil.encryptAndEncodeSecretString(plaintext, SecretEncodingVersion.V1));
    }

    /**
     * Returns whether {@code presented} matches the stored challenge, or false when either side is null.
     */
    public boolean verify(CertificateRegistrationAuthorization row, String presented) {
        if (presented == null || row.getChallenge() == null) {
            return false;
        }
        String stored = SecretsUtil.decodeAndDecryptSecretString(row.getChallenge(), SecretEncodingVersion.V1);
        // Constant-time comparison so a timing side channel cannot leak how much of the challenge matched.
        return MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8),
                stored.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypts and returns the plaintext challenge. Internal-only — for building the future registration event
     * payload (SCEP / CMP); never exposed by any API.
     */
    public String resolvePlaintext(CertificateRegistrationAuthorization row) {
        // Consistent with verify()'s guard: a clear domain error beats an NPE inside SecretsUtil if this is ever
        // called on an unpopulated row. The NOT NULL challenge column keeps it unreachable for a persisted row.
        if (row.getChallenge() == null) {
            throw new IllegalStateException("Registration authorization has no stored challenge to resolve");
        }
        return SecretsUtil.decodeAndDecryptSecretString(row.getChallenge(), SecretEncodingVersion.V1);
    }
}

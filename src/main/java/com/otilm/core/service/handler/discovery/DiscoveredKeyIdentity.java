package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.core.util.CertificateUtil;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

/**
 * What identifies a discovered key across everything that reports it.
 *
 * <p>
 * Computed from the material whenever there is material, with the call {@code CertificateHandler} makes for a
 * certificate's public key: the v2 contract asks a connector for an intrinsic fingerprint but does not say how to
 * compute one, so trusting the connector's string would file the same key twice — once as a key, once as the key of a
 * certificate carrying it. That convergence holds for SubjectPublicKeyInfo material, which is what a certificate
 * carries; a key reported in another encoding is identified by its own bytes. A connector's own value identifies only
 * the key types that have no public part, which no certificate can collide with.
 *
 * <p>
 * Staging and import both ask here. Asked different questions they would disagree: a key the inventory already holds
 * would be staged as newly discovered and then imported onto the record that was there all along.
 */
public final class DiscoveredKeyIdentity {

    private DiscoveredKeyIdentity() {
    }

    /**
     * @throws UnusableDiscoveredKeyException when the payload cannot identify a key at all
     */
    public static String of(DiscoveredKeyDto key) {
        String material = key.getPublicKey();
        if (material != null && !material.isBlank()) {
            return fromMaterial(material);
        }
        if (key.getFingerprint() == null || key.getFingerprint().isBlank()) {
            throw new UnusableDiscoveredKeyException(
                    "The key was reported without public key material and without a fingerprint, so it cannot be "
                            + "told apart from any other.");
        }
        return key.getFingerprint();
    }

    /**
     * The identity, or empty when the payload has none to give. For staging, which files what a connector sent either
     * way and leaves the refusal to the import that reads it.
     */
    public static Optional<String> ofQuietly(DiscoveredKeyDto key) {
        try {
            return Optional.of(of(key));
        } catch (UnusableDiscoveredKeyException e) {
            return Optional.empty();
        }
    }

    private static String fromMaterial(String base64Material) {
        try {
            // Whitespace is dropped rather than decoded leniently: wrapped lines are still Base64, anything else is
            // not.
            byte[] encoded = Base64.getDecoder().decode(base64Material.replaceAll("\\s", ""));
            return CertificateUtil
                    .getThumbprint(Base64.getEncoder().encodeToString(encoded).getBytes(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new UnusableDiscoveredKeyException("The reported public key was not valid Base64.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new UnusableDiscoveredKeyException("The key's fingerprint could not be computed.", e);
        }
    }
}

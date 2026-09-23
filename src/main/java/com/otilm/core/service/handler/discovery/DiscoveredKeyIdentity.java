package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.core.util.CertificateUtil;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * What a discovered key is, when Core can know it.
 *
 * <p>
 * Core onboards a discovered key by its public part, read from SubjectPublicKeyInfo material — the form a certificate
 * carries — and files it under the fingerprint {@code CertificateHandler} computes for a certificate's public key. A
 * key discovered on its own and the same key inside a certificate are then one record, whichever arrives first. A key
 * with no public part, or a public part in another encoding, has nothing Core can identify it by: the connector's own
 * fingerprint is a claim the contract does not define, so such a key is listed on the run and not onboarded.
 *
 * <p>
 * Staging and import both ask here. Asked different questions they would disagree: a key the inventory already holds
 * would be staged as newly discovered and then imported onto the record that was there all along.
 */
public final class DiscoveredKeyIdentity {

    private DiscoveredKeyIdentity() {
    }

    /**
     * The public key a discovered key is onboarded by.
     *
     * @throws DiscoveredKeyNotOnboardedException when the key has no public part Core can hold
     * @throws UnusableDiscoveredKeyException when the reported material is not a public key at all
     */
    public static PublicKey publicKeyOf(DiscoveredKeyDto key) {
        String material = key.getPublicKey();
        if (key.getType() != KeyType.PUBLIC_KEY || material == null || material.isBlank()) {
            throw new DiscoveredKeyNotOnboardedException(
                    "Listed, not added to the inventory: Core onboards a discovered key by its public part, and this "
                            + "key was reported without one.");
        }
        if (key.getPublicKeyFormat() != null && key.getPublicKeyFormat() != KeyFormat.SPKI) {
            throw new DiscoveredKeyNotOnboardedException(
                    "Listed, not added to the inventory: its public key was reported in a form other than "
                            + "SubjectPublicKeyInfo, which is the form Core onboards.");
        }
        byte[] encoded;
        try {
            // Whitespace is dropped rather than decoded leniently: wrapped lines are still Base64, anything else is
            // not.
            encoded = Base64.getDecoder().decode(material.replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            throw new UnusableDiscoveredKeyException("The reported public key was not valid Base64.", e);
        }
        try {
            return new JcaPEMKeyConverter().getPublicKey(SubjectPublicKeyInfo.getInstance(encoded));
        } catch (IllegalArgumentException | PEMException e) {
            throw new UnusableDiscoveredKeyException("The reported public key could not be read as a public key.", e);
        }
    }

    /** The fingerprint Core files a public key under — the same call it makes for a certificate's public key. */
    public static String fingerprintOf(PublicKey publicKey) {
        try {
            return CertificateUtil
                    .getThumbprint(Base64
                            .getEncoder()
                            .encodeToString(publicKey.getEncoded())
                            .getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new UnusableDiscoveredKeyException("The key's fingerprint could not be computed.", e);
        }
    }

    /**
     * @throws UnusableDiscoveredKeyException when the key is not one Core onboards
     */
    public static String of(DiscoveredKeyDto key) {
        return fingerprintOf(publicKeyOf(key));
    }

    /**
     * The identity, or empty when the key is not one Core onboards. For staging, which files what a connector sent
     * either way and leaves the reason to the import that reads it.
     */
    public static Optional<String> ofQuietly(DiscoveredKeyDto key) {
        try {
            return Optional.of(of(key));
        } catch (UnusableDiscoveredKeyException e) {
            return Optional.empty();
        }
    }
}

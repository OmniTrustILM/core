package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.core.util.CertificateUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * What a discovered key is, when Core can know it.
 *
 * <p>
 * A discovered key is onboarded by its SubjectPublicKeyInfo public part and filed under the fingerprint
 * {@code CertificateHandler} computes for a certificate's public key, so a key found on its own and the same key inside
 * a certificate are one record. The connector's own fingerprint is undefined by the contract and never used; a key
 * without such a public part is listed on the run and not onboarded.
 *
 * <p>
 * Staging and import both call here, so a key the inventory already holds is never staged as newly discovered.
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
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(encoded);
            // The call a certificate's public key goes through, so the key is named the same whichever arrives first:
            // JcaPEMKeyConverter names an EC key "ECDSA", which no algorithm mapping knows.
            PublicKey publicKey = BouncyCastleProvider.getPublicKey(spki);
            return publicKey != null ? publicKey : new JcaPEMKeyConverter().getPublicKey(spki);
        } catch (IllegalArgumentException | IOException e) {
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

package com.otilm.core.container;

import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.core.key.normalization.KeyDescription;
import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * A key the file holds, with the certificate that carries its public key when the file holds one.
 *
 * @param reference the lowercase hex SHA-256 of the key's DER {@code SubjectPublicKeyInfo}, or of the key as the file
 * holds it when there is no public key to take
 * @param alias the name the file gives the key, or {@code null}
 * @param keyFile the key as the file holds it, readable on its own by the normalizer (a DER structure, a PEM block, or
 * a JCEKS sealed key)
 * @param description what the normalizer found the key to be
 * @param leaf the certificate carrying the key's public key, or null
 * @param issuers the leaf's issuers found in the file, nearest first
 * @param secret whether the key is a secret key: as the normalizer describes it, or, for a key of an algorithm the
 * platform does not support, as the file stores it
 */
// S6218: nothing compares, hashes or prints an entry as a whole; the key it keeps is overwritten by Container.clear().
@SuppressWarnings("java:S6218")
public record KeyEntry(String reference, String alias, byte[] keyFile, KeyDescription description,
        X509CertificateHolder leaf, List<X509CertificateHolder> issuers, boolean secret) implements ContainerEntry {

    /**
     * A secret key, a key pair with the certificate that carries its public key, or a private key without one.
     *
     * @return the entry's kind
     */
    @Override
    public InspectedEntryKind kind() {
        if (secret) {
            return InspectedEntryKind.SECRET_KEY;
        }
        return leaf != null ? InspectedEntryKind.KEY_PAIR_WITH_CHAIN : InspectedEntryKind.PRIVATE_KEY;
    }
}

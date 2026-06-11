package com.otilm.core.model.signing.resolved;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.model.crypto.CryptographicKeyItemModel;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.signing.tsa.CertificateChain;

import java.util.List;

/**
 * Resolved scheme: managed signing using a pre-existing static certificate.
 *
 * @param certificate                Cached snapshot of the end-entity certificate used for signing.
 * @param keyItems                   Cached snapshots of the signing key's items (private/public).
 * @param chain                      Validated certificate chain (see {@link CertificateChain}), built once at resolution time.
 * @param signingOperationAttributes Attributes required for signing operations.
 */
public record ResolvedStaticKeyManagedSigning(
        SigningCertificate certificate,
        List<CryptographicKeyItemModel> keyItems,
        CertificateChain chain,
        List<RequestAttribute> signingOperationAttributes
) implements ResolvedManagedScheme {
}

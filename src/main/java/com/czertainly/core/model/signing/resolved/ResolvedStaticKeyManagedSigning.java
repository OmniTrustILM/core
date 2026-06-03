package com.czertainly.core.model.signing.resolved;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.core.dao.entity.Certificate;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Resolved scheme: managed signing using a pre-existing static certificate.
 *
 * <p>The certificate chain starts with the signing certificate (index 0) and is followed by any CA certificates up to the root.</p>
 *
 * @param certificate                Resolved end-entity certificate used for signing.
 * @param chain                      Full certificate chain.
 * @param signingOperationAttributes Attributes required for signing operations.
 */
public record ResolvedStaticKeyManagedSigning(
        Certificate certificate,
        List<X509Certificate> chain,
        List<RequestAttribute> signingOperationAttributes
) implements ResolvedManagedScheme {
}

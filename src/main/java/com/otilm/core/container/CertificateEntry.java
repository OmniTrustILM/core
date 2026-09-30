package com.otilm.core.container;

import com.otilm.api.model.client.inspection.InspectedEntryKind;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * A certificate the file holds that is in no key's chain.
 *
 * @param reference the lowercase hex SHA-256 of the certificate's DER
 * @param alias the name the file gives the certificate, or {@code null}
 * @param certificate the certificate
 */
public record CertificateEntry(String reference, String alias,
        X509CertificateHolder certificate) implements ContainerEntry {

    @Override
    public InspectedEntryKind kind() {
        return InspectedEntryKind.CERTIFICATE;
    }
}

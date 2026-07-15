package com.otilm.core.certificate.request;

import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateType;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Seeder for renew/re-key: extracts the identity (subject RDNs + SANs) of an existing certificate into typed {@link X509RequestContent}
 * so the successor request keeps the same identity by default.
 *
 * <p><b>Extensions are NOT seeded</b>: issued-certificate extensions are largely CA-populated (AKI, SKI, CRL DP, AIA, SCT)
 * and must not be echoed back as requested extensions. The {@code extensions} list is always empty.</p>
 */
@Slf4j
public final class RequestContentSeeder {

    private RequestContentSeeder() {
    }

    /**
     * Seeds subject RDNs and SANs from {@code certificate}. Unrepresentable SAN kinds (x400Address, ediPartyName) are logged and skipped.
     */
    public static X509RequestContent seedFromCertificate(X509Certificate certificate) throws CertificateEncodingException {
        Objects.requireNonNull(certificate, "certificate");
        JcaX509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
        X509RequestContent content = new X509RequestContent();
        content.setCertificateType(CertificateType.X509);
        content.setSubject(X509RequestContentParser.parseSubject(holder.getSubject()));
        content.setSubjectAltNames(seedSans(holder.getExtensions()));
        content.setExtensions(new ArrayList<>());
        return content;
    }

    private static List<GeneralNameEntry> seedSans(Extensions extensions) {
        if (extensions == null) {
            return new ArrayList<>();
        }
        GeneralNames generalNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        if (generalNames == null) {
            return new ArrayList<>();
        }
        List<String> unsupportedSans = new ArrayList<>();
        List<GeneralNameEntry> entries = X509RequestContentParser.toGeneralNameEntries(generalNames, unsupportedSans);
        for (String kind : unsupportedSans) {
            log.warn("SAN {} of the existing certificate cannot be represented in typed request content and is not seeded", kind);
        }
        return entries;
    }
}

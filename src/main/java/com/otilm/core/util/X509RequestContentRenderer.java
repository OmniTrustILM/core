package com.otilm.core.util;

import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.core.oid.OidHandler;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Pure-kernel renderer: maps {@link X509RequestContent} into BouncyCastle structures.
 * No Spring context required; all methods are static.
 */
public final class X509RequestContentRenderer {

    private static final Pattern OID_PATTERN = Pattern.compile("^[0-2](\\.(0|[1-9]\\d{0,38})){1,127}$");

    /**
     * RFC 5280 extensions that MUST stay critical regardless of criticalOverridable or registry defaults.
     * BasicConstraints (§4.2.1.9) and KeyUsage (§4.2.1.3).
     */
    static final Set<String> CRITICALITY_FORCED_OIDS = Set.of(
            Extension.basicConstraints.getId(),
            Extension.keyUsage.getId()
    );

    private X509RequestContentRenderer() {}

    /**
     * Builds a subject DN from the ordered {@link RdnEntry} list.
     * RDN types are resolved via the OID registry cache, then as dotted-decimal OIDs directly.
     */
    public static X500Name toX500Name(X509RequestContent x509) {
        Map<String, String> codeToOid = OidHandler.getCodeToOidMap();
        X500NameBuilder builder = new X500NameBuilder();
        List<RdnEntry> subject = x509.getSubject() == null ? List.of() : x509.getSubject();
        for (RdnEntry rdn : subject) {
            builder.addRDN(resolveOid(rdn.getType(), codeToOid), rdn.getValue());
        }
        return builder.build();
    }

    /**
     * Builds the SAN extension and any requested extensions into a BC {@link Extensions}.
     * RFC 5280 must-stay-critical OIDs are forced critical regardless of the supplied flag.
     * Returns null if no extensions are present in the request.
     */
    public static Extensions toExtensions(X509RequestContent x509) throws IOException {
        ExtensionsGenerator gen = new ExtensionsGenerator();

        List<GeneralNameEntry> sans = x509.getSubjectAltNames() == null ? List.of() : x509.getSubjectAltNames();
        if (!sans.isEmpty()) {
            GeneralName[] names = sans.stream()
                    .map(X509RequestContentRenderer::toGeneralName)
                    .toArray(GeneralName[]::new);
            gen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        }

        List<RequestedExtension> extensions = x509.getExtensions() == null ? List.of() : x509.getExtensions();
        for (RequestedExtension ext : extensions) {
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(ext.getOid());
            boolean critical = effectiveCritical(ext.getOid(), ext.getCritical());
            byte[] derValue = Base64.decode(ext.getValue());
            gen.addExtension(oid, critical, derValue);
        }

        if (gen.isEmpty()) return null;

        return gen.generate();
    }

    private static boolean effectiveCritical(String oid, boolean requestedCritical) {
        if (oid != null && CRITICALITY_FORCED_OIDS.contains(oid)) {
            return true;
        }
        return requestedCritical;
    }

    private static GeneralName toGeneralName(GeneralNameEntry e) {
        return new GeneralName(e.getType().getBcTag(), e.getValue());
    }

    private static ASN1ObjectIdentifier resolveOid(String type, Map<String, String> codeToOid) {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("RDN type is required");
        }
        if (OID_PATTERN.matcher(type).matches()) {
            return new ASN1ObjectIdentifier(type);
        }
        if (codeToOid != null && codeToOid.containsKey(type)) {
            return new ASN1ObjectIdentifier(codeToOid.get(type));
        }
        throw new IllegalArgumentException("Unknown RDN type/code: " + type);
    }
}

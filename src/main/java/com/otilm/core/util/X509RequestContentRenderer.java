package com.otilm.core.util;

import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.core.oid.OidHandler;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.OtherName;

import javax.security.auth.x500.X500Principal;
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
    public static X500Principal toX500Principal(X509RequestContent x509) throws IOException {
        Map<String, String> codeToOid = OidHandler.getCodeToOidMap();
        X500NameBuilder builder = new X500NameBuilder();
        List<RdnEntry> subject = x509.getSubject() == null ? List.of() : x509.getSubject();
        for (RdnEntry rdn : subject) {
            builder.addRDN(resolveOid(rdn.getType(), codeToOid), rdn.getValue());
        }
        return new X500Principal(builder.build().getEncoded());
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
        if (e.getType() == GeneralNameType.OTHER_NAME) {
            ASN1Encodable asn1Value = encodeOtherNameValue(e.getValue(), e.getValueEncoding());
            return new GeneralName(GeneralName.otherName,
                    new OtherName(new ASN1ObjectIdentifier(e.getOtherNameOid()), asn1Value));
        }
        return new GeneralName(e.getType().getBcTag(), e.getValue());
    }

    private static ASN1Encodable encodeOtherNameValue(String value, ExtensionValueEncoding encoding) {
        if (encoding == null) {
            return new DERUTF8String(value);
        }
        return switch (encoding) {
            case IA5_STRING -> new DERIA5String(value);
            case OCTET_STRING -> new DEROctetString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            // DER: caller supplies a base64-encoded DER blob
            case DER -> org.bouncycastle.util.encoders.Base64.decode(value).length > 0
                    ? new org.bouncycastle.asn1.DEROctetString(org.bouncycastle.util.encoders.Base64.decode(value))
                    : new DERUTF8String(value);
            default -> new DERUTF8String(value);
        };
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

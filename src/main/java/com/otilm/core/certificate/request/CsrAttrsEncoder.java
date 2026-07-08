package com.otilm.core.certificate.request;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.core.oid.OidHandler;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Projects a resolved request-attribute set into a DER-encoded EST CsrAttrs (RFC 7030 §4.5):
 * <pre>
 *   CsrAttrs  ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
 *   AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }
 * </pre>
 * RDN-mapped attributes become bare attribute-type OIDs; SAN/EXTENSION-mapped attributes are grouped
 * into a single PKCS#9 extensionRequest attribute, following the RFC 7030 §4.5.2 example. This advertisement is advisory.
 */
public final class CsrAttrsEncoder {

    private CsrAttrsEncoder() {
    }

    /**
     * Projects the resolved request-attribute {@code definitions} into a DER-encoded EST CsrAttrs body.
     *
     * @param definitions the resolved request-attribute set; RDN-mapped fields become bare attribute-type
     *                    OIDs and SAN/EXTENSION-mapped fields are grouped into one extensionRequest attribute
     * @param codeToOid   maps a well-known RDN code (e.g. {@code CN}) to its dotted OID; may be {@code null}
     *                    when every RDN is already a dotted OID
     * @return the DER encoding of the CsrAttrs {@code SEQUENCE}
     * @throws IOException if DER encoding fails
     * @throws IllegalArgumentException if an RDN code is blank or cannot be resolved to an OID
     */
    public static byte[] encode(List<? extends BaseAttribute> definitions, Map<String, String> codeToOid) throws IOException {
        List<MappedField> fields = x509Fields(definitions);
        Map<String, String> caseInsensitiveCodeToOid = caseInsensitive(codeToOid);

        Set<ASN1ObjectIdentifier> rdnOids = fields.stream()
                .filter(RdnMappedField.class::isInstance)
                .map(RdnMappedField.class::cast)
                .map(rdn -> resolveOid(rdn.getRdn(), caseInsensitiveCodeToOid))
                .collect(Collectors.toCollection(LinkedHashSet::new));

        Set<ASN1ObjectIdentifier> extensionOids = fields.stream()
                .filter(ExtensionMappedField.class::isInstance)
                .map(ExtensionMappedField.class::cast)
                .filter(ext -> ext.getExtensionOid() != null && OidHandler.isOid(ext.getExtensionOid()))
                .map(ext -> new ASN1ObjectIdentifier(ext.getExtensionOid()))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        // SAN is a specific extension (id-ce-subjectAltName); append it after any explicit extensions.
        if (fields.stream().anyMatch(SanMappedField.class::isInstance)) {
            extensionOids.add(Extension.subjectAlternativeName);
        }

        ASN1EncodableVector csrAttrs = new ASN1EncodableVector();
        rdnOids.forEach(csrAttrs::add);
        if (!extensionOids.isEmpty()) {
            csrAttrs.add(extensionRequestAttribute(extensionOids));
        }
        return new DERSequence(csrAttrs).getEncoded("DER");
    }

    /** Flattens the definitions to the ordered stream of fields mapped onto an X.509 certificate. */
    private static List<MappedField> x509Fields(List<? extends BaseAttribute> definitions) {
        return definitions.stream()
                .map(CsrAttrsEncoder::mappingOf)
                .filter(mapping -> mapping != null && mapping.getObjectType() == ObjectType.X509_CERTIFICATE)
                .flatMap(mapping -> mapping.getFields().stream())
                .toList();
    }

    /**
     * Builds the PKCS#9 extensionRequest Attribute (1.2.840.113549.1.9.14). Following the RFC 7030 §4.5.2
     * example, its {@code values} SET lists the requested extension OIDs directly (advisory; no values).
     */
    private static Attribute extensionRequestAttribute(Set<ASN1ObjectIdentifier> extensionOids) {
        ASN1EncodableVector values = new ASN1EncodableVector();
        extensionOids.forEach(values::add);
        return new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(values));
    }

    /**
     * Wraps {@code codeToOid} in a case-insensitive view so RDN-code resolution matches {@link CertificateRequestContentValidator}.
     */
    private static Map<String, String> caseInsensitive(Map<String, String> codeToOid) {
        if (codeToOid == null) {
            return null;
        }
        Map<String, String> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        ci.putAll(codeToOid);
        return ci;
    }

    static FieldMapping mappingOf(BaseAttribute def) {
        if (def instanceof DataAttributeV3 v3 && v3.getFieldMapping() != null && v3.getFieldMapping().getFields() != null) {
            return v3.getFieldMapping();
        }
        return null;
    }

    static ASN1ObjectIdentifier resolveOid(String code, Map<String, String> codeToOid) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("RDN code/OID is required for csrattrs projection");
        }
        if (OidHandler.isOid(code)) {
            return new ASN1ObjectIdentifier(code);
        }
        if (codeToOid != null && codeToOid.containsKey(code)) {
            return new ASN1ObjectIdentifier(codeToOid.get(code));
        }
        throw new IllegalArgumentException("Unknown RDN code/OID for csrattrs projection: " + code);
    }
}

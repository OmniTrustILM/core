package com.otilm.core.certificate.request;

import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.util.PlatformX500NameStyle;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.OtherName;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Parses a {@link CertificateRequest} (PKCS#10 or CRMF) into typed {@link X509RequestContent}, decoding directly
 * from BouncyCastle ASN.1 so RFC 4514 special characters survive verbatim. SAN kinds {@link GeneralNameType}
 * cannot model are reported in {@link ParsedRequestContent#unsupportedSans()}.
 */
@Slf4j
public final class X509RequestContentParser {

    private X509RequestContentParser() {
    }

    public static ParsedRequestContent parse(CertificateRequest request) {
        X509RequestContent x509 = new X509RequestContent();
        x509.setCertificateType(CertificateType.X509);
        x509.setSubject(parseSubject(request));
        List<String> unsupportedSans = new ArrayList<>();
        x509.setSubjectAltNames(parseSans(request, unsupportedSans));
        x509.setExtensions(parseExtensions(request));
        return new ParsedRequestContent(x509, unsupportedSans);
    }

    /**
     * Parses an RFC 4514 subject DN string into ordered {@link RdnEntry} entries, using the same BouncyCastle
     * decoding as {@link #parse(CertificateRequest)}. Blank input yields an empty list.
     *
     * @throws IllegalArgumentException when the DN string is not parseable
     */
    public static List<RdnEntry> parseSubjectDn(String subjectDn) {
        if (subjectDn == null || subjectDn.isBlank()) {
            return new ArrayList<>();
        }
        return parseSubject(new X500Name(PlatformX500NameStyle.DEFAULT, subjectDn));
    }

    private static List<RdnEntry> parseSubject(CertificateRequest request) {
        X500Name subject = request.getSubject();
        if (subject == null) {
            return new ArrayList<>();
        }
        return parseSubject(subject);
    }

    static List<RdnEntry> parseSubject(X500Name subject) {
        List<RdnEntry> result = new ArrayList<>();
        for (RDN rdn : subject.getRDNs()) {
            for (AttributeTypeAndValue atv : rdn.getTypesAndValues()) {
                RdnEntry entry = toRdnEntry(atv);
                if (entry != null) {
                    result.add(entry);
                }
            }
        }
        return result;
    }

    /** Decodes a single RDN component, or null when its value is blank (no identity to validate). */
    private static RdnEntry toRdnEntry(AttributeTypeAndValue atv) {
        String value = asn1ValueToString(atv.getValue());
        if (value.isBlank()) {
            return null;
        }
        RdnEntry entry = new RdnEntry();
        entry.setType(rdnTypeCode(atv.getType()));
        entry.setValue(value);
        return entry;
    }

    /**
     * Resolves an RDN type OID to the platform's short code (OID registry, then BC symbols, then the dotted OID)
     * so validator matching and violation messages share one vocabulary.
     */
    private static String rdnTypeCode(ASN1ObjectIdentifier oid) {
        Map<String, OidRecord> rdnCache = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        OidRecord oidRecord = rdnCache == null ? null : rdnCache.get(oid.getId());
        if (oidRecord != null && oidRecord.code() != null) {
            return oidRecord.code();
        }
        String displayName = BCStyle.INSTANCE.oidToDisplayName(oid);
        return displayName != null ? displayName : oid.getId();
    }

    private static String asn1ValueToString(ASN1Encodable value) {
        return value instanceof ASN1String str ? str.getString() : value.toString();
    }

    private static List<GeneralNameEntry> parseSans(CertificateRequest request, List<String> unsupportedSans) {
        Extensions extensions = extractExtensions(request);
        if (extensions == null) {
            return new ArrayList<>();
        }
        GeneralNames generalNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        if (generalNames == null) {
            return new ArrayList<>();
        }
        List<GeneralNameEntry> entries = toGeneralNameEntries(generalNames, unsupportedSans);
        for (String kind : unsupportedSans) {
            log.warn("SAN {} in CSR has no typed representation; counted for whitelist enforcement", kind);
        }
        return entries;
    }

    /**
     * Decodes each name into a typed entry, collecting the kinds it cannot represent into {@code unsupportedSans}.
     */
    static List<GeneralNameEntry> toGeneralNameEntries(GeneralNames generalNames, List<String> unsupportedSans) {
        List<GeneralNameEntry> result = new ArrayList<>();
        for (GeneralName name : generalNames.getNames()) {
            String kind = sanKindName(name.getTagNo());
            try {
                GeneralNameEntry entry = toGeneralNameEntry(name);
                if (entry != null) {
                    result.add(entry);
                } else {
                    unsupportedSans.add(kind);
                }
            } catch (RuntimeException | IOException ex) {
                unsupportedSans.add(kind);
                log.debug("Failed to decode SAN {}; skipped from typed content", kind, ex);
            }
        }
        return result;
    }

    /** Decodes one SAN into a typed entry, or null for kinds {@link GeneralNameType} cannot model. */
    private static GeneralNameEntry toGeneralNameEntry(GeneralName name) throws IOException {
        return switch (name.getTagNo()) {
            case GeneralName.otherName -> toOtherNameEntry(name);
            case GeneralName.rfc822Name -> entry(GeneralNameType.EMAIL, ia5(name));
            case GeneralName.dNSName -> entry(GeneralNameType.DNS, ia5(name));
            case GeneralName.directoryName -> entry(GeneralNameType.DIRECTORY_NAME,
                    X500Name.getInstance(name.getName()).toString());
            case GeneralName.uniformResourceIdentifier -> entry(GeneralNameType.URI, ia5(name));
            case GeneralName.iPAddress -> entry(GeneralNameType.IP,
                    decodeIpAddress(ASN1OctetString.getInstance(name.getName()).getOctets()));
            case GeneralName.registeredID -> entry(GeneralNameType.REGISTERED_ID,
                    ASN1ObjectIdentifier.getInstance(name.getName()).getId());
            default -> null; // x400Address, ediPartyName — no GeneralNameType counterpart
        };
    }

    private static GeneralNameEntry entry(GeneralNameType type, String value) {
        GeneralNameEntry entry = new GeneralNameEntry();
        entry.setType(type);
        entry.setValue(value);
        return entry;
    }

    private static String ia5(GeneralName name) {
        return ASN1IA5String.getInstance(name.getName()).getString();
    }

    /**
     * Recovers an {@code otherName} SAN with its type-id OID so the validator can match on the (type, OID) pair.
     * String values keep their scalar form ({@link ExtensionValueEncoding#UTF8_STRING}); others are Base64(DER).
     */
    private static GeneralNameEntry toOtherNameEntry(GeneralName name) throws IOException {
        OtherName otherName = OtherName.getInstance(name.getName());
        GeneralNameEntry entry = new GeneralNameEntry();
        entry.setType(GeneralNameType.OTHER_NAME);
        entry.setOtherNameOid(otherName.getTypeID().getId());
        ASN1Encodable value = otherName.getValue();
        if (value instanceof ASN1String str) {
            entry.setValue(str.getString());
            entry.setValueEncoding(ExtensionValueEncoding.UTF8_STRING);
        } else {
            entry.setValue(Base64.getEncoder().encodeToString(value.toASN1Primitive().getEncoded()));
            entry.setValueEncoding(ExtensionValueEncoding.DER);
        }
        return entry;
    }

    private static String decodeIpAddress(byte[] octets) {
        try {
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("iPAddress SAN is not a 4- or 16-octet address", e);
        }
    }

    private static String sanKindName(int tagNo) {
        return switch (tagNo) {
            case GeneralName.otherName -> "otherName";
            case GeneralName.rfc822Name -> "rfc822Name";
            case GeneralName.dNSName -> "dNSName";
            case GeneralName.x400Address -> "x400Address";
            case GeneralName.directoryName -> "directoryName";
            case GeneralName.ediPartyName -> "ediPartyName";
            case GeneralName.uniformResourceIdentifier -> "uniformResourceIdentifier";
            case GeneralName.iPAddress -> "iPAddress";
            case GeneralName.registeredID -> "registeredID";
            default -> "tag " + tagNo;
        };
    }

    private static List<RequestedExtension> parseExtensions(CertificateRequest request) {
        Extensions extensions = extractExtensions(request);
        List<RequestedExtension> result = new ArrayList<>();
        if (extensions == null) {
            return result;
        }
        for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
            RequestedExtension re = toRequestedExtension(oid, extensions);
            if (re != null) {
                result.add(re);
            }
        }
        return result;
    }

    /** Encodes one requested extension, skipping the SAN OID (kept in subjectAltNames) and empty values. */
    private static RequestedExtension toRequestedExtension(ASN1ObjectIdentifier oid, Extensions extensions) {
        if (Extension.subjectAlternativeName.equals(oid)) {
            return null;
        }
        Extension ext = extensions.getExtension(oid);
        String value = Base64.getEncoder().encodeToString(ext.getExtnValue().getOctets());
        if (value.isBlank()) {
            log.warn("Skipping extension {} in CSR: empty extension value", oid.getId());
            return null;
        }
        RequestedExtension re = new RequestedExtension();
        re.setOid(oid.getId());
        re.setCritical(ext.isCritical());
        re.setEncoding(ExtensionValueEncoding.DER);
        re.setValue(value);
        return re;
    }

    private static Extensions extractExtensions(CertificateRequest request) {
        if (request instanceof Pkcs10CertificateRequest p10) {
            for (Attribute attribute : p10.getJcaObject().getAttributes()) {
                if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    return Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
                }
            }
            return null;
        }
        if (request instanceof CrmfCertificateRequest crmf) {
            return crmf.getCertTemplateExtensions();
        }
        return null;
    }
}

package com.otilm.core.certificate.request;

import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.CrmfCertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.PlatformX500NameStyle;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Parses a supplied {@link CertificateRequest} (PKCS#10 or CRMF) into the typed {@link X509RequestContent}.
 */
@Slf4j
public final class X509RequestContentParser {

    private X509RequestContentParser() {
    }

    public static X509RequestContent parse(CertificateRequest request) {
        X509RequestContent x509 = new X509RequestContent();
        x509.setSubject(parseSubject(request));
        x509.setSubjectAltNames(parseSans(request));
        x509.setExtensions(parseExtensions(request));
        return x509;
    }

    private static List<RdnEntry> parseSubject(CertificateRequest request) {
        List<RdnEntry> result = new ArrayList<>();
        X500Name subject = request.getSubject();
        if (subject == null) {
            return result;
        }
        String dn = PlatformX500NameStyle.DEFAULT.toString(subject);
        for (String rdn : splitOnUnescaped(dn, ',')) {
            int eq = indexOfUnescaped(rdn, '=');
            if (eq <= 0) {
                continue;
            }
            String value = unescape(rdn.substring(eq + 1));
            if (value.isBlank()) {
                continue; // an empty RDN carries no identity to validate
            }
            RdnEntry entry = new RdnEntry();
            entry.setType(rdn.substring(0, eq).trim());
            entry.setValue(value);
            result.add(entry);
        }
        // Reverse because PlatformX500NameStyle.DEFAULT reverses RDN order for display
        Collections.reverse(result);
        return result;
    }

    private static List<GeneralNameEntry> parseSans(CertificateRequest request) {
        List<GeneralNameEntry> result = new ArrayList<>();
        if (request instanceof CrmfCertificateRequest && extractExtensions(request) == null) {
            return result; // CMRF request with no extensions -> no SANs
        }
        Map<String, List<String>> sans = CertificateUtil.getSAN(request);
        for (Map.Entry<String, List<String>> e : sans.entrySet()) {
            if (e.getValue() == null || e.getValue().isEmpty()) {
                continue;
            }
            if ("otherName".equals(e.getKey())) {
                log.warn("Skipping otherName SAN in CSR: ASN.1 encoding cannot be recovered from the flattened representation");
                continue;
            }
            GeneralNameType type;
            try {
                String code = mapSanKeyToGeneralNameTypeCode(e.getKey());
                type = GeneralNameType.fromCode(code);
            } catch (IllegalArgumentException ex) {
                log.warn("Skipping unknown SAN type code in CSR: {}", e.getKey());
                continue;
            }
            for (String value : e.getValue()) {
                GeneralNameEntry entry = new GeneralNameEntry();
                entry.setType(type);
                entry.setValue(value);
                result.add(entry);
            }
        }
        return result;
    }

    private static String mapSanKeyToGeneralNameTypeCode(String sanTypeKey) {
        return switch (sanTypeKey) {
            case "rfc822Name" -> GeneralNameType.EMAIL.getCode();
            case "dNSName" -> GeneralNameType.DNS.getCode();
            case "directoryName" -> GeneralNameType.DIRECTORY_NAME.getCode();
            case "uniformResourceIdentifier" -> GeneralNameType.URI.getCode();
            case "iPAddress" -> GeneralNameType.IP.getCode();
            case "registeredID" -> GeneralNameType.REGISTERED_ID.getCode();
            default -> sanTypeKey; // x400Address, ediPartyName, etc. — no GeneralNameType counterpart
        };
    }

    private static List<RequestedExtension> parseExtensions(CertificateRequest request) {
        Extensions extensions = extractExtensions(request);
        List<RequestedExtension> result = new ArrayList<>();
        if (extensions == null) {
            return result;
        }
        for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
            if (Extension.subjectAlternativeName.equals(oid)) {
                continue; // SAN lives in subjectAltNames only
            }
            Extension ext = extensions.getExtension(oid);
            String value = Base64.getEncoder().encodeToString(ext.getExtnValue().getOctets());
            if (value.isBlank()) {
                log.warn("Skipping extension {} in CSR: empty extension value", oid.getId());
                continue;
            }
            RequestedExtension re = new RequestedExtension();
            re.setOid(oid.getId());
            re.setCritical(ext.isCritical());
            re.setEncoding(ExtensionValueEncoding.DER);
            re.setValue(value);
            result.add(re);
        }
        return result;
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

    private static List<String> splitOnUnescaped(String value, char separator) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (escaped) {
                current.append(c);
                escaped = false;
            } else if (c == '\\') {
                current.append(c);
                escaped = true;
            } else if (c == separator) {
                parts.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            parts.add(current.toString());
        }
        return parts;
    }

    private static int indexOfUnescaped(String s, char target) {
        boolean escaped = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == target) {
                return i;
            }
        }
        return -1;
    }

    private static String unescape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        boolean escaped = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escaped) {
                sb.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}

package com.otilm.core.service.acme.identifier;

import com.otilm.api.model.core.acme.AcmeIdentifierType;
import com.otilm.api.model.core.acme.Identifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * What a CSR offers to stand for, read out of it once and held in the forms an ordered identifier is compared against.
 *
 * <p>
 * Each type is kept as the thing it is rather than as text. An address subjectAltName is an OCTET STRING, and rendering
 * one the way a name is rendered yields the hex of its DER encoding, which no ordered value can ever equal; keeping the
 * octets is what lets an address be compared as an address.
 */
public final class AcmeCsrIdentifiers {

    private static final Logger logger = LoggerFactory.getLogger(AcmeCsrIdentifiers.class);

    private final List<String> dnsNames;
    private final List<byte[]> addresses;

    private AcmeCsrIdentifiers(List<String> dnsNames, List<byte[]> addresses) {
        this.dnsNames = dnsNames;
        this.addresses = addresses;
    }

    public static AcmeCsrIdentifiers of(JcaPKCS10CertificationRequest csr) {
        List<String> dnsNames = new ArrayList<>();
        List<byte[]> addresses = new ArrayList<>();
        commonNameOf(csr).ifPresent(dnsNames::add);
        for (Attribute attribute : csr.getAttributes()) {
            for (GeneralName name : subjectAlternativeNames(attribute)) {
                if (name.getTagNo() == GeneralName.dNSName) {
                    dnsNames.add(IETFUtils.valueToString(name.getName()));
                } else if (name.getTagNo() == GeneralName.iPAddress) {
                    addresses.add(ASN1OctetString.getInstance(name.getName()).getOctets());
                }
            }
        }
        return new AcmeCsrIdentifiers(dnsNames, addresses);
    }

    /** The subjectAltName entries an attribute carries, and none for an attribute that is about something else. */
    private static GeneralName[] subjectAlternativeNames(Attribute attribute) {
        if (!attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
            return new GeneralName[0];
        }
        Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
        GeneralNames names = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        return names == null ? new GeneralName[0] : names.getNames();
    }

    /**
     * Whether the CSR carries this identifier, compared the way its own type is compared. A DNS name goes by text,
     * ignoring case and a trailing root dot, which is how the order accepted it in the first place. An address goes by
     * its octets, and must be a subjectAltName: RFC 8738 section 3 puts the address there, and a subject common name is
     * text that was never one.
     *
     * <p>
     * Any other type is refused. Nothing can prove control of one, so no CSR satisfies an order naming one.
     */
    public boolean carries(Identifier identifier) {
        if (identifier == null || identifier.getValue() == null || identifier.getType() == null) {
            return false;
        }
        if (AcmeIdentifierType.DNS.getCode().equalsIgnoreCase(identifier.getType())) {
            return dnsNames.stream().anyMatch(offered -> sameName(offered, identifier.getValue()));
        }
        if (AcmeIdentifierType.IP.getCode().equalsIgnoreCase(identifier.getType())) {
            return AcmeIdentifierPolicy
                    .addressBytes(identifier.getValue())
                    .filter(ordered -> addresses.stream().anyMatch(offered -> Arrays.equals(ordered, offered)))
                    .isPresent();
        }
        return false;
    }

    private static Optional<String> commonNameOf(JcaPKCS10CertificationRequest csr) {
        try {
            String commonName = IETFUtils.valueToString(csr.getSubject().getRDNs(BCStyle.CN)[0].getFirst().getValue());
            return commonName.isEmpty() ? Optional.empty() : Optional.of(commonName);
        } catch (Exception e) {
            logger.warn("Unable to find common name: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private static boolean sameName(String left, String right) {
        return withoutRootDot(left).equalsIgnoreCase(withoutRootDot(right));
    }

    private static String withoutRootDot(String name) {
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }
}

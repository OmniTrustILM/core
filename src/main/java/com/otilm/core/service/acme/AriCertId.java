package com.otilm.core.service.acme;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;

/**
 * The certificate identifier of RFC 9773: the base64url authority key identifier and the base64url DER serial number of
 * a certificate, joined by a dot and without padding.
 */
public final class AriCertId {

    private static final Pattern BASE64_URL_PART = Pattern.compile("[A-Za-z0-9_-]+");

    private final byte[] keyIdentifier;
    private final String serialHex;

    private AriCertId(byte[] keyIdentifier, String serialHex) {
        this.keyIdentifier = keyIdentifier;
        this.serialHex = serialHex;
    }

    /**
     * Parses a certificate identifier.
     *
     * @throws IllegalArgumentException when the identifier is not two non-empty, unpadded base64url parts
     */
    public static AriCertId parse(String certId) {
        if (certId == null) {
            throw new IllegalArgumentException("Certificate identifier is missing");
        }
        String[] parts = certId.split("\\.", -1);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Certificate identifier must have two parts separated by a dot");
        }
        byte[] aki = decode(parts[0]);
        byte[] serial = decode(parts[1]);
        return new AriCertId(aki, new BigInteger(1, serial).toString(16));
    }

    /** The identifier of the certificate, which must carry an authority key identifier. */
    public static String of(X509Certificate certificate) {
        byte[] keyIdentifier = authorityKeyIdentifier(certificate);
        if (keyIdentifier == null) {
            throw new IllegalArgumentException("Certificate has no authority key identifier");
        }
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(keyIdentifier) + "."
                + encoder.encodeToString(certificate.getSerialNumber().toByteArray());
    }

    /** Whether the certificate carries the authority key identifier of this identifier. */
    public boolean matchesIssuerOf(X509Certificate certificate) {
        return Arrays.equals(keyIdentifier, authorityKeyIdentifier(certificate));
    }

    /** The authority key identifier octets. */
    public byte[] keyIdentifier() {
        return keyIdentifier.clone();
    }

    /** The serial number as lower-case hexadecimal without leading zeros, as the certificate table stores it. */
    public String serialHex() {
        return serialHex;
    }

    private static byte[] authorityKeyIdentifier(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        return extension == null
                ? null
                : AuthorityKeyIdentifier
                        .getInstance(ASN1OctetString.getInstance(extension).getOctets())
                        .getKeyIdentifier();
    }

    private static byte[] decode(String part) {
        if (!BASE64_URL_PART.matcher(part).matches()) {
            throw new IllegalArgumentException("Certificate identifier part is not unpadded base64url");
        }
        try {
            return Base64.getUrlDecoder().decode(part);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Certificate identifier part is not valid base64url", e);
        }
    }
}

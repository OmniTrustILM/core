package com.otilm.core.security.authn;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;

final class CertificateHeaderValueDecoder {
    private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_END = "-----END CERTIFICATE-----";

    private CertificateHeaderValueDecoder() {
    }

    static List<byte[]> decode(String value) {
        String decoded = transport(value, false);
        if (formPem(decoded)) {
            decoded = transport(value, true);
        }
        return decodeSequence(decoded, false);
    }

    private static boolean formPem(String decoded) {
        int position = 0;
        while (position < decoded.length() && " \t\r\n+".indexOf(decoded.charAt(position)) >= 0) {
            position++;
        }
        return decoded.startsWith("-----BEGIN+CERTIFICATE-----", position);
    }

    static List<byte[]> decodePemTransport(String value) {
        return decodeSequence(transport(value, false), true);
    }

    private static String transport(String value, boolean formPem) {
        ForwardedCertificateLimits.headerBytes(value, 0);
        try {
            return URLDecoder.decode(formPem ? value : value.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid certificate transport encoding");
        }
    }

    private static List<byte[]> decodeSequence(String value, boolean pemOnly) {
        return decodeSequence(value, pemOnly, 0);
    }

    private static List<byte[]> decodeSequence(String value, boolean pemOnly, int precedingCertificates) {
        List<byte[]> certificates = new ArrayList<>();
        int position = skipWhitespace(value, 0);
        while (position < value.length()) {
            ForwardedCertificateLimits.certificateCount(precedingCertificates + certificates.size() + 1);
            EncodedCertificate member = encodedCertificate(value, position, pemOnly);
            byte[] decoded = decodeBase64(member.body().replace("\r", "").replace("\n", ""), member.pem());
            if (!member.pem() && wrappedPem(decoded)) {
                String wrapped = new String(decoded, StandardCharsets.US_ASCII);
                certificates.addAll(decodeSequence(wrapped, true, precedingCertificates + certificates.size()));
            } else {
                certificates.add(canonicalDer(decoded));
            }
            position = nextCertificate(value, member, pemOnly);
        }
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("Empty certificate header");
        }
        return certificates;
    }

    private static EncodedCertificate encodedCertificate(String value, int position, boolean pemOnly) {
        if (value.startsWith(PEM_BEGIN, position)) {
            int bodyStart = position + PEM_BEGIN.length();
            int bodyEnd = value.indexOf(PEM_END, bodyStart);
            if (bodyEnd < 0) {
                throw new IllegalArgumentException("Invalid certificate PEM armor");
            }
            String body = value.substring(bodyStart, bodyEnd).replace(" ", "").replace("\t", "");
            return new EncodedCertificate(body, bodyEnd + PEM_END.length(), true);
        }
        if (pemOnly) {
            throw new IllegalArgumentException("Expected certificate PEM armor");
        }
        int end = value.indexOf(',', position);
        if (end < 0) {
            end = value.length();
        }
        return new EncodedCertificate(value.substring(position, end).trim(), end, false);
    }

    private static int nextCertificate(String value, EncodedCertificate member, boolean pemOnly) {
        int position = skipWhitespace(value, member.end());
        if (position == value.length()) {
            return position;
        }
        if (value.charAt(position) == ',') {
            if (pemOnly) {
                throw new IllegalArgumentException("Invalid certificate PEM sequence");
            }
            position = skipWhitespace(value, position + 1);
            if (position == value.length()) {
                throw new IllegalArgumentException("Empty certificate sequence member");
            }
        } else if (!member.pem() || !value.startsWith(PEM_BEGIN, position)) {
            throw new IllegalArgumentException("Invalid certificate sequence");
        }
        return position;
    }

    private record EncodedCertificate(String body, int end, boolean pem) {
    }

    private static int skipWhitespace(String value, int position) {
        while (position < value.length() && " \t\r\n".indexOf(value.charAt(position)) >= 0) {
            position++;
        }
        return position;
    }

    private static byte[] decodeBase64(String content, boolean derOnly) {
        if (derOnly && content.length() > ((ForwardedCertificateLimits.DER_BYTES + 2) / 3) * 4) {
            throw new IllegalArgumentException("Certificate DER size limit exceeded");
        }
        byte[] der;
        try {
            der = Base64.getDecoder().decode(content);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid certificate Base64 encoding");
        }
        return der;
    }

    private static boolean wrappedPem(byte[] decoded) {
        int position = 0;
        while (position < decoded.length && " \t\r\n".indexOf(decoded[position]) >= 0) {
            position++;
        }
        if (decoded.length - position < PEM_BEGIN.length()) {
            return false;
        }
        for (int i = 0; i < PEM_BEGIN.length(); i++) {
            if (decoded[position + i] != PEM_BEGIN.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    static byte[] canonicalDer(byte[] der) {
        ForwardedCertificateLimits.derSize(der.length);
        try {
            ByteArrayInputStream input = new ByteArrayInputStream(der);
            byte[] encoded = new CertificateFactory().engineGenerateCertificate(input).getEncoded();
            if (input.available() != 0 || !Arrays.equals(der, encoded)) {
                throw new IllegalArgumentException("Invalid certificate DER encoding");
            }
            return encoded;
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Invalid X.509 certificate");
        }
    }
}

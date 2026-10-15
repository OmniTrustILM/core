package com.otilm.core.security.authn;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.greenbytes.http.sfv.ByteSequenceItem;
import org.greenbytes.http.sfv.Item;
import org.greenbytes.http.sfv.ParseException;
import org.greenbytes.http.sfv.SfList;

final class Rfc9440CertificateDecoder {
    private Rfc9440CertificateDecoder() {
    }

    static List<byte[]> decode(String leafValue, List<String> companionValues) {
        preflight(leafValue, companionValues);
        try {
            byte[] leaf = certificate(Item.parse(leafValue));
            List<byte[]> certificates = new ArrayList<>();
            certificates.add(leaf);
            if (!companionValues.isEmpty()) {
                var members = SfList.parse(companionValues).get();
                ForwardedCertificateLimits.certificateCount(members.size() + 1);
                for (var member : members) {
                    byte[] candidate = certificate(member);
                    if (Arrays.equals(leaf, candidate)) {
                        throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                                "RFC certificate chain contains the leaf");
                    }
                    certificates.add(candidate);
                }
            }
            return certificates;
        } catch (ParseException e) {
            throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                    "Invalid RFC certificate field syntax");
        }
    }

    private static byte[] certificate(Object member) {
        if (!(member instanceof ByteSequenceItem item)) {
            throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                    "Expected RFC certificate byte item");
        }
        ByteBuffer buffer = item.byteBufferValue();
        ForwardedCertificateLimits.derSize(buffer.remaining());
        byte[] der = new byte[buffer.remaining()];
        buffer.get(der);
        return CertificateHeaderValueDecoder.canonicalDer(der);
    }

    private static void preflight(String leafValue, List<String> values) {
        int bytes = ForwardedCertificateLimits.headerBytes(leafValue, 0);
        if (values.size() > ForwardedCertificateLimits.COMPANION_LINES) {
            throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                    "RFC companion occurrence limit exceeded");
        }
        FieldStructure structure = new FieldStructure();
        structure.count(leafValue, false);
        int lines = 0;
        for (String value : values) {
            bytes = ForwardedCertificateLimits.headerBytes(value, bytes + (lines++ == 0 ? 0 : 1));
            structure.count(value, true);
        }
    }

    /**
     * The Structured Fields parser sizes the buffer of every token, string and byte sequence it reads to the whole
     * field, so its work grows with the field length times the number of values. Members and parameter occurrences are
     * counted before parsing to bound that number; an inner list never holds a certificate, so it is refused unread.
     */
    private static final class FieldStructure {
        private int members;
        private int parameters;

        private void count(String value, boolean companion) {
            if (companion && !value.isBlank()) {
                ForwardedCertificateLimits.certificateCount(++members + 1);
            }
            boolean quoted = false;
            boolean escaped = false;
            for (int i = 0; i < value.length(); i++) {
                char character = value.charAt(i);
                if (escaped) {
                    escaped = false;
                } else if (quoted && character == '\\') {
                    escaped = true;
                } else if (character == '"') {
                    quoted = !quoted;
                } else if (!quoted) {
                    countDelimiter(character, companion);
                }
            }
        }

        private void countDelimiter(char character, boolean companion) {
            if (character == '(') {
                throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                        "RFC certificate field contains an inner list");
            }
            if (character == ';') {
                ForwardedCertificateLimits.parameterCount(++parameters);
            } else if (companion && character == ',') {
                ForwardedCertificateLimits.certificateCount(++members + 1);
            }
        }
    }
}

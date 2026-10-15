package com.otilm.core.security.authn;

import com.otilm.api.exception.PlatformException;
import com.otilm.core.util.CertificateUtil;
import jakarta.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;

/** Parses proxy-forwarded certificates into one immutable leaf identity and untrusted candidates. */
public final class ForwardedClientCertificateParser {
    private ForwardedClientCertificateParser() {
    }

    static ParsedCertificate parse(String header) throws NoSuchAlgorithmException {
        String selected = selectedValue(header);
        return normalize(decode(selected, envelope(selected), List.of()));
    }

    public static ParsedCertificate parse(HttpServletRequest request, String headerName)
            throws NoSuchAlgorithmException {
        String header = request.getHeader(headerName);
        String selected = selectedValue(header);
        Envelope envelope = envelope(selected);
        rejectRepeatedIdentityFields(request, headerName, envelope);
        List<String> companions = envelope == Envelope.RFC9440 ? companions(request, header) : List.of();
        return normalize(decode(selected, envelope, companions));
    }

    private static void rejectRepeatedIdentityFields(HttpServletRequest request, String headerName, Envelope selected) {
        var values = request.getHeaders(headerName);
        boolean assertedIdentity = selected != Envelope.CERTIFICATE;
        int occurrences = 0;
        while (values != null && values.hasMoreElements()) {
            String value = values.nextElement();
            String trimmed = value == null ? "" : value.trim();
            occurrences++;
            if (!trimmed.isEmpty() && envelope(trimmed) != Envelope.CERTIFICATE) {
                assertedIdentity = true;
            }
            if (occurrences > 1 && assertedIdentity) {
                throw new InvalidCertificateHeaderException("Repeated certificate identity field");
            }
        }
    }

    private static String selectedValue(String header) {
        ForwardedCertificateLimits.headerBytes(header, 0);
        if (header.isBlank()) {
            throw new InvalidCertificateHeaderException("Empty certificate header");
        }
        return header.trim();
    }

    private static List<String> companions(HttpServletRequest request, String leaf) {
        var fields = request.getHeaders("Client-Cert-Chain");
        List<String> values = new ArrayList<>();
        int bytes = leaf.length();
        while (fields != null && fields.hasMoreElements()) {
            if (values.size() == ForwardedCertificateLimits.COMPANION_LINES) {
                throw new InvalidCertificateHeaderException("RFC companion occurrence limit exceeded");
            }
            String value = fields.nextElement();
            bytes = ForwardedCertificateLimits.headerBytes(value, bytes + (values.isEmpty() ? 0 : 1));
            values.add(value);
        }
        return values;
    }

    private static Envelope envelope(String value) {
        if (value.charAt(0) == ':') {
            return Envelope.RFC9440;
        }
        if (bareCertificateSequence(value)) {
            return Envelope.CERTIFICATE;
        }
        int position = 0;
        while (position < value.length() && XfccCertificateDecoder.keyCharacter(value.charAt(position))) {
            position++;
        }
        return position > 0 && position < value.length() && value.charAt(position) == '='
                ? Envelope.XFCC
                : Envelope.CERTIFICATE;
    }

    /** Checks transport characters without decoding the outer grammar or mistaking Base64 padding for assignments. */
    private static boolean bareCertificateSequence(String value) {
        BareCertificateMember member = new BareCertificateMember();
        int position = 0;
        while (position < value.length()) {
            char character = value.charAt(position);
            if (character == '%') {
                character = percentCharacter(value, position);
                position += 3;
            } else {
                position++;
            }
            if (!member.accept(character)) {
                return false;
            }
        }
        return member.content;
    }

    private static char percentCharacter(String value, int position) {
        if (position + 2 >= value.length()) {
            return '\0';
        }
        int high = Character.digit(value.charAt(position + 1), 16);
        int low = Character.digit(value.charAt(position + 2), 16);
        return high < 0 || low < 0 ? '\0' : (char) (high * 16 + low);
    }

    private static final class BareCertificateMember {
        private boolean content;
        private int paddingCount;

        private boolean accept(char character) {
            if (character == ',') {
                boolean complete = content;
                content = false;
                paddingCount = 0;
                return complete;
            }
            if (character == '=') {
                return content && ++paddingCount <= 2;
            }
            if (" \t\r\n".indexOf(character) >= 0) {
                return true;
            }
            if (paddingCount > 0 || !base64Character(character)) {
                return false;
            }
            content = true;
            return true;
        }

        private static boolean base64Character(char character) {
            return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
                    || character >= '0' && character <= '9' || character == '+' || character == '/';
        }
    }

    private static List<byte[]> decode(String value, Envelope envelope, List<String> companions) {
        return switch (envelope) {
            case CERTIFICATE -> CertificateHeaderValueDecoder.decode(value);
            case RFC9440 -> Rfc9440CertificateDecoder.decode(value, companions);
            case XFCC -> XfccCertificateDecoder.decode(value);
        };
    }

    private static ParsedCertificate normalize(List<byte[]> certificates) throws NoSuchAlgorithmException {
        byte[] leaf = certificates.getFirst();
        String content = Base64.getEncoder().encodeToString(leaf);
        LinkedHashSet<String> candidates = new LinkedHashSet<>();
        for (int i = 1; i < certificates.size(); i++) {
            String candidate = Base64.getEncoder().encodeToString(certificates.get(i));
            if (!content.equals(candidate)) {
                candidates.add(candidate);
            }
        }
        return new ParsedCertificate(content, CertificateUtil.getThumbprint(leaf), List.copyOf(candidates));
    }

    private enum Envelope {
        CERTIFICATE,
        RFC9440,
        XFCC
    }

    public static final class InvalidCertificateHeaderException extends IllegalArgumentException
            implements
                PlatformException {
        InvalidCertificateHeaderException(String reason) {
            super(reason);
        }
    }

    public static final class ParsedCertificate {
        private final String content;
        private final String thumbprint;
        private final List<String> chain;

        private ParsedCertificate(String content, String thumbprint, List<String> chain) {
            this.content = content;
            this.thumbprint = thumbprint;
            this.chain = chain;
        }

        public String content() {
            return content;
        }

        public String thumbprint() {
            return thumbprint;
        }

        public List<String> chain() {
            return chain;
        }
    }
}

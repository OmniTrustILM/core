package com.otilm.core.security.authn;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class XfccCertificateDecoder {
    private XfccCertificateDecoder() {
    }

    static List<byte[]> decode(String value) {
        ForwardedCertificateLimits.headerBytes(value, 0);
        Map<String, String> fields = certificateFields(value);
        String cert = fields.get("cert");
        if (cert == null) {
            throw new IllegalArgumentException("Missing XFCC certificate");
        }
        List<byte[]> leaf = CertificateHeaderValueDecoder.decodePemTransport(cert);
        if (leaf.size() != 1) {
            throw new IllegalArgumentException("XFCC Cert must contain one certificate");
        }
        return candidates(leaf.getFirst(), fields.get("chain"));
    }

    private static Map<String, String> certificateFields(String value) {
        Map<String, String> fields = new HashMap<>();
        int position = 0;
        int pairs = 0;
        while (position < value.length()) {
            if (++pairs > ForwardedCertificateLimits.XFCC_PAIRS) {
                throw new IllegalArgumentException("XFCC pair count limit exceeded");
            }
            int end = keyEnd(value, position);
            String key = value.substring(position, end).toLowerCase(Locale.ROOT);
            Value parsed = fieldValue(value, end + 1);
            if (key.equals("cert") || key.equals("chain")) {
                addCertificateField(fields, key, parsed.text());
            }
            position = nextPair(value, parsed.end());
        }
        return fields;
    }

    private static void addCertificateField(Map<String, String> fields, String key, String text) {
        if (text.isEmpty() || fields.putIfAbsent(key, text) != null) {
            throw new IllegalArgumentException("Invalid XFCC certificate field occurrence");
        }
    }

    private static int keyEnd(String value, int start) {
        int position = start;
        while (position < value.length() && keyCharacter(value.charAt(position))) {
            position++;
        }
        if (position == start || position == value.length() || value.charAt(position) != '=') {
            throw syntaxFailure();
        }
        return position;
    }

    private static int nextPair(String value, int position) {
        if (position == value.length()) {
            return position;
        }
        if (value.charAt(position) != ';' || position + 1 == value.length()) {
            throw syntaxFailure();
        }
        return position + 1;
    }

    private static List<byte[]> candidates(byte[] leaf, String chain) {
        List<byte[]> certificates = new ArrayList<>();
        certificates.add(leaf);
        if (chain != null) {
            List<byte[]> bundle = CertificateHeaderValueDecoder.decodePemTransport(chain);
            if (!Arrays.equals(leaf, bundle.getFirst())) {
                throw new IllegalArgumentException("XFCC Chain does not begin with the leaf");
            }
            for (int i = 1; i < bundle.size(); i++) {
                if (Arrays.equals(leaf, bundle.get(i))) {
                    throw new IllegalArgumentException("XFCC Chain repeats the leaf");
                }
                certificates.add(bundle.get(i));
            }
        }
        return certificates;
    }

    private static Value fieldValue(String value, int start) {
        if (start < value.length() && value.charAt(start) == '"') {
            return quotedValue(value, start + 1);
        }
        int position = start;
        while (position < value.length()) {
            char character = value.charAt(position);
            if (character == ';' || character == ',') {
                break;
            }
            if (controlCharacter(character) || " \"\\".indexOf(character) >= 0) {
                throw syntaxFailure();
            }
            position++;
        }
        return new Value(value.substring(start, position), position);
    }

    private static Value quotedValue(String value, int start) {
        StringBuilder text = new StringBuilder();
        int position = start;
        while (position < value.length()) {
            char character = value.charAt(position++);
            if (character == '"') {
                return new Value(text.toString(), position);
            }
            if (character == '\\') {
                character = escapedCharacter(value, position++);
            } else if (invalidQuotedCharacter(character)) {
                throw syntaxFailure();
            }
            text.append(character);
        }
        throw syntaxFailure();
    }

    private static char escapedCharacter(String value, int position) {
        if (position == value.length()) {
            throw syntaxFailure();
        }
        char character = value.charAt(position);
        if (invalidQuotedCharacter(character)) {
            throw syntaxFailure();
        }
        return character;
    }

    private static boolean invalidQuotedCharacter(char character) {
        return character != '\t' && controlCharacter(character);
    }

    private static boolean controlCharacter(char character) {
        return character < 32 || character == 127;
    }

    static boolean keyCharacter(char character) {
        return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
                || character >= '0' && character <= '9' || "!#$%&'*+-.^_`|~".indexOf(character) >= 0;
    }

    private static IllegalArgumentException syntaxFailure() {
        return new IllegalArgumentException("Invalid XFCC certificate field syntax");
    }

    private record Value(String text, int end) {
    }
}

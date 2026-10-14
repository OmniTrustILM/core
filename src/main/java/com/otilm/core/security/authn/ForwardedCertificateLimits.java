package com.otilm.core.security.authn;

final class ForwardedCertificateLimits {
    static final int HEADER_BYTES = 262144;
    static final int DER_BYTES = 65536;
    static final int CERTIFICATES = 16;
    static final int COMPANION_LINES = 16;
    static final int XFCC_PAIRS = 128;

    private ForwardedCertificateLimits() {
    }

    static int headerBytes(String value, int previous) {
        if (value == null) {
            throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException("Empty certificate header");
        }
        if (previous > HEADER_BYTES) {
            throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                    "Certificate header size limit exceeded");
        }
        int size = previous;
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (character > 127) {
                throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                        "Invalid certificate header encoding");
            }
            if (++size > HEADER_BYTES) {
                throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                        "Certificate header size limit exceeded");
            }
        }
        return size;
    }

    static void certificateCount(int count) {
        if (count > CERTIFICATES) {
            throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                    "Certificate count limit exceeded");
        }
    }

    static void derSize(int size) {
        if (size > DER_BYTES) {
            throw new ForwardedClientCertificateParser.InvalidCertificateHeaderException(
                    "Certificate DER size limit exceeded");
        }
    }
}

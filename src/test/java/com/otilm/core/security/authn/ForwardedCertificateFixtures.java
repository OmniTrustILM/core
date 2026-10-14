package com.otilm.core.security.authn;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public final class ForwardedCertificateFixtures {
    private static final String EMPTY_PKCS7 = "MCMGCSqGSIb3DQEHAqAWMBQCAQExADALBgkqhkiG9w0BBwExAA==";
    public static final String LEAF_PEM = read("leaf.pem");
    public static final String LEAF_DER = content(LEAF_PEM);
    public static final String ISSUER_DER = content(read("issuer.pem"));
    public static final String THUMBPRINT = "b9b5806e249ad19a7f632c5a5d1a92e7c7e51bfd792a46901d6be0c4ba12e6e3";

    private ForwardedCertificateFixtures() {
    }

    public static Stream<Arguments> supportedHeaders() {
        Stream<Arguments> original = headers(LEAF_PEM).map(header -> Arguments.of(header, LEAF_DER, THUMBPRINT));
        Stream<Arguments> explicit = Stream
                .of(new String[]{
                        "explicit-secp256r1.pem",
                        "3cf6e07c353c058e9aebd0f8658af5186ca50b35f42a949731570e450f3d78ac"},
                        new String[]{
                                "explicit-brainpoolP256r1.pem",
                                "97b591598f2fecaea48a7cb03e0520b2ff722bcbbe453b3b42d531e2f487bf6c"})
                .flatMap(fixture -> {
                    String pem = read(fixture[0]);
                    return headers(pem).map(header -> Arguments.of(header, content(pem), fixture[1]));
                });
        return Stream.concat(original, explicit);
    }

    private static Stream<String> headers(String pem) {
        String der = content(pem);
        String wrapped = wrapPem(pem);
        return Stream
                .of(der, der + "," + ISSUER_DER, pem, wrapped, URLEncoder.encode(wrapped, StandardCharsets.UTF_8),
                        URLEncoder.encode(der, StandardCharsets.UTF_8), URLEncoder.encode(pem, StandardCharsets.UTF_8),
                        URLEncoder.encode(pem, StandardCharsets.UTF_8).replace("+", "%20"),
                        "%0A" + URLEncoder.encode(pem, StandardCharsets.UTF_8),
                        URLEncoder.encode(" \t\n" + pem, StandardCharsets.UTF_8),
                        URLEncoder.encode(pem, StandardCharsets.UTF_8).replace("-", "%2D"));
    }

    public static Stream<String> malformedHeaders() {
        return List
                .of("", "%%%", "!!not-base64!!", "dGVzdA==", EMPTY_PKCS7, LEAF_DER + ",", "," + LEAF_DER,
                        LEAF_DER + ",dGVzdA==", LEAF_DER + "," + ISSUER_DER + ",!", LEAF_DER + "AAAA", trailingBytes(),
                        "-----BEGIN CERTIFICATE-----\n" + LEAF_DER)
                .stream();
    }

    private static String trailingBytes() {
        byte[] der = Base64.getDecoder().decode(LEAF_DER);
        return Base64.getEncoder().encodeToString(Arrays.copyOf(der, der.length + 1));
    }

    public static String read(String name) {
        try (var input = ForwardedCertificateFixtures.class.getResourceAsStream("/security/authn/" + name)) {
            return new String(input.readAllBytes(), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String content(String pem) {
        return pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }

    static byte[] sizedCertificate(int size) throws Exception {
        var keys = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var name = new org.bouncycastle.asn1.x500.X500Name("CN=Parser size boundary");
        var publicKey = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("Ed25519").build(keys.getPrivate());
        int padding = Math.max(1, size - 300);
        for (int attempt = 0; attempt < 3; attempt++) {
            var builder = new org.bouncycastle.cert.X509v3CertificateBuilder(name, java.math.BigInteger.ONE,
                    new java.util.Date(0), new java.util.Date(1893456000000L), name, publicKey);
            builder
                    .addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4"), false,
                            new org.bouncycastle.asn1.DEROctetString(new byte[padding]));
            byte[] certificate = builder.build(signer).getEncoded();
            if (certificate.length == size) {
                return certificate;
            }
            padding += size - certificate.length;
        }
        throw new IllegalStateException("Cannot construct certificate size fixture");
    }

    static String wrapPem(String pem) {
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII));
    }
}

package com.otilm.ai.controller;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KubernetesConfigurationTest {
    @TempDir
    Path directory;

    @Test
    void fixedConfigurationUsesOnlyItsExplicitApiCaAndTokenReference() throws Exception {
        byte[] expected = new byte[]{'{', '}'};
        try (var server = new KubernetesHttpsFixture(200, expected)) {
            Path roots = directory.resolve("api-ca.der");
            Files.write(roots, server.ca.getEncoded());
            var configuration = new KubernetesConfiguration(server.endpoint(), roots, token());
            var client = assertDoesNotThrow(() -> configuration.open(Duration.ofSeconds(2)));
            assertArrayEquals(expected, client.namespace("runtime"));
            assertEquals(1, server.requests.get());
            assertEquals("Bearer synthetic.api.token", server.authorization.get());
        }
    }

    @Test
    void anotherCaCannotAuthorizeTheConfiguredApiEndpoint() throws Exception {
        try (var server = new KubernetesHttpsFixture(200, new byte[]{'{', '}'});
                var other = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path roots = directory.resolve("other-ca.der");
            Files.write(roots, other.ca.getEncoded());
            var configuration = new KubernetesConfiguration(server.endpoint(), roots, token());
            assertThrows(ObservationFailure.class,
                    () -> configuration.open(Duration.ofSeconds(2)).namespace("runtime"));
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void missingMalformedOversizedOrExpiredBootstrapBudgetCannotSendAnyRequest() throws Exception {
        try (var server = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path roots = directory.resolve("api-ca.der");
            var configuration = new KubernetesConfiguration(server.endpoint(), roots, token());
            assertThrows(ObservationFailure.class, () -> configuration.open(Duration.ofSeconds(2)));
            Files.writeString(roots, "PUBLIC_CA_CANARY");
            assertThrows(ObservationFailure.class, () -> configuration.open(Duration.ofSeconds(2)));
            Files.write(roots, new byte[65537]);
            assertThrows(ObservationFailure.class, () -> configuration.open(Duration.ofSeconds(2)));
            Files.write(roots, server.ca.getEncoded());
            assertThrows(ObservationFailure.class, () -> configuration.open(Duration.ofNanos(1)));
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void aLeafOrACaWithoutCertificateSigningUsageCannotBecomeAnApiTrustAnchor() throws Exception {
        try (var server = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path roots = directory.resolve("invalid-purpose.der");
            Path credential = token();
            var configuration = new KubernetesConfiguration(server.endpoint(), roots, credential);
            for (boolean ca : new boolean[]{false, true}) {
                Files.write(roots, certificate(ca, false).getEncoded());
                assertThrows(ObservationFailure.class, () -> configuration.open(Duration.ofSeconds(2)),
                        "CA=" + ca + " with only digitalSignature usage");
            }
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void expiredOrTooManyApiTrustAnchorsCannotOpenAnApiClient() throws Exception {
        try (var server = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path roots = directory.resolve("invalid-roots.der");
            var configuration = new KubernetesConfiguration(server.endpoint(), roots, token());
            Files.write(roots, certificate(true, true).getEncoded());
            assertThrows(ObservationFailure.class, () -> configuration.open(Duration.ofSeconds(2)));
            var seventeen = new java.io.ByteArrayOutputStream();
            for (int index = 0; index < 17; index++) {
                seventeen.write(server.ca.getEncoded());
            }
            Files.write(roots, seventeen.toByteArray());
            assertThrows(ObservationFailure.class, () -> configuration.open(Duration.ofSeconds(2)));
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void malformedRootConfigurationAndWritableTrustSourcesCannotOpenTheApi() throws Exception {
        try (var server = new KubernetesHttpsFixture(200, new byte[]{'{', '}'})) {
            Path roots = directory.resolve("api-ca.der");
            Files.write(roots, server.ca.getEncoded());
            Path credential = token();
            assertThrows(ObservationFailure.class, () -> new KubernetesConfiguration(null, roots, credential));
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesConfiguration(server.endpoint(), null, credential));
            assertThrows(ObservationFailure.class, () -> new KubernetesConfiguration(server.endpoint(), roots, null));
            for (Path path : new Path[]{Path.of("relative"), Path.of("/"), directory.resolve("x/../ca")}) {
                assertThrows(ObservationFailure.class,
                        () -> new KubernetesConfiguration(server.endpoint(), path, credential));
            }
            var context = new com.otilm.ai.proxy.CoreEndpoint(java.net.URI.create(server.endpoint().origin() + "/api"),
                    server.endpoint().address());
            assertThrows(ObservationFailure.class, () -> new KubernetesConfiguration(context, roots, credential));
            var configuration = new KubernetesConfiguration(server.endpoint(), roots, credential);
            for (Duration budget : new Duration[]{null, Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(6)}) {
                assertThrows(ObservationFailure.class, () -> configuration.open(budget));
            }
            Files.setPosixFilePermissions(roots, PosixFilePermissions.fromString("rw-rw-rw-"));
            assertThrows(ObservationFailure.class, () -> configuration.open(Duration.ofSeconds(2)));
            assertThrows(ObservationFailure.class,
                    () -> new KubernetesConfiguration(server.endpoint(), directory, credential)
                            .open(Duration.ofSeconds(2)));
            assertEquals(0, server.requests.get());
        }
    }

    private Path token() throws Exception {
        Path file = Files.createTempFile(directory, "api-", ".token");
        Files.writeString(file, "synthetic.api.token");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        return file;
    }

    private static X509Certificate certificate(boolean ca, boolean expired) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        var keys = generator.generateKeyPair();
        var name = new X500Name("CN=synthetic invalid API trust purpose");
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(name, java.math.BigInteger.ONE, Date.from(now.minusSeconds(120)),
                Date.from(now.plusSeconds(expired ? -60 : 3600)), name, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }
}

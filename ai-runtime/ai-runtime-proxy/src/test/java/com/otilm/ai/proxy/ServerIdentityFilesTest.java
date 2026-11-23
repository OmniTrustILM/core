package com.otilm.ai.proxy;

import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Fixed server purpose and real JSSE handshake controls; synthetic files confer no native Core identity. */
class ServerIdentityFilesTest {
    @TempDir
    Path directory;

    @Test
    void serverPurposeMaterialCanServeAnActualTls13Handshake() throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("client"))) {
            var server = LocalTlsFixture.material("core.test", fixture.ca, false, "core.test", false, "secp256r1");
            Path files = directory.resolve("server");
            LocalTlsFixture.writeClient(files, server);
            Path roots = fixture.configuration().serverCaFile();
            Files
                    .writeString(files.resolve("tls.crt"),
                            Files.readString(files.resolve("tls.crt")) + Files.readString(roots));
            var manager = assertDoesNotThrow(
                    () -> IdentityFiles.loadServerKeys(files.resolve("tls.crt"), files.resolve("tls.key"), roots));
            assertThrows(GeneralSecurityException.class,
                    () -> IdentityFiles.load(files.resolve("tls.crt"), files.resolve("tls.key"), roots));
            SSLContext serving = SSLContext.getInstance("TLS");
            serving.init(new KeyManager[]{manager}, null, null);
            var failure = new AtomicReference<Throwable>();
            try (var listener = (SSLServerSocket) serving
                    .getServerSocketFactory()
                    .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                listener.setSoTimeout(2000);
                listener.setEnabledProtocols(new String[]{"TLSv1.3"});
                var accepted = Thread.ofPlatform().daemon().name("synthetic-server-purpose").start(() -> {
                    try (var peer = (SSLSocket) listener.accept()) {
                        peer.setSoTimeout(2000);
                        peer.startHandshake();
                        peer.getOutputStream().write(7);
                    } catch (Throwable unavailable) {
                        failure.set(unavailable);
                    }
                });
                try {
                    var client = IdentityFiles.load(fixture.configuration());
                    try (var connection = new java.net.Socket(InetAddress.getLoopbackAddress(),
                            listener.getLocalPort());
                            var peer = (SSLSocket) client
                                    .getSocketFactory()
                                    .createSocket(connection, "core.test", listener.getLocalPort(), true)) {
                        peer.setSoTimeout(2000);
                        var parameters = peer.getSSLParameters();
                        parameters.setEndpointIdentificationAlgorithm("HTTPS");
                        peer.setSSLParameters(parameters);
                        peer.startHandshake();
                        assertEquals("TLSv1.3", peer.getSession().getProtocol());
                        assertEquals(server.certificate().getSerialNumber(),
                                ((java.security.cert.X509Certificate) peer.getSession().getPeerCertificates()[0])
                                        .getSerialNumber());
                        assertEquals(7, peer.getInputStream().read());
                    }
                } finally {
                    listener.close();
                    accepted.join(2000);
                    assertFalse(accepted.isAlive());
                }
            }
            assertNull(failure.get());
        }
    }

    @Test
    void clientPurposeAndMismatchedKeysCannotBecomeServerMaterial() throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("client"))) {
            var configuration = fixture.configuration();
            assertThrows(GeneralSecurityException.class,
                    () -> IdentityFiles
                            .loadServerKeys(configuration.certificateFile(), configuration.privateKeyFile(),
                                    configuration.serverCaFile()));
            var first = LocalTlsFixture.material("core.test", fixture.ca, false, "core.test", false, "secp256r1");
            var other = LocalTlsFixture.material("other.test", fixture.ca, false, "other.test", false, "secp256r1");
            Path files = directory.resolve("server");
            LocalTlsFixture.writeClient(files, first);
            LocalTlsFixture.writePem(files.resolve("tls.key"), "PRIVATE KEY", other.keys().getPrivate().getEncoded());
            assertThrows(GeneralSecurityException.class, () -> IdentityFiles
                    .loadServerKeys(files.resolve("tls.crt"), files.resolve("tls.key"), configuration.serverCaFile()));
        }
    }

    @Test
    void serverChainMustReachTheExplicitServerCa() throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("client"))) {
            var server = LocalTlsFixture.material("core.test", fixture.ca, false, "core.test", false, "secp256r1");
            var other = LocalTlsFixture.material("other-ca", null, true, null, false, "secp256r1");
            Path files = directory.resolve("server");
            LocalTlsFixture.writeClient(files, server);
            LocalTlsFixture.writePem(files.resolve("other-ca.pem"), "CERTIFICATE", other.certificate().getEncoded());
            assertThrows(GeneralSecurityException.class, () -> IdentityFiles
                    .loadServerKeys(files.resolve("tls.crt"), files.resolve("tls.key"), files.resolve("other-ca.pem")));
        }
    }

    @Test
    void serverRotationReadsOnlyTheCurrentConsistentRevisionWithoutFallback() throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("client"))) {
            Path mount = Files.createDirectory(directory.resolve("mount"));
            var first = LocalTlsFixture.material("core.test", fixture.ca, false, "core.test", false, "secp256r1");
            var second = LocalTlsFixture.material("core.test", fixture.ca, false, "core.test", false, "secp256r1");
            LocalTlsFixture.writeClient(mount.resolve("revision-one"), first);
            LocalTlsFixture.writeClient(mount.resolve("revision-two"), second);
            Files.createSymbolicLink(mount.resolve("..data"), Path.of("revision-one"));
            Files.createSymbolicLink(mount.resolve("tls.crt"), Path.of("..data/tls.crt"));
            Files.createSymbolicLink(mount.resolve("tls.key"), Path.of("..data/tls.key"));
            Path ca = fixture.configuration().serverCaFile();
            var original = IdentityFiles.loadServerKeys(mount.resolve("tls.crt"), mount.resolve("tls.key"), ca);
            assertEquals(first.certificate().getSerialNumber(),
                    original.getCertificateChain(original.getServerAliases("EC", null)[0])[0].getSerialNumber());
            Files.createSymbolicLink(mount.resolve("..next"), Path.of("revision-two"));
            Files
                    .move(mount.resolve("..next"), mount.resolve("..data"),
                            java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            var rotated = IdentityFiles.loadServerKeys(mount.resolve("tls.crt"), mount.resolve("tls.key"), ca);
            assertEquals(second.certificate().getSerialNumber(),
                    rotated.getCertificateChain(rotated.getServerAliases("EC", null)[0])[0].getSerialNumber());
            Files.delete(mount.resolve("revision-two/tls.key"));
            assertThrows(GeneralSecurityException.class,
                    () -> IdentityFiles.loadServerKeys(mount.resolve("tls.crt"), mount.resolve("tls.key"), ca));
        }
    }

    @Test
    void expiredAndUnsupportedServerKeysAreRejectedBeforeUse() throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("client"))) {
            for (var material : new LocalTlsFixture.Material[]{
                    LocalTlsFixture.material("core.test", fixture.ca, false, "core.test", true, "secp256r1"),
                    LocalTlsFixture.material("core.test", fixture.ca, false, "core.test", false, "secp384r1")}) {
                Path files = directory.resolve("server");
                LocalTlsFixture.writeClient(files, material);
                assertThrows(GeneralSecurityException.class,
                        () -> IdentityFiles
                                .loadServerKeys(files.resolve("tls.crt"), files.resolve("tls.key"),
                                        fixture.configuration().serverCaFile()));
            }
        }
    }

    @ParameterizedTest
    @MethodSource("invalidProfiles")
    void serverPurposeExtensionRulesCannotBeOmitted(Profile profile) throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("client"))) {
            var material = extensionProfile(fixture.ca, profile);
            Path files = directory.resolve("server");
            LocalTlsFixture.writeClient(files, material);
            assertThrows(GeneralSecurityException.class,
                    () -> IdentityFiles
                            .loadServerKeys(files.resolve("tls.crt"), files.resolve("tls.key"),
                                    fixture.configuration().serverCaFile()));
        }
    }

    @Test
    void extensionProfileFixtureAlsoProducesAnAcceptedServerOnlyLeaf() throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("client"))) {
            var profile = new Profile(false, org.bouncycastle.asn1.x509.KeyUsage.digitalSignature,
                    new org.bouncycastle.asn1.x509.KeyPurposeId[]{
                            org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth});
            Path files = directory.resolve("server");
            LocalTlsFixture.writeClient(files, extensionProfile(fixture.ca, profile));
            assertDoesNotThrow(() -> IdentityFiles
                    .loadServerKeys(files.resolve("tls.crt"), files.resolve("tls.key"),
                            fixture.configuration().serverCaFile()));
        }
    }

    @Test
    void anExplicitIntermediateAnchorCanTerminateThePresentedServerChain() throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("client"))) {
            var intermediate = LocalTlsFixture.material("intermediate", fixture.ca, true, null, false, "secp256r1");
            var server = LocalTlsFixture.material("core.test", intermediate, false, "core.test", false, "secp256r1");
            Path files = directory.resolve("server");
            LocalTlsFixture.writeClient(files, server);
            LocalTlsFixture.writePem(files.resolve("ca.pem"), "CERTIFICATE", intermediate.certificate().getEncoded());
            Files
                    .writeString(files.resolve("tls.crt"), Files.readString(files.resolve("tls.crt"))
                            + pem(intermediate.certificate()) + pem(fixture.ca.certificate()));
            assertDoesNotThrow(() -> IdentityFiles
                    .loadServerKeys(files.resolve("tls.crt"), files.resolve("tls.key"), files.resolve("ca.pem")));
        }
    }

    private record Profile(boolean ca, Integer usage, org.bouncycastle.asn1.x509.KeyPurposeId[] purposes) {
    }

    private static java.util.stream.Stream<Profile> invalidProfiles() {
        var server = org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth;
        var client = org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth;
        int signing = org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
        return java.util.stream.Stream
                .of(new Profile(true, signing | org.bouncycastle.asn1.x509.KeyUsage.keyCertSign,
                        new org.bouncycastle.asn1.x509.KeyPurposeId[]{server}),
                        new Profile(false, null, new org.bouncycastle.asn1.x509.KeyPurposeId[]{server}),
                        new Profile(false, org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment,
                                new org.bouncycastle.asn1.x509.KeyPurposeId[]{server}),
                        new Profile(false, signing, null),
                        new Profile(false, signing, new org.bouncycastle.asn1.x509.KeyPurposeId[]{server, client}),
                        new Profile(false, signing, new org.bouncycastle.asn1.x509.KeyPurposeId[]{
                                org.bouncycastle.asn1.x509.KeyPurposeId.anyExtendedKeyUsage}));
    }

    private static LocalTlsFixture.Material extensionProfile(LocalTlsFixture.Material ca, Profile profile)
            throws Exception {
        var keys = LocalTlsFixture.material("unused", ca, false, "core.test", false, "secp256r1").keys();
        var now = java.time.Instant.now();
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                new org.bouncycastle.asn1.x500.X500Name(ca.certificate().getSubjectX500Principal().getName()),
                new java.math.BigInteger(128, new java.security.SecureRandom()),
                java.util.Date.from(now.minusSeconds(30)), java.util.Date.from(now.plusSeconds(300)),
                new org.bouncycastle.asn1.x500.X500Name("CN=core.test"), keys.getPublic());
        builder
                .addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                        new org.bouncycastle.asn1.x509.BasicConstraints(profile.ca()));
        if (profile.usage() != null) {
            builder
                    .addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                            new org.bouncycastle.asn1.x509.KeyUsage(profile.usage()));
        }
        if (profile.purposes() != null) {
            builder
                    .addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false,
                            new org.bouncycastle.asn1.x509.ExtendedKeyUsage(profile.purposes()));
        }
        var certificate = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(builder
                        .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                                .build(ca.keys().getPrivate())));
        return new LocalTlsFixture.Material(keys, certificate);
    }

    private static String pem(java.security.cert.X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }
}

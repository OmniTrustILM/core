package com.otilm.ai.gateway;

import com.otilm.ai.proxy.CoreEndpoint;
import com.otilm.ai.proxy.IdentityFiles;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.hc.core5.net.InetAddressUtils;

/** Fixed administrator deployment pins; no selection is taken from the public dispatch reference. */
final class GatewayRunConfiguration {
    private final CoreEndpoint core;
    private final Path certificate;
    private final Path key;
    private final Path serverCa;
    private final URI provider;
    private final InetAddress providerAddress;
    private final Path providerCa;
    private final GatewayRunWire.Connection connection;
    private final String reference;
    private final Path secret;
    private final AtomicBoolean resolved = new AtomicBoolean();

    private GatewayRunConfiguration(com.fasterxml.jackson.databind.JsonNode n) throws Exception {
        GatewayRunWire
                .fields(n, "protocolVersion", "coreOrigin", "coreAddress", "certificateFile", "privateKeyFile",
                        "serverCaFile", "providerOrigin", "providerAddress", "providerCaFile", "connection",
                        "credentialReference", "credentialFile");
        GatewayRunWire.positive(n, "protocolVersion", 1);
        core = new CoreEndpoint(URI.create(GatewayRunWire.text(n, "coreOrigin")),
                address(GatewayRunWire.text(n, "coreAddress")));
        certificate = path(GatewayRunWire.text(n, "certificateFile"));
        key = path(GatewayRunWire.text(n, "privateKeyFile"));
        serverCa = path(GatewayRunWire.text(n, "serverCaFile"));
        if (!certificate.getParent().equals(key.getParent())) {
            throw GatewayRunWire.invalid();
        }
        provider = normalized(GatewayRunWire.origin(GatewayRunWire.text(n, "providerOrigin")));
        providerAddress = address(GatewayRunWire.text(n, "providerAddress"));
        providerCa = path(GatewayRunWire.text(n, "providerCaFile"));
        connection = GatewayRunWire.connection(n.get("connection"));
        reference = GatewayRunWire.reference(GatewayRunWire.text(n, "credentialReference"));
        secret = path(GatewayRunWire.text(n, "credentialFile"));
    }

    static GatewayRunConfiguration read(Path path) {
        try {
            return new GatewayRunConfiguration(GatewayRunWire.parse(snapshot(path, 16384), 16384));
        } catch (Exception bad) {
            throw GatewayRunWire.invalid();
        }
    }

    CoreEndpoint core() {
        return core;
    }

    SSLContext identity() {
        try {
            return IdentityFiles.load(certificate, key, serverCa);
        } catch (Exception unavailable) {
            throw GatewayRunWire.invalid();
        }
    }

    void verify(GatewayRunWire.Consumed consumed) {
        if (!connection.equals(consumed.connection()) || !provider.equals(normalized(consumed.origin()))
                || !reference.equals(consumed.credentialReference()) || !consumed.expiresAt().isAfter(Instant.now())) {
            throw GatewayRunWire.invalid();
        }
    }

    String credential(GatewayRunWire.Consumed consumed) {
        if (!resolved.compareAndSet(false, true)) {
            throw GatewayRunWire.invalid();
        }
        verify(consumed);
        byte[] bytes = null;
        try {
            bytes = snapshot(secret, 8192);
            var root = GatewayRunWire.parse(bytes, 8192);
            GatewayRunWire.fields(root, "protocolVersion", "credentialReference", "authentication", "bearer");
            GatewayRunWire.positive(root, "protocolVersion", 1);
            if (!reference.equals(GatewayRunWire.text(root, "credentialReference"))
                    || GatewayRunWire.positive(root, "authentication", Long.MAX_VALUE) != connection.authentication()) {
                throw GatewayRunWire.invalid();
            }
            String bearer = GatewayRunWire.text(root, "bearer");
            if (bearer.length() > 4096 || !bearer.matches("[A-Za-z0-9._~+/=-]+")) {
                throw GatewayRunWire.invalid();
            }
            return bearer;
        } catch (Exception unavailable) {
            throw GatewayRunWire.invalid();
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    PinnedEndpoint provider(GatewayRunWire.Consumed consumed) {
        verify(consumed);
        try {
            var certificates = CertificateFactory
                    .getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(snapshot(providerCa, 65536)));
            if (certificates.isEmpty() || certificates.size() > 16) {
                throw GatewayRunWire.invalid();
            }
            var store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            int index = 0;
            for (var raw : certificates) {
                var ca = (X509Certificate) raw;
                ca.checkValidity();
                boolean[] usage = ca.getKeyUsage();
                if (ca.getBasicConstraints() < 0 || (usage != null && (usage.length < 6 || !usage[5]))) {
                    throw GatewayRunWire.invalid();
                }
                store.setCertificateEntry("provider-" + index++, ca);
            }
            var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            var context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[0], trust.getTrustManagers(), null);
            return new PinnedEndpoint(provider, List.of(providerAddress), context);
        } catch (Exception unavailable) {
            throw GatewayRunWire.invalid();
        }
    }

    static byte[] snapshot(Path logical, int maximum) throws Exception {
        Path real = path(logical.toString()).toRealPath();
        BasicFileAttributes before = Files.readAttributes(real, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.fileKey() == null || before.size() < 1 || before.size() > maximum) {
            throw GatewayRunWire.invalid();
        }
        ByteBuffer buffer = ByteBuffer.allocate(maximum + 1);
        try (var input = Files.newByteChannel(real, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            while (buffer.hasRemaining()) {
                if (input.read(buffer) < 0) {
                    break;
                }
            }
        }
        var after = Files.readAttributes(real, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (buffer.position() > maximum || !logical.toRealPath().equals(real)
                || !Objects.equals(before.fileKey(), after.fileKey()) || before.size() != after.size()
                || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
            throw GatewayRunWire.invalid();
        }
        return Arrays.copyOf(buffer.array(), buffer.position());
    }

    private static Path path(String value) {
        Path path = Path.of(value);
        if (!path.isAbsolute() || path.normalize().getParent() == null) {
            throw GatewayRunWire.invalid();
        }
        return path.normalize();
    }

    private static InetAddress address(String value) throws Exception {
        if (!InetAddressUtils.isIPv4(value) && !InetAddressUtils.isIPv6(value)) {
            throw GatewayRunWire.invalid();
        }
        InetAddress result = InetAddress.getByName(value);
        if (result.isAnyLocalAddress() || result.isMulticastAddress()) {
            throw GatewayRunWire.invalid();
        }
        return result;
    }

    private static URI normalized(URI uri) {
        try {
            return new URI("https", null, uri.getHost().toLowerCase(Locale.ROOT),
                    uri.getPort() < 0 ? 443 : uri.getPort(), "", null, null);
        } catch (Exception bad) {
            throw GatewayRunWire.invalid();
        }
    }

    @Override
    public String toString() {
        return "GatewayRunConfiguration[redacted]";
    }
}

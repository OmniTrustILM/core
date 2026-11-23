package com.otilm.ai.proxy;

import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProxyConfigurationTest {
    private final Path certificate = Path.of("/run/identity/tls.crt");
    private final Path key = Path.of("/run/identity/tls.key");
    private final Path ca = Path.of("/run/trust/ca.pem");

    @ParameterizedTest
    @ValueSource(strings = {
            "http://core.test",
            "https://user@core.test",
            "https://core.test/a//b",
            "https://core.test/%61pi",
            "https://core.test/a/../b",
            "https://core.test/a.",
            "https://core.test/api/",
            "https://core.test/",
            "https://core.test?x=1",
            "https://core.test#x",
            "https:///path",
            "https://core.test:0",
            "https://core.test:65536"})
    void refusesAnyDestinationThatIsNotAFixedHttpsOrigin(String origin) {
        assertThrows(IllegalArgumentException.class, () -> new ProxyConfiguration(URI.create(origin),
                InetAddress.getLoopbackAddress(), certificate, key, ca));
    }

    @Test
    void acceptsOnlyFiveFixedAdministratorArgumentsAndNumericAddress() {
        ProxyConfiguration parsed = ProxyConfiguration
                .fromArguments(new String[]{
                        "https://core.test:8443",
                        "127.0.0.1",
                        certificate.toString(),
                        key.toString(),
                        ca.toString()});
        assertEquals(URI.create("https://core.test:8443"), parsed.coreOrigin());
        assertEquals("127.0.0.1", parsed.coreAddress().getHostAddress());
        assertEquals(certificate, parsed.certificateFile());
        assertThrows(IllegalArgumentException.class, () -> ProxyConfiguration.fromArguments(new String[0]));
        assertThrows(IllegalArgumentException.class,
                () -> ProxyConfiguration
                        .fromArguments(new String[]{
                                "https://core.test",
                                "core.test",
                                certificate.toString(),
                                key.toString(),
                                ca.toString()}));
    }

    @Test
    void rejectsRootPathsAsControlledConfigurationErrors() {
        URI origin = URI.create("https://core.test");
        InetAddress address = InetAddress.getLoopbackAddress();
        assertThrows(IllegalArgumentException.class,
                () -> new ProxyConfiguration(origin, address, Path.of("/"), key, ca));
        assertThrows(IllegalArgumentException.class,
                () -> new ProxyConfiguration(origin, address, certificate, Path.of("/"), ca));
        assertThrows(IllegalArgumentException.class,
                () -> new ProxyConfiguration(origin, address, certificate, key, Path.of("/")));
    }

    @Test
    void rejectsEveryMissingAdministratorValueBeforeAnyOperation() {
        URI origin = URI.create("https://core.test");
        InetAddress address = InetAddress.getLoopbackAddress();
        assertThrows(IllegalArgumentException.class, () -> new ProxyConfiguration(null, address, certificate, key, ca));
        assertThrows(IllegalArgumentException.class, () -> new ProxyConfiguration(origin, null, certificate, key, ca));
        assertThrows(IllegalArgumentException.class, () -> new ProxyConfiguration(origin, address, null, key, ca));
        assertThrows(IllegalArgumentException.class,
                () -> new ProxyConfiguration(origin, address, certificate, null, ca));
        assertThrows(IllegalArgumentException.class,
                () -> new ProxyConfiguration(origin, address, certificate, key, null));
        assertThrows(IllegalArgumentException.class, () -> ProxyConfiguration.fromArguments(null));
        assertThrows(IllegalArgumentException.class,
                () -> new ProxyConfiguration(origin, address, certificate, Path.of("tls.key"), ca));
        assertThrows(IllegalArgumentException.class,
                () -> new ProxyConfiguration(origin, address, certificate, key, Path.of("ca.pem")));
    }

    @Test
    void acceptsAFixedNumericIpv6AddressWithoutResolvingAHostname() {
        var parsed = ProxyConfiguration
                .fromArguments(new String[]{
                        "https://core.test",
                        "::1",
                        certificate.toString(),
                        key.toString(),
                        ca.toString()});
        assertTrue(parsed.coreAddress() instanceof java.net.Inet6Address);
    }

    @Test
    void rejectsRelativeOrSeparateIdentityPathsAndUnspecifiedAddress() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> new ProxyConfiguration(URI.create("https://core.test"),
                InetAddress.getLoopbackAddress(), Path.of("tls.crt"), key, ca));
        assertThrows(IllegalArgumentException.class, () -> new ProxyConfiguration(URI.create("https://core.test"),
                InetAddress.getLoopbackAddress(), certificate, Path.of("/other/tls.key"), ca));
        assertThrows(IllegalArgumentException.class, () -> new ProxyConfiguration(URI.create("https://core.test"),
                InetAddress.getByName("0.0.0.0"), certificate, key, ca));
        assertThrows(IllegalArgumentException.class, () -> new ProxyConfiguration(URI.create("https://core.test"),
                InetAddress.getByName("224.0.0.1"), certificate, key, ca));
    }
}

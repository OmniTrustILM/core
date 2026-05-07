package com.czertainly.core.util.serialnumber;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.Mockito.*;

class InstanceIdResolverTest {

    static Stream<InetAddress> nonUsableLocalHostAddresses() throws UnknownHostException {
        return Stream.of(
                InetAddress.getByAddress(new byte[]{127, 0, 0, 1}),                 // loopback
                InetAddress.getByAddress(new byte[]{(byte) 169, (byte) 254, 1, 1}), // link-local
                InetAddress.getByAddress(new byte[]{(byte) 224, 0, 0, 1}),          // multicast
                InetAddress.getByAddress(new byte[]{0, 0, 0, 0})                    // any-local (wildcard)
        );
    }

    @Test
    void shouldResolveFromEnvVar() {
        // given
        String envValue = "1234";

        // when
        int id = InstanceIdResolver.resolve(envValue, () -> {
            throw new AssertionError("should not be called");
        });

        // then
        assertThat(id).isEqualTo(1234);
    }

    @Test
    void shouldRejectNegativeEnvValue() {
        // given
        String envValue = "-1";

        // then
        assertThatThrownBy(() -> InstanceIdResolver.resolve(envValue, () -> null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("-1");
    }

    @Test
    void shouldRejectEnvValueAbove65535() {
        // given
        String envValue = "65536";

        // then
        assertThatThrownBy(() -> InstanceIdResolver.resolve(envValue, () -> null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("65536");
    }

    @Test
    void shouldRejectNonNumericEnvValue() {
        // given
        String envValue = "abc";

        // then
        assertThatThrownBy(() -> InstanceIdResolver.resolve(envValue, () -> null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("abc");
    }

    @Test
    void shouldAcceptBoundaryValues() {
        // given/when/then
        assertThat(InstanceIdResolver.resolve("0", () -> null)).isZero();
        assertThat(InstanceIdResolver.resolve("65535", () -> null)).isEqualTo(65535);
    }

    @Test
    void shouldFallBackToIpWhenEnvVarIsNull() throws UnknownHostException {
        // given — IP 192.168.1.42 → lower 16 bits = (1 << 8) | 42 = 298
        InetAddress address = InetAddress.getByAddress(new byte[]{(byte) 192, (byte) 168, 1, 42});

        // when
        int id = InstanceIdResolver.resolve(null, () -> address);

        // then
        assertThat(id).isEqualTo((1 << 8) | 42);
    }

    @Test
    void shouldFallBackToIpWhenEnvVarIsBlank() throws UnknownHostException {
        // given
        InetAddress address = InetAddress.getByAddress(new byte[]{10, 0, (byte) 255, (byte) 200});

        // when
        int id = InstanceIdResolver.resolve("  ", () -> address);

        // then — lower 16 bits of 10.0.255.200 = (255 << 8) | 200 = 65480
        assertThat(id).isEqualTo((255 << 8) | 200);
    }

    @Test
    void shouldProduceValidIdFromIpFallback() throws UnknownHostException {
        // given — explicit blank env value and deterministic IP to avoid depending on process environment
        InetAddress address = InetAddress.getByAddress(new byte[]{(byte) 172, 16, 1, 7});

        // when — exercises the fallback-to-IP path
        int id = InstanceIdResolver.resolve(null, () -> address);

        // then — lower 16 bits of 172.16.1.7 = (1 << 8) | 7 = 263
        assertThat(id).isEqualTo((1 << 8) | 7);
    }

    @ParameterizedTest
    @MethodSource("nonUsableLocalHostAddresses")
    void shouldFallBackToUsableAddressWhenLocalhostReturnsNonUsableAddress(InetAddress nonUsable) throws Exception {
        // given — getLocalHost() returns a non-usable address, but a routable address exists on an interface
        InetAddress routable = InetAddress.getByAddress(new byte[]{10, 0, 1, 5});

        NetworkInterface ni = mock(NetworkInterface.class);
        when(ni.getInetAddresses()).thenReturn(Collections.enumeration(List.of(routable)));

        try (MockedStatic<InetAddress> mockedAddr = mockStatic(InetAddress.class, CALLS_REAL_METHODS);
             MockedStatic<NetworkInterface> mockedNI = mockStatic(NetworkInterface.class)) {
            mockedAddr.when(InetAddress::getLocalHost).thenReturn(nonUsable);
            mockedNI.when(NetworkInterface::getNetworkInterfaces)
                    .thenReturn(Collections.enumeration(List.of(ni)));

            // when
            var resolution = InstanceIdResolver.resolve();

            // then — ID must be derived from the routable address, not the non-usable one
            assertThat(resolution.source()).isEqualTo(InstanceIdResolver.Source.IP_ADDRESS);
            assertThat(resolution.id()).isEqualTo((1 << 8) | 5); // 10.0.1.5 → lower 16 bits
            // NetworkInterface.getByInetAddress is not stubbed, so findPrefixLength returns -1
            assertThat(resolution.prefixLength()).isEqualTo((short) -1);
        }
    }

    @Test
    void shouldFailWhenAddressSupplierThrowsAndNoEnvVar() {
        // given — supplier that simulates no usable address found
        // then
        assertThatThrownBy(() -> InstanceIdResolver.resolve(null, () -> {
            throw new IllegalStateException("No suitable network address found");
        }))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void shouldExtractCorrectLower16BitsFromIpAddress() throws UnknownHostException {
        // given — IP 10.20.30.40 → lower 16 bits = (30 << 8) | 40 = 7720
        InetAddress address = InetAddress.getByAddress(new byte[]{10, 20, 30, 40});

        // when
        int id = InstanceIdResolver.resolve(null, () -> address);

        // then
        assertThat(id).isEqualTo((30 << 8) | 40);
    }

    @Test
    void shouldXorFoldIpv6WhenUsedViaResolve() throws UnknownHostException {
        // given — IPv6 address passed through resolve's supplier path
        InetAddress ipv6 = InetAddress.getByAddress(new byte[]{
                0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0,
                0, 0, 0, 0, 0x0A, 0x0B, 0x0C, 0x0D});

        // when
        int id = InstanceIdResolver.resolve(null, () -> ipv6);

        // then
        assertThat(id).isEqualTo(0x0A0B ^ 0x0C0D);
    }

    @Nested
    class FindPrefixLengthTest {

        @Test
        void shouldReturnUnknownWhenInterfaceNotFound() throws UnknownHostException {
            // given
            InetAddress address = InetAddress.getByAddress(new byte[]{10, 0, 1, 5});

            try (MockedStatic<NetworkInterface> mockedNI = mockStatic(NetworkInterface.class)) {
                // when
                mockedNI.when(() -> NetworkInterface.getByInetAddress(any())).thenReturn(null);
                short prefixLength = InstanceIdResolver.findPrefixLength(address);

                // then
                assertThat(prefixLength).isEqualTo((short) -1);
            }
        }

        @Test
        void shouldReturnUnknownOnSocketException() throws UnknownHostException {
            // given
            InetAddress address = InetAddress.getByAddress(new byte[]{10, 0, 1, 5});

            try (MockedStatic<NetworkInterface> mockedNI = mockStatic(NetworkInterface.class)) {
                // when
                mockedNI.when(() -> NetworkInterface.getByInetAddress(any())).thenThrow(new SocketException("simulated"));
                short prefixLength = InstanceIdResolver.findPrefixLength(address);

                // then
                assertThat(prefixLength).isEqualTo((short) -1);
            }
        }
    }

    @Nested
    class IsUsableAddressTest {

        @Test
        void shouldRejectLoopbackAddress() throws UnknownHostException {
            // given
            InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});

            // when/then
            assertThat(InstanceIdResolver.isUsableAddress(loopback)).isFalse();
        }

        @Test
        void shouldRejectLinkLocalAddress() throws UnknownHostException {
            // given — 169.254.x.x is link-local
            InetAddress linkLocal = InetAddress.getByAddress(new byte[]{(byte) 169, (byte) 254, 1, 1});

            // when/then
            assertThat(InstanceIdResolver.isUsableAddress(linkLocal)).isFalse();
        }

        @Test
        void shouldRejectMulticastAddress() throws UnknownHostException {
            // given — 224.0.0.1 is multicast
            InetAddress multicast = InetAddress.getByAddress(new byte[]{(byte) 224, 0, 0, 1});

            // when/then
            assertThat(InstanceIdResolver.isUsableAddress(multicast)).isFalse();
        }

        @Test
        void shouldRejectAnyLocalAddress() throws UnknownHostException {
            // given — 0.0.0.0 is any-local (wildcard)
            InetAddress anyLocal = InetAddress.getByAddress(new byte[]{0, 0, 0, 0});

            // when/then
            assertThat(InstanceIdResolver.isUsableAddress(anyLocal)).isFalse();
        }

        @Test
        void shouldAcceptRoutableAddress() throws UnknownHostException {
            // given
            InetAddress routable = InetAddress.getByAddress(new byte[]{10, 0, 1, 1});

            // when/then
            assertThat(InstanceIdResolver.isUsableAddress(routable)).isTrue();
        }
    }

    @Nested
    class ExtractIdFromAddressTest {

        @Test
        void shouldExtractLower16BitsFromIpv4() {
            // given — IPv4 bytes [10, 20, 30, 40]
            byte[] ipv4 = {10, 20, 30, 40};

            // when
            int id = InstanceIdResolver.extractIdFromAddress(ipv4);

            // then — (30 << 8) | 40 = 7720
            assertThat(id).isEqualTo((30 << 8) | 40);
        }

        @Test
        void shouldXorFoldLastFourBytesOfIpv6() {
            // given — 16-byte IPv6 address
            byte[] ipv6 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A, 0x0B, 0x0C, 0x0D};

            // when
            int id = InstanceIdResolver.extractIdFromAddress(ipv6);

            // then — hi = (0x0A << 8) | 0x0B = 0x0A0B, lo = (0x0C << 8) | 0x0D = 0x0C0D
            //         xor = 0x0A0B ^ 0x0C0D = 0x0606
            assertThat(id).isEqualTo(0x0A0B ^ 0x0C0D);
        }

        @Test
        void shouldProduceValueInValidRange() {
            // given — worst case: all 0xFF bytes
            byte[] ipv6 = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

            // when
            int id = InstanceIdResolver.extractIdFromAddress(ipv6);

            // then — 0xFFFF ^ 0xFFFF = 0x0000
            assertThat(id).isBetween(0, 65535);
        }
    }

}
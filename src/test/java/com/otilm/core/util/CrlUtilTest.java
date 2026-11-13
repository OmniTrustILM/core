package com.otilm.core.util;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class CrlUtilTest {

    @ParameterizedTest
    @MethodSource("malformedCrlDistributionPoints")
    void throwsIoException_whenExtensionValueIsMalformed(byte[] malformedCrlDistributionPoints) throws Exception {
        // given
        byte[] extensionValue = new DEROctetString(malformedCrlDistributionPoints).getEncoded();

        // when
        ThrowingCallable readCrlUrls = () -> CrlUtil.getCDPFromCertificate(extensionValue, "freshestCRL");

        // then
        assertThatThrownBy(readCrlUrls)
                .isInstanceOfSatisfying(IOException.class, exception -> assertThat(exception.getCause()).isNotNull())
                .hasMessage("The freshestCRL extension is malformed");
    }

    @Test
    void isNotCurrent_whenNextUpdateIsMissing() {
        // given — a CRL without nextUpdate

        // when
        boolean current = CrlUtil.isCurrent(null);

        // then
        assertThat(current).isFalse();
    }

    @ParameterizedTest
    @MethodSource("nextUpdatesAndTheirCurrency")
    void judgesCurrency_whenNextUpdateIsWithinTheClockSkew(Duration offsetFromNow, boolean expectedCurrent) {
        // given
        Date nextUpdate = Date.from(Instant.now().plus(offsetFromNow));

        // when
        boolean current = CrlUtil.isCurrent(nextUpdate);

        // then
        assertThat(current).isEqualTo(expectedCurrent);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> nextUpdatesAndTheirCurrency() {
        return Stream
                .of(arguments(named("4 minutes in the past, within the skew", Duration.ofMinutes(-4)), true),
                        arguments(named("6 minutes in the past, beyond the skew", Duration.ofMinutes(-6)), false),
                        arguments(named("in the future", Duration.ofHours(1)), true));
    }

    private static Stream<Named<byte[]>> malformedCrlDistributionPoints() {
        return Stream
                .of(named("no value", new byte[0]),
                        named("an empty list of distribution points", HexFormat.of().parseHex("3000")),
                        named("a distribution point name tagged implicitly", HexFormat.of().parseHex("300430028000")),
                        named("an EDI party name without its party name",
                                HexFormat.of().parseHex("300d300ba009a007a505a0030c0141")),
                        named("a length beyond the end of the value", HexFormat.of().parseHex("30053003")));
    }
}

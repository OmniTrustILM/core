package com.otilm.core.util;

import java.io.IOException;
import java.util.HexFormat;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

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
                .isInstanceOf(IOException.class)
                .hasMessageContaining("The freshestCRL extension is malformed");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

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

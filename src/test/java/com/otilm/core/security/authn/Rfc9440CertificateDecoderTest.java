package com.otilm.core.security.authn;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static com.otilm.core.security.authn.ForwardedCertificateFixtures.ISSUER_DER;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_DER;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.THUMBPRINT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Rfc9440CertificateDecoderTest {
    @Test
    void acceptsCompleteByteItemsAndLegalParameters() throws Exception {
        var value = ForwardedClientCertificateParser
                .parse(" :" + LEAF_DER.replace("=", "")
                        + ":;flag;p=\"comma,semi;equals=\\\"\";p=1;date=@1;display=%\"caf%c3%a9\" ");
        assertThat(value.content()).isEqualTo(LEAF_DER);
        assertThat(value.thumbprint()).isEqualTo(THUMBPRINT);
    }

    @Test
    void combinesCompanionLinesAndDeduplicatesAfterValidation() throws Exception {
        var request = request(":" + LEAF_DER + ":");
        request.addHeader("Client-Cert-Chain", ":" + ISSUER_DER + ":;flag");
        request.addHeader("Client-Cert-Chain", ":" + ISSUER_DER + ":");
        assertThat(ForwardedClientCertificateParser.parse(request, "Custom-Cert").chain()).containsExactly(ISSUER_DER);
    }

    @Test
    void permitsAbsentAndEmptyOptionalList() throws Exception {
        var request = request(":" + LEAF_DER + ":");
        assertThat(ForwardedClientCertificateParser.parse(request, "Custom-Cert").chain()).isEmpty();
        request.addHeader("Client-Cert-Chain", "");
        assertThat(ForwardedClientCertificateParser.parse(request, "Custom-Cert").chain()).isEmpty();
    }

    @Test
    void rejectsInvalidLeafAndCompanionSyntaxWithoutContentInErrors() {
        for (String leaf : List
                .of("::", ":" + LEAF_DER + ":, :AQI=:", ":AQ_=: sentinel", ":" + LEAF_DER + ":;p=\"sentinel",
                        ":" + LEAF_DER + ":sentinel")) {
            assertSafeFailure(() -> ForwardedClientCertificateParser.parse(leaf));
        }
        for (String chain : List
                .of("token", "(:" + ISSUER_DER + ":)", "::", ":" + ISSUER_DER + ":,", ":" + LEAF_DER + ":", ":AQI=:",
                        ":" + ISSUER_DER + ":;x=\"sentinel")) {
            var request = request(":" + LEAF_DER + ":");
            request.addHeader("Client-Cert-Chain", chain);
            assertSafeFailure(() -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"));
        }
    }

    @Test
    void rejectsRepeatedPhysicalLeafFields() {
        var request = request(":" + LEAF_DER + ":");
        request.addHeader("Custom-Cert", ":" + LEAF_DER + ":");
        assertSafeFailure(() -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"));
    }

    @Test
    void countsSourceCertificatesBeforeDeduplication() throws Exception {
        var request = request(":" + LEAF_DER + ":");
        request
                .addHeader("Client-Cert-Chain",
                        String.join(",", java.util.Collections.nCopies(15, ":" + ISSUER_DER + ":")));
        assertThat(ForwardedClientCertificateParser.parse(request, "Custom-Cert").chain()).containsExactly(ISSUER_DER);
        request.addHeader("Client-Cert-Chain", ":" + ISSUER_DER + ":");
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"))).hasMessageContaining("limit");
    }

    @Test
    void boundsCompanionOccurrencesAndCombinedHeaderSize() {
        var request = request(":" + LEAF_DER + ":");
        for (int i = 0; i < 17; i++) {
            request.addHeader("Client-Cert-Chain", "");
        }
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"))).hasMessageContaining("limit");
        var oversized = request(":" + LEAF_DER + ":");
        oversized.addHeader("Client-Cert-Chain", " ".repeat(262144));
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(oversized, "Custom-Cert"))).hasMessageContaining("limit");
        String oversizedDer = ":" + java.util.Base64.getEncoder().encodeToString(new byte[65537]) + ":";
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(oversizedDer))).hasMessageContaining("limit");
    }

    @Test
    void rejectsRepeatedParametersBeforeTheParserSizesABufferPerValue() {
        String leaf = ":" + LEAF_DER + ":" + ";p=x".repeat(15000);
        List<String> noCompanions = List.of();
        long allocated = allocatedBytes(() -> assertThat(assertThrows(IllegalArgumentException.class,
                () -> Rfc9440CertificateDecoder.decode(leaf, noCompanions))).hasMessageContaining("limit"));
        assertThat(allocated).isLessThan(16L << 20);
    }

    @Test
    void rejectsInnerListCompanionsBeforeParsingTheirItems() {
        String leaf = ":" + LEAF_DER + ":";
        var innerList = List.of("(" + "a ".repeat(30000) + ")");
        long allocated = allocatedBytes(
                () -> assertSafeFailure(() -> Rfc9440CertificateDecoder.decode(leaf, innerList)));
        assertThat(allocated).isLessThan(16L << 20);
    }

    @Test
    void countsParametersAfterADisplayStringEndingInABackslash() {
        String leaf = ":" + LEAF_DER + ":" + ";d=%\"\\\"" + ";p=x".repeat(15000);
        List<String> noCompanions = List.of();
        long allocated = allocatedBytes(() -> assertThat(assertThrows(IllegalArgumentException.class,
                () -> Rfc9440CertificateDecoder.decode(leaf, noCompanions))).hasMessageContaining("limit"));
        assertThat(allocated).isLessThan(16L << 20);
    }

    @Test
    void findsAnInnerListAfterADisplayStringEndingInABackslash() {
        String leaf = ":" + LEAF_DER + ":";
        var chain = List.of(":" + ISSUER_DER + ":" + ";d=%\"\\\", (" + "a ".repeat(30000) + ")");
        long allocated = allocatedBytes(() -> assertSafeFailure(() -> Rfc9440CertificateDecoder.decode(leaf, chain)));
        assertThat(allocated).isLessThan(16L << 20);
    }

    @Test
    void countsParameterOccurrencesAcrossLeafAndCompanions() {
        int leafParameters = ForwardedCertificateLimits.PARAMETERS / 2;
        String leaf = ":" + LEAF_DER + ":" + ";p".repeat(leafParameters);
        var chain = List
                .of(":" + ISSUER_DER + ":" + ";p".repeat(ForwardedCertificateLimits.PARAMETERS - leafParameters));
        assertThat(Rfc9440CertificateDecoder.decode(leaf, chain)).hasSize(2);
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> Rfc9440CertificateDecoder.decode(leaf + ";p", chain))).hasMessageContaining("limit");
    }

    @Test
    void ignoresDelimitersInsideQuotedParameterValues() {
        String quoted = ";p=\"" + "(;".repeat(ForwardedCertificateLimits.PARAMETERS + 1) + "\\\"\"";
        assertThat(Rfc9440CertificateDecoder.decode(":" + LEAF_DER + ":" + quoted, List.of())).hasSize(1);
    }

    private static long allocatedBytes(Runnable action) {
        var threads = (com.sun.management.ThreadMXBean) java.lang.management.ManagementFactory.getThreadMXBean();
        long before = threads.getCurrentThreadAllocatedBytes();
        action.run();
        return threads.getCurrentThreadAllocatedBytes() - before;
    }

    private static MockHttpServletRequest request(String leaf) {
        var request = new MockHttpServletRequest();
        request.addHeader("Custom-Cert", leaf);
        return request;
    }

    private static void assertSafeFailure(org.junit.jupiter.api.function.Executable action) {
        var failure = assertThrows(IllegalArgumentException.class, action);
        assertThat(failure.getMessage()).doesNotContain("sentinel", LEAF_DER, ISSUER_DER);
        assertThat(failure.getCause()).isNull();
    }

    @Test
    void rejectsPinnedHttpwgBinaryVectorsAsNonCertificateMaterial() throws Exception {
        try (var input = getClass().getResourceAsStream("/security/authn/httpwg/binary.json")) {
            var vectors = new com.fasterxml.jackson.databind.ObjectMapper().readTree(input);
            List<String> noCompanions = List.of();
            for (var vector : vectors) {
                String raw = vector.get("raw").get(0).asText();
                var failure = assertThrows(IllegalArgumentException.class,
                        () -> Rfc9440CertificateDecoder.decode(raw, noCompanions), vector.get("name").asText());
                assertThat(failure.getCause()).isNull();
                if (!vector.path("must_fail").asBoolean()) {
                    assertThat(failure.getMessage()).isEqualTo("Invalid X.509 certificate");
                }
            }
        }
    }

    @Test
    void countsJoiningSeparatorsEvenWhenLastCompanionIsEmpty() {
        String leaf = ":" + LEAF_DER + ":";
        String chain = ":" + ISSUER_DER + ":";
        String paddedChain = chain + " ".repeat(262144 - leaf.length() - chain.length());
        assertThat(Rfc9440CertificateDecoder.decode(leaf, List.of(paddedChain))).hasSize(2);
        var oversizedCompanions = List.of(paddedChain, "");
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> Rfc9440CertificateDecoder.decode(leaf, oversizedCompanions))).hasMessageContaining("limit");
        var request = request(leaf);
        request.addHeader("Client-Cert-Chain", paddedChain);
        request.addHeader("Client-Cert-Chain", "");
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"))).hasMessageContaining("limit");
    }
}

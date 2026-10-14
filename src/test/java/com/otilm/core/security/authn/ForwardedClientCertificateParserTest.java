package com.otilm.core.security.authn;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ForwardedClientCertificateParserTest {
    @ParameterizedTest
    @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#supportedHeaders")
    void returnsSameLeafIdentityForSupportedForms(String header, String content, String thumbprint) throws Exception {
        var certificate = ForwardedClientCertificateParser.parse(header);
        assertThat(certificate.content()).isEqualTo(content);
        assertThat(certificate.thumbprint()).isEqualTo(thumbprint);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t\r\n"})
    @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#malformedHeaders")
    void rejectsMissingOrMalformedCertificates(String header) {
        assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(header));
    }

    @Test
    void preservesLiteralPlusAlongsidePercentEscapes() throws Exception {
        assertThat(ForwardedClientCertificateParser
                .parse(ForwardedCertificateFixtures.LEAF_DER.replace("=", "%3D"))
                .content()).isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
    }

    @Test
    void acceptsWhitespaceAroundNativeChainMembers() throws Exception {
        assertThat(ForwardedClientCertificateParser
                .parse(" " + ForwardedCertificateFixtures.LEAF_DER + ", " + ForwardedCertificateFixtures.ISSUER_DER
                        + " ")
                .thumbprint()).isEqualTo(ForwardedCertificateFixtures.THUMBPRINT);
    }

    @Test
    void recognizesNativeRepresentationsWithoutFormatSetting() throws Exception {
        for (String value : java.util.List
                .of(":" + ForwardedCertificateFixtures.LEAF_DER + ":",
                        "Cert=\"" + java.net.URLEncoder
                                .encode(ForwardedCertificateFixtures.LEAF_PEM, java.nio.charset.StandardCharsets.UTF_8)
                                .replace("+", "%20") + "\"",
                        ForwardedCertificateFixtures.LEAF_PEM + ForwardedCertificateFixtures.LEAF_PEM)) {
            var parsed = ForwardedClientCertificateParser.parse(value);
            assertThat(parsed.content()).isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
            assertThat(parsed.thumbprint()).isEqualTo(ForwardedCertificateFixtures.THUMBPRINT);
        }
    }

    @Test
    void doesNotClassifyPaddedCertificateSequenceAsXfcc() throws Exception {
        for (String value : java.util.List
                .of(ForwardedCertificateFixtures.LEAF_DER,
                        ForwardedCertificateFixtures.LEAF_DER + "," + ForwardedCertificateFixtures.ISSUER_DER,
                        ForwardedCertificateFixtures.LEAF_DER.replace("=", "%3D") + "%2C"
                                + ForwardedCertificateFixtures.ISSUER_DER)) {
            assertThat(ForwardedClientCertificateParser.parse(value).content())
                    .isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
        }
    }

    @Test
    void preservesEncodedPaddingAndLiteralPlus() throws Exception {
        assertThat(ForwardedClientCertificateParser
                .parse(ForwardedCertificateFixtures.LEAF_DER.replace("=", "%3D"))
                .thumbprint()).isEqualTo(ForwardedCertificateFixtures.THUMBPRINT);
    }

    @Test
    void rejectsMalformedRecognizedEnvelopeWithoutFallback() {
        for (String value : java.util.List
                .of(":" + ForwardedCertificateFixtures.LEAF_DER + ":junk",
                        "Cert=\"" + ForwardedCertificateFixtures.LEAF_DER + "\"", "Unknown=x;Cert=", "::")) {
            assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(value));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"explicit-secp256r1.pem", "explicit-brainpoolP256r1.pem"})
    void preservesExplicitEcParameters(String fixture) throws Exception {
        String pem = ForwardedCertificateFixtures.read(fixture);
        String der = ForwardedCertificateFixtures.content(pem);
        assertThat(ForwardedClientCertificateParser.parse(":" + der + ":").content()).isEqualTo(der);
    }

    @Test
    void preservesFirstPhysicalLegacyFieldAndIgnoresUnselectedHeaders() throws Exception {
        var request = new org.springframework.mock.web.MockHttpServletRequest();
        request.addHeader("Custom-Cert", ForwardedCertificateFixtures.LEAF_DER);
        request.addHeader("Custom-Cert", "invalid");
        request.addHeader("Client-Cert-Chain", "invalid");
        request.addHeader("ssl-client-cert", "invalid");
        var parsed = ForwardedClientCertificateParser.parse(request, "Custom-Cert");
        assertThat(parsed.content()).isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
        assertThat(parsed.chain()).isEmpty();
    }

    @Test
    void rejectsRepeatedIdentityFieldsWhenAnyOccurrenceUsesRfcOrXfcc() {
        String leaf = ForwardedCertificateFixtures.LEAF_DER;
        String xfcc = "Cert=\"" + java.net.URLEncoder
                .encode(ForwardedCertificateFixtures.LEAF_PEM, java.nio.charset.StandardCharsets.UTF_8)
                .replace("+", "%20") + "\"";
        for (String nativeValue : java.util.List.of(":" + leaf + ":", xfcc, ":invalid:", "Subject=\"ignored\"")) {
            for (java.util.List<String> headers : java.util.List
                    .of(java.util.List.of(leaf, nativeValue), java.util.List.of(nativeValue, leaf),
                            java.util.List.of(leaf, "invalid", " " + nativeValue + " "))) {
                var request = new org.springframework.mock.web.MockHttpServletRequest();
                headers.forEach(header -> request.addHeader("Custom-Cert", header));
                assertThat(assertThrows(IllegalArgumentException.class,
                        () -> ForwardedClientCertificateParser.parse(request, "Custom-Cert")))
                        .hasMessageContaining("Repeated");
            }
        }
    }

    @Test
    void ignoresEveryUnselectedLegacyOccurrenceWithoutValidatingIt() throws Exception {
        var request = new org.springframework.mock.web.MockHttpServletRequest();
        request.addHeader("Custom-Cert", ForwardedCertificateFixtures.LEAF_DER);
        for (String ignored : java.util.List
                .of("", " ", "\0", "\0 \t", "\001\002\037", "!not-base64!", "%%%", "A".repeat(262145))) {
            request.addHeader("Custom-Cert", ignored);
        }
        request.addHeader("Client-Cert-Chain", ":invalid:");
        var parsed = ForwardedClientCertificateParser.parse(request, "Custom-Cert");
        assertThat(parsed.content()).isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
        assertThat(parsed.thumbprint()).isEqualTo(ForwardedCertificateFixtures.THUMBPRINT);
        assertThat(parsed.chain()).isEmpty();
    }

    @Test
    void validatesEveryLegacyMemberAndKeepsOrderedCandidates() throws Exception {
        String leaf = ForwardedCertificateFixtures.LEAF_DER;
        String issuer = ForwardedCertificateFixtures.ISSUER_DER;
        String explicit = ForwardedCertificateFixtures
                .content(ForwardedCertificateFixtures.read("explicit-secp256r1.pem"));
        var parsed = ForwardedClientCertificateParser
                .parse(leaf + "," + issuer + "," + leaf + "," + explicit + "," + issuer);
        assertThat(parsed.chain()).containsExactly(issuer, explicit);
        var candidates = parsed.chain();
        assertThrows(UnsupportedOperationException.class, () -> candidates.add(leaf));
        assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(leaf + "," + issuer + ",!"));
        assertThat(ForwardedClientCertificateParser
                .parse(String.join(",", java.util.Collections.nCopies(16, leaf)))
                .chain()).isEmpty();
        String tooManyCertificates = String.join(",", java.util.Collections.nCopies(17, leaf));
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(tooManyCertificates))).hasMessageContaining("limit");
    }

    @Test
    void acceptsMixedAndConsecutivePemWithBodyWhitespace() throws Exception {
        String pem = ForwardedCertificateFixtures.LEAF_PEM.replace("\n", " ");
        for (String value : java.util.List
                .of(pem, pem + ForwardedCertificateFixtures.read("issuer.pem"),
                        pem + "," + ForwardedCertificateFixtures.ISSUER_DER, ForwardedCertificateFixtures.LEAF_DER + ","
                                + ForwardedCertificateFixtures.read("issuer.pem"))) {
            assertThat(ForwardedClientCertificateParser.parse(value).content())
                    .isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
        }
    }

    @Test
    void boundsTheCompleteSelectedHeaderBeforeTrimming() throws Exception {
        String leaf = ":" + ForwardedCertificateFixtures.LEAF_DER + ":";
        String padded = " ".repeat(262144 - leaf.length()) + leaf;
        assertThat(ForwardedClientCertificateParser.parse(padded).content())
                .isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(" " + padded))).hasMessageContaining("limit");
        var request = new org.springframework.mock.web.MockHttpServletRequest();
        request.addHeader("Custom-Cert", padded);
        request.addHeader("Client-Cert-Chain", " ");
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(request, "Custom-Cert"))).hasMessageContaining("limit");
    }

    @Test
    void acceptsOnePaddingMemberAndExactDerSizeBoundary() throws Exception {
        String singlePadding = java.util.Base64
                .getEncoder()
                .encodeToString(ForwardedCertificateFixtures.sizedCertificate(740));
        assertThat(singlePadding).endsWith("=").doesNotEndWith("==");
        for (String header : java.util.List
                .of(singlePadding + "," + ForwardedCertificateFixtures.LEAF_DER,
                        singlePadding.replace("=", "%3D") + "%2C" + ForwardedCertificateFixtures.LEAF_DER)) {
            assertThat(ForwardedClientCertificateParser.parse(header).content()).isEqualTo(singlePadding);
        }
        String maximum = java.util.Base64
                .getEncoder()
                .encodeToString(ForwardedCertificateFixtures.sizedCertificate(65536));
        for (String header : java.util.List.of(maximum, ":" + maximum + ":")) {
            assertThat(ForwardedClientCertificateParser.parse(header).content()).isEqualTo(maximum);
        }
        String tooLarge = java.util.Base64
                .getEncoder()
                .encodeToString(ForwardedCertificateFixtures.sizedCertificate(65537));
        for (String header : java.util.List.of(tooLarge, ":" + tooLarge + ":")) {
            assertThat(
                    assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(header)))
                    .hasMessageContaining("limit");
        }
    }

    @Test
    void preservesLegacyWrappedPemLeafAndCompleteBundle() throws Exception {
        String leaf = ForwardedCertificateFixtures.LEAF_PEM;
        String bundle = leaf + ForwardedCertificateFixtures.read("issuer.pem") + leaf;
        for (String material : java.util.List.of(leaf, bundle, " \t\r\n" + bundle)) {
            String wrapped = ForwardedCertificateFixtures.wrapPem(material);
            for (String header : java.util.List
                    .of(wrapped, java.net.URLEncoder.encode(wrapped, java.nio.charset.StandardCharsets.UTF_8))) {
                var parsed = ForwardedClientCertificateParser.parse(header);
                assertThat(parsed.content()).isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
                assertThat(parsed.thumbprint()).isEqualTo(ForwardedCertificateFixtures.THUMBPRINT);
                assertThat(parsed.chain())
                        .containsExactlyElementsOf(material.equals(leaf)
                                ? java.util.List.of()
                                : java.util.List.of(ForwardedCertificateFixtures.ISSUER_DER));
            }
        }
    }

    @Test
    void boundsActualWrappedPemCertificatesBeforeDeduplication() throws Exception {
        String leaf = ForwardedCertificateFixtures.LEAF_PEM;
        String issuer = ForwardedCertificateFixtures.read("issuer.pem");
        String bundle = leaf + issuer.repeat(15);
        assertThat(ForwardedClientCertificateParser.parse(ForwardedCertificateFixtures.wrapPem(bundle)).chain())
                .containsExactly(ForwardedCertificateFixtures.ISSUER_DER);
        for (String material : java.util.List
                .of(ForwardedCertificateFixtures.wrapPem(bundle + issuer),
                        ForwardedCertificateFixtures.LEAF_DER + "," + ForwardedCertificateFixtures.wrapPem(bundle),
                        ForwardedCertificateFixtures.wrapPem(bundle) + "," + ForwardedCertificateFixtures.ISSUER_DER)) {
            assertThat(assertThrows(IllegalArgumentException.class,
                    () -> ForwardedClientCertificateParser.parse(material))).hasMessageContaining("limit");
        }
        String maximum = ForwardedCertificateFixtures.wrapPem(leaf + " ".repeat(196608 - leaf.length()));
        assertThat(maximum).hasSize(262144);
        assertThat(ForwardedClientCertificateParser.parse(maximum).content())
                .isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(maximum + "A"))).hasMessageContaining("limit");
    }

    @Test
    void rejectsWrappedPemTrailingJunkAndRecursiveDecoding() {
        String leaf = ForwardedCertificateFixtures.LEAF_PEM;
        String wrapped = ForwardedCertificateFixtures.wrapPem(leaf);
        for (String material : java.util.List
                .of(ForwardedCertificateFixtures.wrapPem(leaf + "junk"),
                        ForwardedCertificateFixtures
                                .wrapPem(leaf + "-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----"),
                        ForwardedCertificateFixtures.wrapPem(wrapped),
                        java.net.URLEncoder
                                .encode(java.net.URLEncoder.encode(leaf, java.nio.charset.StandardCharsets.UTF_8),
                                        java.nio.charset.StandardCharsets.UTF_8),
                        ForwardedCertificateFixtures
                                .wrapPem("-----BEGIN CERTIFICATE-----\n" + wrapped + "\n-----END CERTIFICATE-----\n"),
                        ForwardedCertificateFixtures
                                .wrapPem(java.net.URLEncoder.encode(leaf, java.nio.charset.StandardCharsets.UTF_8)),
                        java.net.URLEncoder
                                .encode(java.net.URLEncoder.encode(wrapped, java.nio.charset.StandardCharsets.UTF_8),
                                        java.nio.charset.StandardCharsets.UTF_8))) {
            assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(material));
        }
    }

    @Test
    void preservesNativeDerAndPemContractsWhenLegacyPemIsWrapped() {
        String wrapped = ForwardedCertificateFixtures.wrapPem(ForwardedCertificateFixtures.LEAF_PEM);
        assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(":" + wrapped + ":"));
        assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse("Cert=\"" + wrapped + "\""));
        String invalidChain = "Cert=\"" + java.net.URLEncoder
                .encode(ForwardedCertificateFixtures.LEAF_PEM, java.nio.charset.StandardCharsets.UTF_8)
                .replace("+", "%20") + "\";Chain=\"" + wrapped + "\"";
        assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(invalidChain));
    }

    @Test
    void appliesDerLimitToTheInnerCertificateOfWrappedPem() throws Exception {
        for (int size : new int[]{65536, 65537}) {
            String der = java.util.Base64
                    .getEncoder()
                    .encodeToString(ForwardedCertificateFixtures.sizedCertificate(size));
            String wrapped = ForwardedCertificateFixtures
                    .wrapPem("-----BEGIN CERTIFICATE-----\n" + der + "\n-----END CERTIFICATE-----\n");
            assertThat(wrapped.length()).isLessThan(262144);
            if (size == 65536) {
                assertThat(ForwardedClientCertificateParser.parse(wrapped).content()).isEqualTo(der);
            } else {
                assertThat(assertThrows(IllegalArgumentException.class,
                        () -> ForwardedClientCertificateParser.parse(wrapped))).hasMessageContaining("limit");
            }
        }
    }

    @ParameterizedTest
    @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#noncanonicalSingletonHeaders")
    void legacySingletonPreservesCompleteNoncanonicalEncoding(String header, String content, String thumbprint)
            throws Exception {
        var parsed = ForwardedClientCertificateParser.parse(header);
        assertThat(parsed.content()).isEqualTo(content);
        assertThat(parsed.thumbprint()).isEqualTo(thumbprint);
        assertThat(parsed.chain()).isEmpty();
    }

    @Test
    void newAssertionsAndLegacyChainsStillRequireCanonicalDer() throws Exception {
        var noncanonical = ForwardedCertificateFixtures
                .noncanonicalSingletonHeaders()
                .findFirst()
                .orElseThrow()
                .get()[1]
                .toString();
        String pem = "-----BEGIN CERTIFICATE-----\n" + noncanonical + "\n-----END CERTIFICATE-----\n";
        for (String header : java.util.List
                .of(noncanonical + "," + ForwardedCertificateFixtures.ISSUER_DER,
                        ForwardedCertificateFixtures.LEAF_DER + "," + noncanonical, ":" + noncanonical + ":",
                        "Cert=\"" + java.net.URLEncoder
                                .encode(pem, java.nio.charset.StandardCharsets.UTF_8)
                                .replace("+", "%20") + "\"")) {
            assertThat(assertThrows(ForwardedClientCertificateParser.InvalidCertificateHeaderException.class,
                    () -> ForwardedClientCertificateParser.parse(header)))
                    .hasMessage("Invalid certificate DER encoding");
        }
    }

    @ParameterizedTest
    @MethodSource("com.otilm.core.security.authn.ForwardedCertificateFixtures#populatedPkcs7Headers")
    void rejectsPopulatedPkcs7InsteadOfUsingItsFirstCertificate(String header) {
        assertThat(assertThrows(ForwardedClientCertificateParser.InvalidCertificateHeaderException.class,
                () -> ForwardedClientCertificateParser.parse(header))).hasMessage("Invalid X.509 certificate");
    }

    @Test
    void rejectsMalformedNestedCertificateWithControlledReason() {
        assertThat(assertThrows(ForwardedClientCertificateParser.InvalidCertificateHeaderException.class,
                () -> ForwardedClientCertificateParser
                        .parse(ForwardedCertificateFixtures.MALFORMED_NESTED_CERTIFICATE)))
                .hasMessage("Invalid X.509 certificate");
    }

}

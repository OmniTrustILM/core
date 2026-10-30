package com.otilm.core.security.authn;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static com.otilm.core.security.authn.ForwardedCertificateFixtures.ISSUER_DER;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_DER;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.LEAF_PEM;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.THUMBPRINT;
import static com.otilm.core.security.authn.ForwardedCertificateFixtures.read;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XfccCertificateDecoderTest {
    private static final String ENVOY_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDkDCCAnigAwIBAgIUFVxwBtp5SJ2m4d7S3+w7uqewFPYwDQYJKoZIhvcNAQEL
            BQAwRDETMBEGA1UECgwKQWNtZSwgSW5jLjEdMBsGA1UECwwUUmVzZWFyY2grRGV2
            ZWxvcG1lbnQxDjAMBgNVBAMMBUpvc8OpMB4XDTI2MTAxNDA1MzAzOVoXDTI2MTAx
            NTA1MzAzOVowRDETMBEGA1UECgwKQWNtZSwgSW5jLjEdMBsGA1UECwwUUmVzZWFy
            Y2grRGV2ZWxvcG1lbnQxDjAMBgNVBAMMBUpvc8OpMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEAkqAJotUI2trDTINp5XW1am6Y/yWUQ+knwg13N/gCdGbC
            VEQeyRrRGmu2idOlouq3tj8cNJpvOPTP8fggJYZumTGpUv1IA4IGBVikSbIUOtJ5
            QL9NKZ06a7WoE47+eZ2wMr3ePJHZyJ64L1j0cB/d96Byvh49yUgiHDVAVtnMnazQ
            4wREi/gUmAh/YfAX+wALPT7vcoNpA1IxuxAXN3poh7X4j7aNRHsicvrGwBxLaU2f
            ZBlYfTBVj4XF/3hv9gTHWemQT+flZd0ku1NRSCP/Vyby+2U5/SMUoOL9Mwi1IwFf
            ldPsqV378JEpod7m49QIsNyo89JfVshNcSJM7S9IiwIDAQABo3oweDAdBgNVHQ4E
            FgQUWqIMLeQXiUE2YCaHPuFqqbupSJAwHwYDVR0jBBgwFoAUWqIMLeQXiUE2YCaH
            PuFqqbupSJAwDwYDVR0TAQH/BAUwAwEB/zAlBgNVHREEHjAchhpodHRwczovL3gu
            ZXhhbXBsZS8/YT1iJmM9ZDANBgkqhkiG9w0BAQsFAAOCAQEAcusDRR8HanSZhCvf
            Meb9gLvhycz9wvsk1r1d8Qh5IhUAiyVOH5X5LWgNkp5RSR/MMp/5g4jeq1wp5Yfl
            2Mt6xrDofdg6USbDW+9xWKzBS7gOfiu3EirdSeuOzATbrwXYIPcxDJ/XrMVYFME0
            7/tIiQc++1IZAfFR4nXTJ8y6SVs/fay3AwenDc6K4hr4aN1jXtixk6bxkoF6zxwG
            NQe8r8RKKPJDV9FwUL8valcOXbKzxsYbhPcDSR1/SkaOqE0b5r9Ulmkz+PoNIJXT
            rNKSLBBE6dLNbhiEil2YJwNTfPw3rxHdeWrMOYzmB1meZtQj/yQgq3UQEhArEa82
            uZ5u0w==
            -----END CERTIFICATE-----
            """;
    private static final String ENVOY_SUBJECT = "CN=Jos\\C3\\A9,OU=Research\\+Development,O=Acme\\, Inc.";
    private static final String ENVOY_URI = "https://x.example/?a=b&c=d";
    private static final String ENVOY_THUMBPRINT = "cb7752b64a01afa1d495a57abecc8671b6f7ab8cfdf8bbfba77973c90837d370";

    @Test
    void acceptsNativeEnvoyRfc2253SubjectEscapes() throws Exception {
        var parsed = ForwardedClientCertificateParser
                .parse("Hash=" + ENVOY_THUMBPRINT + ";Cert=" + quoted(ENVOY_PEM) + ";Subject=\"" + ENVOY_SUBJECT
                        + "\";URI=spiffe://client");
        assertThat(parsed.content()).isEqualTo(ForwardedCertificateFixtures.content(ENVOY_PEM));
        assertThat(parsed.thumbprint()).isEqualTo(ENVOY_THUMBPRINT);
        assertThat(parsed.chain()).isEmpty();
    }

    @Test
    void acceptsNativeEnvoyUnquotedUriQueryAssignments() throws Exception {
        var parsed = ForwardedClientCertificateParser
                .parse("Hash=" + ENVOY_THUMBPRINT + ";Cert=" + quoted(ENVOY_PEM) + ";URI=" + ENVOY_URI
                        + ";DNS=x.example");
        assertThat(parsed.content()).isEqualTo(ForwardedCertificateFixtures.content(ENVOY_PEM));
        assertThat(parsed.thumbprint()).isEqualTo(ENVOY_THUMBPRINT);
        assertThat(parsed.chain()).isEmpty();
    }

    @Test
    void acceptsHttpQuotedPairsAndQuotedWhitespace() throws Exception {
        for (int character = 0; character <= 126; character++) {
            if (character == 9 || character >= 32 && character != 127) {
                var parsed = ForwardedClientCertificateParser
                        .parse(cert() + ";Subject=\"before\\" + (char) character + "after\"");
                assertThat(parsed.content()).isEqualTo(LEAF_DER);
            }
        }
        assertThat(ForwardedClientCertificateParser.parse(cert() + ";Subject=\"tab\tspace \"").content())
                .isEqualTo(LEAF_DER);
    }

    @Test
    void rejectsControlsAndDanglingEscapesInQuotedMetadata() {
        for (int character = 0; character <= 127; character++) {
            if (character < 32 && character != 9 || character == 127) {
                for (String prefix : List.of("", "\\")) {
                    String header = cert() + ";Subject=\"before" + prefix + (char) character + "after\"";
                    assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(header));
                }
            }
        }
        String danglingEscape = cert() + ";Subject=\"dangling\\";
        assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(danglingEscape));
    }

    @Test
    void acceptsCaseInsensitiveKeysAndQuotedMetadataDelimiters() throws Exception {
        var parsed = ForwardedClientCertificateParser
                .parse("Unknown=ok;Subject=\"comma,semi;equals=\\\"quoted\\\"\";" + "URI=one;URI=two;DNS=a;DNS=b;cErT="
                        + quoted(LEAF_PEM));
        assertThat(parsed.content()).isEqualTo(LEAF_DER);
        assertThat(parsed.thumbprint()).isEqualTo(THUMBPRINT);
        assertThat(parsed.chain()).isEmpty();
    }

    @Test
    void verifiesAndRemovesDefinedFirstChainLeaf() throws Exception {
        var parsed = ForwardedClientCertificateParser
                .parse(cert() + ";Chain=" + quoted(LEAF_PEM + read("issuer.pem") + read("issuer.pem")));
        assertThat(parsed.chain()).containsExactly(ISSUER_DER);
    }

    @Test
    void rejectsAmbiguousOrIncompleteObservations() {
        for (String value : List
                .of("Hash=abc", "Subject=\"sentinel\"", "Chain=" + quoted(LEAF_PEM), cert() + "," + cert(),
                        cert() + ";cErT=" + quoted(LEAF_PEM),
                        cert() + ";Chain=" + quoted(LEAF_PEM) + ";chain=" + quoted(LEAF_PEM), cert() + ";",
                        cert() + ";;URI=a", "Cert=\"sentinel", cert() + ";Unknown=\"a\nb\"", cert() + ";Unknown=a b",
                        cert() + ";Unknown=\"a\"suffix", "Cert=", "Cert=\"\"", cert() + ";Chain=",
                        cert() + ";Chain=\"\"", "Cert=" + LEAF_DER, cert() + ";Chain=" + quoted(read("issuer.pem")),
                        cert() + ";Chain=" + quoted(LEAF_PEM + read("issuer.pem") + LEAF_PEM))) {
            var failure = assertThrows(IllegalArgumentException.class,
                    () -> ForwardedClientCertificateParser.parse(value));
            assertThat(failure.getMessage()).doesNotContain("sentinel", LEAF_DER, ISSUER_DER);
            assertThat(failure.getCause()).isNull();
        }
    }

    @Test
    void doesNotDecodeTheOuterGrammarOrDecodeTransportTwice() {
        for (String value : List
                .of("Cert%3D" + quoted(LEAF_PEM), cert() + ";Unknown=%22%3B%2C",
                        "Cert=" + quoted(LEAF_PEM).replace("%", "%25"))) {
            if (value.contains("Unknown=")) {
                assertThat(org.junit.jupiter.api.Assertions
                        .assertDoesNotThrow(() -> ForwardedClientCertificateParser.parse(value))
                        .content()).isEqualTo(LEAF_DER);
            } else {
                assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(value));
            }
        }
    }

    @Test
    void boundsPairsAndMaterialBeforeDeduplication() throws Exception {
        String metadata = "URI=x;".repeat(127);
        assertThat(ForwardedClientCertificateParser.parse(metadata + cert()).content()).isEqualTo(LEAF_DER);
        String tooManyPairs = "URI=x;" + metadata + cert();
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(tooManyPairs))).hasMessageContaining("limit");
        String bundle = LEAF_PEM + read("issuer.pem").repeat(15);
        assertThat(ForwardedClientCertificateParser.parse(cert() + ";Chain=" + quoted(bundle)).chain())
                .containsExactly(ISSUER_DER);
        String tooManyCertificates = cert() + ";Chain=" + quoted(bundle + read("issuer.pem"));
        assertThat(assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(tooManyCertificates))).hasMessageContaining("limit");
    }

    @Test
    void rejectsRepeatedPhysicalXfccFields() {
        var request = new MockHttpServletRequest();
        request.addHeader("ssl-client-cert", cert());
        request.addHeader("ssl-client-cert", cert());
        assertThrows(IllegalArgumentException.class,
                () -> ForwardedClientCertificateParser.parse(request, "ssl-client-cert"));
    }

    private static String cert() {
        return "Cert=" + quoted(LEAF_PEM);
    }

    private static String quoted(String pem) {
        return "\"" + URLEncoder.encode(pem, StandardCharsets.UTF_8).replace("+", "%20") + "\"";
    }
}

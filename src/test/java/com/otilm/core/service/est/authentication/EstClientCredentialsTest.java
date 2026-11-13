package com.otilm.core.service.est.authentication;

import com.otilm.core.security.authn.ForwardedCertificateFixtures;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class EstClientCredentialsTest {

    private static final String CERTIFICATE_HEADER = "ssl-client-cert";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "p4ssw0rd";

    // ── BasicAuthorization ────────────────────────────────────────────────────

    @Nested
    class BasicAuthorization {

        @Test
        void readsBasicCredentials_whenHeaderIsBasic() {
            // given
            MockHttpServletRequest request = requestWithAuthorization(basic(USERNAME + ":" + PASSWORD));

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).hasValueSatisfying(basic -> {
                assertThat(basic.username()).isEqualTo(USERNAME);
                assertThat(basic.password()).isEqualTo(PASSWORD);
            });
            assertThat(credentials.basicMalformed()).isFalse();
        }

        @ParameterizedTest
        @ValueSource(strings = {"Basic", "basic", "BASIC", "bAsIc"})
        void readsBasicCredentials_whenSchemeIsInAnyLetterCase(String scheme) {
            // given
            String encoded = Base64
                    .getEncoder()
                    .encodeToString((USERNAME + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8));
            MockHttpServletRequest request = requestWithAuthorization(scheme + " " + encoded);

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).hasValueSatisfying(basic -> {
                assertThat(basic.username()).isEqualTo(USERNAME);
                assertThat(basic.password()).isEqualTo(PASSWORD);
            });
        }

        @Test
        void splitsAtFirstColon_whenPasswordContainsColons() {
            // given
            var passwordWithColons = "pa:ss:wo:rd:";
            MockHttpServletRequest request = requestWithAuthorization(basic(USERNAME + ":" + passwordWithColons));

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).hasValueSatisfying(basic -> {
                assertThat(basic.username()).isEqualTo(USERNAME);
                assertThat(basic.password()).isEqualTo(passwordWithColons);
            });
        }

        @Test
        void keepsEmptyUsername_whenClientSendsNone() {
            // given
            MockHttpServletRequest request = requestWithAuthorization(basic(":" + PASSWORD));

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).hasValueSatisfying(basic -> {
                assertThat(basic.username()).isEmpty();
                assertThat(basic.password()).isEqualTo(PASSWORD);
            });
            assertThat(credentials.basicMalformed()).isFalse();
        }

        @Test
        void decodesUtf8_whenCredentialsCarryNonAsciiCharacters() {
            // given
            var username = "zařízení";
            var password = "pässwörd✓";
            MockHttpServletRequest request = requestWithAuthorization(basic(username + ":" + password));

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).hasValueSatisfying(basic -> {
                assertThat(basic.username()).isEqualTo(username);
                assertThat(basic.password()).isEqualTo(password);
            });
        }

        @ParameterizedTest
        @MethodSource("undecodableHeaders")
        void marksBasicMalformed_whenHeaderCannotBeDecoded(String authorization) {
            // given
            MockHttpServletRequest request = requestWithAuthorization(authorization);

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).isEmpty();
            assertThat(credentials.basicMalformed()).isTrue();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "Bearer eyJhbGciOiJSUzI1NiJ9",
                "Digest username=\"device-owner\"",
                "Basicx dXNlcjpwYXNz",
                "Basic:dXNlcjpwYXNz"})
        void ignoresAuthorization_whenSchemeIsNotBasic(String authorization) {
            // given
            MockHttpServletRequest request = requestWithAuthorization(authorization);

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).isEmpty();
            assertThat(credentials.basicMalformed()).isFalse();
        }

        @Test
        void readsNoBasicCredentials_whenRequestHasNoAuthorizationHeader() {
            // given
            MockHttpServletRequest request = new MockHttpServletRequest();

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).isEmpty();
            assertThat(credentials.basicMalformed()).isFalse();
        }

        @ParameterizedTest
        @MethodSource("headersWithALongRunOfSpaces")
        @Timeout(value = 1, unit = TimeUnit.SECONDS)
        void marksBasicMalformedQuickly_whenALongRunOfSpacesFollowsTheScheme(String authorization) {
            // given
            MockHttpServletRequest request = requestWithAuthorization(authorization);

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basicMalformed()).isTrue();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> undecodableHeaders() {
            return Stream
                    .of(arguments(named("not base64 text", "Basic !!!not-base64!!!")),
                            arguments(named("URL-safe base64 alphabet", "Basic dXNlcjpw-_8")),
                            arguments(named("base64 text with a blank inside", "Basic dXNl cjpwYXNz")),
                            arguments(named("no colon between user and password", basic("user-without-colon"))),
                            arguments(named("no credentials after the scheme", "Basic")),
                            arguments(named("blank credentials after the scheme", "Basic    ")));
        }

        static Stream<Arguments> headersWithALongRunOfSpaces() {
            String spaces = " ".repeat(60_000);
            return Stream
                    .of(arguments(named("a next-line character after the spaces, which a regular expression dot does "
                            + "not match", "Basic" + spaces + "\u0085")),
                            arguments(named("a character outside base64 after the spaces", "Basic" + spaces + "!")));
        }
    }

    // ── ClientCertificate ─────────────────────────────────────────────────────

    @Nested
    class ClientCertificate {

        @Test
        void readsCertificate_whenHeaderHoldsOne() {
            // given
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader(CERTIFICATE_HEADER, ForwardedCertificateFixtures.LEAF_DER);

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.certificate()).hasValueSatisfying(certificate -> {
                assertThat(certificate.content()).isEqualTo(ForwardedCertificateFixtures.LEAF_DER);
                assertThat(certificate.thumbprint()).isEqualTo(ForwardedCertificateFixtures.THUMBPRINT);
            });
            assertThat(credentials.certificateMalformed()).isFalse();
        }

        @ParameterizedTest
        @ValueSource(strings = {"not a certificate", "   ", "AAAA"})
        void marksCertificateMalformed_whenHeaderIsInvalid(String header) {
            // given
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader(CERTIFICATE_HEADER, header);

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.certificate()).isEmpty();
            assertThat(credentials.certificateMalformed()).isTrue();
        }

        @Test
        void readsNoCertificate_whenHeaderIsAbsent() {
            // given
            MockHttpServletRequest request = new MockHttpServletRequest();

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.certificate()).isEmpty();
            assertThat(credentials.certificateMalformed()).isFalse();
        }

        @Test
        void readsCertificateAndBasicCredentialsIndependently_whenRequestCarriesBoth() {
            // given
            MockHttpServletRequest request = requestWithAuthorization(basic(USERNAME + ":" + PASSWORD));
            request.addHeader(CERTIFICATE_HEADER, ForwardedCertificateFixtures.LEAF_DER);

            // when
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // then
            assertThat(credentials.basic()).isPresent();
            assertThat(credentials.certificate()).isPresent();
        }
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    @Nested
    class Rendering {

        @Test
        void printsNoCredential_whenRendered() {
            // given
            MockHttpServletRequest request = requestWithAuthorization(basic(USERNAME + ":" + PASSWORD));
            request.addHeader(CERTIFICATE_HEADER, ForwardedCertificateFixtures.LEAF_DER);
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // when
            String rendered = credentials.toString();

            // then
            assertThat(rendered).isEqualTo("EstClientCredentials[basic=present, certificate=present]");
        }

        @Test
        void printsMalformed_whenCredentialsCannotBeRead() {
            // given
            MockHttpServletRequest request = requestWithAuthorization("Basic !!!not-base64!!!");
            request.addHeader(CERTIFICATE_HEADER, "not a certificate");
            EstClientCredentials credentials = EstClientCredentials.from(request, CERTIFICATE_HEADER);

            // when
            String rendered = credentials.toString();

            // then
            assertThat(rendered).isEqualTo("EstClientCredentials[basic=malformed, certificate=malformed]");
        }

        @Test
        void printsAbsent_whenRequestCarriesNoCredentials() {
            // given
            EstClientCredentials credentials = EstClientCredentials
                    .from(new MockHttpServletRequest(), CERTIFICATE_HEADER);

            // when
            String rendered = credentials.toString();

            // then
            assertThat(rendered).isEqualTo("EstClientCredentials[basic=absent, certificate=absent]");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static MockHttpServletRequest requestWithAuthorization(String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, authorization);
        return request;
    }

    private static String basic(String userAndPassword) {
        byte[] credentials = userAndPassword.getBytes(StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(credentials);
    }
}

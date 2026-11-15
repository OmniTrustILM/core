package com.otilm.core.service.est.message;

import com.otilm.api.model.core.est.EstMediaTypes;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class EstRequestGuardTest {

    private static final String PKCS10 = EstMediaTypes.PKCS10;
    private static final long CSR_LENGTH = 1_024;
    private static final long UNKNOWN_LENGTH = -1;
    private static final long ONE_OVER_THE_LIMIT = EstRequestGuard.MAX_BODY_BYTES + 1L;

    // ── Check ─────────────────────────────────────────────────────────────────

    @Nested
    class Check {

        @ParameterizedTest(name = "{0}")
        @MethodSource("admittedRequests")
        void admits_whenOperationMethodAndContentTypeMatch(String method, String operationPath, String contentType,
                long contentLength) {
            // given — a request whose method, path, content type and length come from the case

            // when
            Optional<EstError> refusal = EstRequestGuard.check(method, operationPath, contentType, contentLength);

            // then
            assertThat(refusal).isEmpty();
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("com.otilm.core.service.est.message.EstRequestGuardTest#pathsThatAreNotOperations")
        void refusesWithNotFound_whenPathIsNotAnOperation(String operationPath) {
            // given — a CSR posted as the rules about the method, the content type and the length require
            var method = "POST";

            // when
            Optional<EstError> refusal = EstRequestGuard.check(method, operationPath, PKCS10, CSR_LENGTH);

            // then
            assertThat(refusal).contains(EstError.NOT_FOUND);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("requestsWithAMethodTheOperationDoesNotAccept")
        void refusesWithMethodNotAllowed_whenMethodDoesNotMatch(String method, String operationPath) {
            // given — a content type and a length that every operation accepts

            // when
            Optional<EstError> refusal = EstRequestGuard.check(method, operationPath, PKCS10, CSR_LENGTH);

            // then
            assertThat(refusal).contains(EstError.METHOD_NOT_ALLOWED);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("contentTypesThatAreNotPkcs10")
        void refusesWithUnsupportedMediaType_whenPostIsNotPkcs10(String contentType) {
            // given — an enrollment posted with the method and the length it requires
            var enrollment = "devices/simpleenroll";

            // when
            Optional<EstError> refusal = EstRequestGuard.check("POST", enrollment, contentType, CSR_LENGTH);

            // then
            assertThat(refusal).contains(EstError.UNSUPPORTED_MEDIA_TYPE);
        }

        @Test
        void refusesWithPayloadTooLarge_whenDeclaredLengthExceedsTheLimit() {
            // given — an enrollment posted with the method and the content type it requires
            var enrollment = "devices/simpleenroll";

            // when
            Optional<EstError> refusal = EstRequestGuard.check("POST", enrollment, PKCS10, ONE_OVER_THE_LIMIT);

            // then
            assertThat(refusal).contains(EstError.PAYLOAD_TOO_LARGE);
        }

        @Test
        void refusesWithPayloadTooLarge_whenAGetDeclaresABodyOverTheLimit() {
            // given — a discovery request, which has no body to speak of
            var discovery = "devices/cacerts";

            // when
            Optional<EstError> refusal = EstRequestGuard.check("GET", discovery, null, ONE_OVER_THE_LIMIT);

            // then
            assertThat(refusal).contains(EstError.PAYLOAD_TOO_LARGE);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("requestsThatBreakSeveralRules")
        void refusesWithTheFirstRuleThatFails_whenSeveralFail(String method, String operationPath, String contentType,
                long contentLength, EstError expected) {
            // given — a request whose method, path, content type and length come from the case

            // when
            Optional<EstError> refusal = EstRequestGuard.check(method, operationPath, contentType, contentLength);

            // then
            assertThat(refusal).contains(expected);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Arguments> admittedRequests() {
            return Stream
                    .of(arguments(named("GET cacerts without a label", "GET"), "cacerts", null, UNKNOWN_LENGTH),
                            arguments(named("GET cacerts with a label", "GET"), "devices/cacerts", null,
                                    UNKNOWN_LENGTH),
                            arguments(named("GET csrattrs without a label", "GET"), "csrattrs", null, UNKNOWN_LENGTH),
                            arguments(named("GET csrattrs with a label", "GET"), "devices/csrattrs", null,
                                    UNKNOWN_LENGTH),
                            arguments(named("POST simpleenroll without a label", "POST"), "simpleenroll", PKCS10,
                                    CSR_LENGTH),
                            arguments(named("POST simpleenroll with a label", "POST"), "devices/simpleenroll", PKCS10,
                                    CSR_LENGTH),
                            arguments(named("POST simplereenroll without a label", "POST"), "simplereenroll", PKCS10,
                                    CSR_LENGTH),
                            arguments(named("POST simplereenroll with a label", "POST"), "devices/simplereenroll",
                                    PKCS10, CSR_LENGTH),
                            arguments(named("POST serverkeygen without a label", "POST"), "serverkeygen", PKCS10,
                                    CSR_LENGTH),
                            arguments(named("POST serverkeygen with a label", "POST"), "devices/serverkeygen", PKCS10,
                                    CSR_LENGTH),
                            arguments(named("a content type with a parameter", "POST"), "devices/simpleenroll",
                                    PKCS10 + "; charset=utf-8", CSR_LENGTH),
                            arguments(named("a content type in capitals", "POST"), "devices/simpleenroll",
                                    "APPLICATION/PKCS10", CSR_LENGTH),
                            arguments(named("a length that is not known in advance", "POST"), "devices/simpleenroll",
                                    PKCS10, UNKNOWN_LENGTH),
                            arguments(named("a body of exactly the limit", "POST"), "devices/simpleenroll", PKCS10,
                                    (long) EstRequestGuard.MAX_BODY_BYTES));
        }

        private static Stream<Arguments> requestsWithAMethodTheOperationDoesNotAccept() {
            return Stream
                    .of(arguments(named("GET on simpleenroll", "GET"), "devices/simpleenroll"),
                            arguments(named("GET on simplereenroll", "GET"), "devices/simplereenroll"),
                            arguments(named("GET on serverkeygen", "GET"), "devices/serverkeygen"),
                            arguments(named("POST on cacerts", "POST"), "devices/cacerts"),
                            arguments(named("POST on csrattrs", "POST"), "devices/csrattrs"),
                            arguments(named("PUT on simpleenroll", "PUT"), "devices/simpleenroll"),
                            arguments(named("DELETE on cacerts", "DELETE"), "devices/cacerts"),
                            arguments(named("HEAD on cacerts", "HEAD"), "devices/cacerts"),
                            arguments(named("OPTIONS on simpleenroll", "OPTIONS"), "devices/simpleenroll"));
        }

        private static Stream<Named<String>> contentTypesThatAreNotPkcs10() {
            return Stream
                    .of(named("none", null), named("blank", ""), named("JSON", "application/json"),
                            named("plain text", "text/plain"), named("not a media type", "pkcs10"),
                            named("a subtype that only starts like it", "application/pkcs10x"),
                            named("a wildcard subtype", "application/*"),
                            named("two media types", PKCS10 + ", text/plain"));
        }

        private static Stream<Arguments> requestsThatBreakSeveralRules() {
            return Stream
                    .of(arguments(named("the path before the method", "DELETE"), "fullcmc", null, ONE_OVER_THE_LIMIT,
                            EstError.NOT_FOUND),
                            arguments(named("the method before the content type", "GET"), "simpleenroll", "text/plain",
                                    ONE_OVER_THE_LIMIT, EstError.METHOD_NOT_ALLOWED),
                            arguments(named("the content type before the length", "POST"), "simpleenroll", "text/plain",
                                    ONE_OVER_THE_LIMIT, EstError.UNSUPPORTED_MEDIA_TYPE));
        }
    }

    // ── AllowedMethod ─────────────────────────────────────────────────────────

    @Nested
    class AllowedMethod {

        @ParameterizedTest(name = "{0}")
        @MethodSource("operationsWithTheirMethods")
        void returnsTheMethodOfTheOperation(String operationPath, String expectedMethod) {
            // given — an operation the server offers, with or without a label

            // when
            String allowed = EstRequestGuard.allowedMethod(operationPath);

            // then
            assertThat(allowed).isEqualTo(expectedMethod);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("com.otilm.core.service.est.message.EstRequestGuardTest#pathsThatAreNotOperations")
        void returnsNothing_whenPathIsNotAnOperation(String operationPath) {
            // given — a path that no operation answers

            // when
            String allowed = EstRequestGuard.allowedMethod(operationPath);

            // then
            assertThat(allowed).isNull();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Arguments> operationsWithTheirMethods() {
            return Stream
                    .of(arguments("cacerts", "GET"), arguments("devices/cacerts", "GET"), arguments("csrattrs", "GET"),
                            arguments("devices/csrattrs", "GET"), arguments("simpleenroll", "POST"),
                            arguments("devices/simpleenroll", "POST"), arguments("simplereenroll", "POST"),
                            arguments("devices/simplereenroll", "POST"), arguments("serverkeygen", "POST"),
                            arguments("devices/serverkeygen", "POST"));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Named<String>> pathsThatAreNotOperations() {
        return Stream
                .of(named("the EST base itself", ""),
                        named("an operation of RFC 7030 that the server does not offer", "fullcmc"),
                        named("two labels", "a/b/cacerts"), named("a label without an operation", "devices/"),
                        named("an operation without a label name", "/cacerts"),
                        named("an unknown operation under a label", "devices/unknown"),
                        named("an operation name in capitals", "CACERTS"));
    }
}

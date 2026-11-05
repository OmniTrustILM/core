package com.otilm.core.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.CertificateRevocationRequest;
import com.otilm.api.model.core.acme.Problem;
import java.util.Map;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.junit.jupiter.api.Named.named;

class AcmeJsonProcessorTest {

    // ── GetPayloadAsRequestObject ─────────────────────────────────────────────

    @Nested
    class GetPayloadAsRequestObject {

        @Test
        void returnsRequestIgnoringUnknownMembers_whenPayloadMapsToItsType() throws Exception {
            // given
            var certificate = "MIIB";
            var reason = 1;
            JWSObject jwsObject = jwsObjectCarrying(
                    "{\"certificate\":\"" + certificate + "\",\"reason\":" + reason + ",\"unknown\":true}");

            // when
            CertificateRevocationRequest request = AcmeJsonProcessor
                    .getPayloadAsRequestObject(jwsObject, CertificateRevocationRequest.class);

            // then
            assertThat(request.getCertificate()).isEqualTo(certificate);
            assertThat(request.getReason()).isEqualTo(reason);
        }

        @ParameterizedTest
        @MethodSource("payloadsThatDoNotMapToTheirType")
        void refusesAsMalformed_whenPayloadDoesNotMapToItsType(String payload, Class<?> type) {
            // given
            JWSObject jwsObject = jwsObjectCarrying(payload);

            // when
            ThrowingCallable read = () -> AcmeJsonProcessor.getPayloadAsRequestObject(jwsObject, type);

            // then
            assertThatThrownBy(read)
                    .isInstanceOfSatisfying(AcmeProblemDocumentException.class,
                            AcmeJsonProcessorTest::assertRefusedAsMalformedPayload);
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        private static Stream<Arguments> payloadsThatDoNotMapToTheirType() {
            Class<?> revocation = CertificateRevocationRequest.class;
            Class<?> account = Account.class;
            return Stream
                    .of(Arguments.of(named("an empty payload", ""), revocation),
                            Arguments.of(named("text that is not JSON", "revoke"), revocation),
                            Arguments.of(named("the JSON null literal", "null"), revocation),
                            Arguments.of(named("a JSON string", "\"revoke\""), revocation),
                            Arguments.of(named("an empty JSON array", "[]"), revocation),
                            Arguments
                                    .of(named("a JSON array of member pairs", "[[\"certificate\",\"MIIB\"]]"),
                                            revocation),
                            Arguments
                                    .of(named("a member stated twice",
                                            "{\"certificate\":\"MIIB\",\"certificate\":\"MIIC\"}"), revocation),
                            Arguments
                                    .of(named("content after the JSON object", "{\"certificate\":\"MIIB\"} {}"),
                                            revocation),
                            Arguments.of(named("an object where text is expected", "{\"certificate\":{}}"), revocation),
                            Arguments
                                    .of(named("a boolean where text is expected", "{\"certificate\":false}"),
                                            revocation),
                            Arguments.of(named("a number where text is expected", "{\"certificate\":1}"), revocation),
                            Arguments.of(named("text where an integer is expected", "{\"reason\":\"1\"}"), revocation),
                            Arguments
                                    .of(named("an empty string where an integer is expected", "{\"reason\":\"\"}"),
                                            revocation),
                            Arguments
                                    .of(named("a blank string where an integer is expected", "{\"reason\":\" \"}"),
                                            revocation),
                            Arguments
                                    .of(named("a fraction where an integer is expected", "{\"reason\":1.9}"),
                                            revocation),
                            Arguments
                                    .of(named("a boolean where an integer is expected", "{\"reason\":true}"),
                                            revocation),
                            Arguments
                                    .of(named("text where a boolean is expected",
                                            "{\"termsOfServiceAgreed\":\"true\"}"), account),
                            Arguments
                                    .of(named("an empty string where a boolean is expected",
                                            "{\"termsOfServiceAgreed\":\"\"}"), account),
                            Arguments
                                    .of(named("a blank string where a boolean is expected",
                                            "{\"termsOfServiceAgreed\":\" \"}"), account),
                            Arguments
                                    .of(named("a number where a boolean is expected", "{\"termsOfServiceAgreed\":1}"),
                                            account),
                            Arguments.of(named("a number where a status is expected", "{\"status\":1}"), account),
                            Arguments
                                    .of(named("an empty string where a status is expected", "{\"status\":\"\"}"),
                                            account));
        }
    }

    // ── GetPayloadAsJsonObject ────────────────────────────────────────────────

    @Nested
    class GetPayloadAsJsonObject {

        @Test
        void returnsMembers_whenPayloadIsJsonObject() throws Exception {
            // given
            var accountUrl = "https://acme.example/acct/1";
            JWSObject jwsObject = jwsObjectCarrying("{\"account\":\"" + accountUrl + "\"}");

            // when
            Map<String, Object> members = AcmeJsonProcessor.getPayloadAsJsonObject(jwsObject);

            // then
            assertThat(members).containsExactly(entry("account", accountUrl));
        }

        @ParameterizedTest
        @MethodSource("payloadsThatAreNotJsonObjects")
        void refusesAsMalformed_whenPayloadIsNotJsonObject(String payload) {
            // given
            JWSObject jwsObject = jwsObjectCarrying(payload);

            // when
            ThrowingCallable read = () -> AcmeJsonProcessor.getPayloadAsJsonObject(jwsObject);

            // then
            assertThatThrownBy(read)
                    .isInstanceOfSatisfying(AcmeProblemDocumentException.class,
                            AcmeJsonProcessorTest::assertRefusedAsMalformedPayload);
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        private static Stream<Named<String>> payloadsThatAreNotJsonObjects() {
            return Stream
                    .of(named("an empty payload", ""), named("text that is not JSON", "rollover"),
                            named("the JSON null literal", "null"), named("a JSON string", "\"rollover\""),
                            named("an empty JSON array", "[]"),
                            named("a JSON array of member pairs", "[[\"account\",\"https://acme.example/acct/1\"]]"));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static JWSObject jwsObjectCarrying(String payload) {
        return new JWSObject(new JWSHeader(JWSAlgorithm.ES256), new Payload(payload));
    }

    private static void assertRefusedAsMalformedPayload(AcmeProblemDocumentException refused) {
        assertThat(refused.getHttpStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(refused.getProblemDocument().getType()).isEqualTo(Problem.MALFORMED.getType());
        assertThat(refused.getProblemDocument().getDetail()).isEqualTo("Request payload is malformed");
    }
}

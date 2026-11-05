package com.otilm.core.service.acme.message;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.Problem;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

class AcmeJwsRequestTest {

    /** The base64url encoding of the protected header {@code {"alg":"RS256"}}. */
    private static final String PROTECTED_HEADER = "eyJhbGciOiJSUzI1NiJ9";

    /** A protected header that names an account, so a body carrying it is refused for nothing else. */
    private static final String HEADER_NAMING_AN_ACCOUNT = base64Url(
            "{\"alg\":\"RS256\",\"kid\":\"https://acme.example/acct/1\"}");

    /** A protected header whose key lists another prime of the RSA modulus without any of its members. */
    private static final String HEADER_WITH_A_MALFORMED_KEY = base64Url(
            "{\"alg\":\"RS256\",\"jwk\":{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"oth\":[{}]}}");

    @ParameterizedTest
    @MethodSource("bodiesThatAreNotAFlattenedJws")
    void refusesAsMalformed_whenBodyIsNotAFlattenedJws(String body) {
        // given — a body that is not a JWS in flattened JSON serialization with a usable protected header

        // when
        ThrowingCallable read = () -> new AcmeJwsRequest(body);

        // then
        assertThatThrownBy(read).isInstanceOfSatisfying(AcmeProblemDocumentException.class, refused -> {
            assertThat(refused.getHttpStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
            assertThat(refused.getProblemDocument().getType()).isEqualTo(Problem.MALFORMED.getType());
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<String>> bodiesThatAreNotAFlattenedJws() {
        return Stream
                .of(named("the JSON null literal", "null"), named("an empty object", "{}"),
                        named("a body without the protected header", "{\"payload\":\"\",\"signature\":\"c2ln\"}"),
                        named("a body without the payload",
                                "{\"protected\":\"" + PROTECTED_HEADER + "\",\"signature\":\"c2ln\"}"),
                        named("a body without the signature",
                                "{\"protected\":\"" + PROTECTED_HEADER + "\",\"payload\":\"\"}"),
                        named("a boolean where the signature is expected",
                                "{\"protected\":\"" + HEADER_NAMING_AN_ACCOUNT
                                        + "\",\"payload\":\"\",\"signature\":false}"),
                        named("a number where the signature is expected",
                                "{\"protected\":\"" + HEADER_NAMING_AN_ACCOUNT
                                        + "\",\"payload\":\"\",\"signature\":1}"),
                        named("a boolean where the payload is expected",
                                "{\"protected\":\"" + HEADER_NAMING_AN_ACCOUNT
                                        + "\",\"payload\":true,\"signature\":\"c2ln\"}"),
                        named("a member stated twice",
                                "{\"protected\":\"" + HEADER_NAMING_AN_ACCOUNT
                                        + "\",\"payload\":\"\",\"signature\":\"c2ln\",\"signature\":\"c2ln\"}"),
                        named("content after the JSON object",
                                "{\"protected\":\"" + HEADER_NAMING_AN_ACCOUNT
                                        + "\",\"payload\":\"\",\"signature\":\"c2ln\"} {}"),
                        named("a key that lists another prime without its members", "{\"protected\":\""
                                + HEADER_WITH_A_MALFORMED_KEY + "\",\"payload\":\"\",\"signature\":\"c2ln\"}"));
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}

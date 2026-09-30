package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ContainerRefusalTest {

    private static final String UNRECOGNIZED = "an unrecognized type";

    @ParameterizedTest
    @MethodSource("namingRefusals")
    void refusal_repeatsAPlainName(Function<String, ValidationException> refusal, String message) {
        // when, then
        assertThat(refusal.apply("1.2.840.113549.1.12.10.1.4").getMessage())
                .isEqualTo(message.formatted("1.2.840.113549.1.12.10.1.4"));
        assertThat(refusal.apply("X509 CRL").getMessage()).isEqualTo(message.formatted("X509 CRL"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "a_type", "type\nwith a line break", "a type with ✓ in it"})
    void refusal_hidesAnyOtherName(String name) {
        // when, then
        assertThat(ContainerRefusal.entryUnsupported(name).getMessage())
                .isEqualTo(ContainerRefusal.ENTRY_UNSUPPORTED.formatted(UNRECOGNIZED));
        assertThat(ContainerRefusal.pemBlockUnsupported(name).getMessage())
                .isEqualTo(ContainerRefusal.PEM_BLOCK_UNSUPPORTED.formatted(UNRECOGNIZED));
    }

    @ParameterizedTest
    @MethodSource("namingRefusals")
    void refusal_hidesANameLongerThanSixtyFourCharacters(Function<String, ValidationException> refusal,
            String message) {
        // when, then
        assertThat(refusal.apply("1".repeat(64)).getMessage()).isEqualTo(message.formatted("1".repeat(64)));
        assertThat(refusal.apply("1".repeat(65)).getMessage()).isEqualTo(message.formatted(UNRECOGNIZED));
        assertThat(refusal.apply(null).getMessage()).isEqualTo(message.formatted(UNRECOGNIZED));
    }

    @ParameterizedTest
    @MethodSource("fixedRefusals")
    void refusal_isItsFixedMessage(Supplier<ValidationException> refusal, String message) {
        // when, then
        assertThat(refusal.get().getMessage()).isEqualTo(message);
    }

    static Stream<Arguments> namingRefusals() {
        return Stream
                .of(arguments(
                        named("PEM block",
                                (Function<String, ValidationException>) ContainerRefusal::pemBlockUnsupported),
                        ContainerRefusal.PEM_BLOCK_UNSUPPORTED),
                        arguments(
                                named("integrity scheme",
                                        (Function<String, ValidationException>) ContainerRefusal::integrityUnsupported),
                                ContainerRefusal.INTEGRITY_UNSUPPORTED),
                        arguments(
                                named("entry",
                                        (Function<String, ValidationException>) ContainerRefusal::entryUnsupported),
                                ContainerRefusal.ENTRY_UNSUPPORTED));
    }

    static Stream<Arguments> fixedRefusals() {
        return Stream
                .of(arguments(
                        named("not supported", (Supplier<ValidationException>) ContainerRefusal::notSupportedFormat),
                        ContainerRefusal.NOT_SUPPORTED_FORMAT),
                        arguments(
                                named("too many keys",
                                        (Supplier<ValidationException>) ContainerRefusal::pemTooManyKeys),
                                ContainerRefusal.PEM_TOO_MANY_KEYS),
                        arguments(
                                named("integrity failed",
                                        (Supplier<ValidationException>) ContainerRefusal::integrityFailed),
                                ContainerRefusal.INTEGRITY_FAILED),
                        arguments(
                                named("two passphrases",
                                        (Supplier<ValidationException>) ContainerRefusal::twoPassphrases),
                                ContainerRefusal.TWO_PASSPHRASES),
                        arguments(
                                named("recipient protected",
                                        (Supplier<ValidationException>) ContainerRefusal::recipientProtected),
                                ContainerRefusal.RECIPIENT_PROTECTED));
    }
}

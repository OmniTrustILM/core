package com.otilm.core.key.description;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class SoftwareProviderKeyValuesTest {

    @ParameterizedTest
    @MethodSource("mapsLackingTheirParameterValue")
    void readsNoParameters_whenTheMapLacksTheValueNamingThem(KeyAlgorithm algorithm, Map<String, String> values) {
        // when
        Optional<KeyParameters> parameters = SoftwareProviderKeyValues.parametersOf(algorithm, values);

        // then
        assertThat(parameters).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> mapsLackingTheirParameterValue() {
        return Stream
                .of(arguments(named("Falcon without degree", KeyAlgorithm.FALCON), Map.of("prehash", "false")),
                        arguments(named("ML-DSA holding only externalId", KeyAlgorithm.MLDSA),
                                Map.of("externalId", "key-1")),
                        arguments(named("SLH-DSA without securityCategory", KeyAlgorithm.SLHDSA),
                                Map.of("hash", "SHA2", "tradeoff", "FAST", "prehash", "false")),
                        arguments(named("ML-KEM, empty", KeyAlgorithm.MLKEM), Map.of()));
    }
}

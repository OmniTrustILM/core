package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.api.model.core.cryptoasset.PqcVerdict.NOT_APPLICABLE;
import static com.otilm.api.model.core.cryptoasset.PqcVerdict.NOT_READY;
import static com.otilm.api.model.core.cryptoasset.PqcVerdict.READY;
import static com.otilm.api.model.core.cryptoasset.PqcVerdict.UNKNOWN;
import static org.assertj.core.api.Assertions.assertThat;

class PqcVerdictTransitionTest {
    @ParameterizedTest(name = "{0}")
    @MethodSource("transitions")
    void decidedHistoryControlsNotReadyPublication(String description, PqcVerdict current, PqcVerdict last,
            PqcVerdict next, PqcVerdict previous, PqcVerdict savedLast, boolean publish) {
        PqcVerdictTransition result = PqcVerdictTransition.decide(current, last, next);

        assertThat(result.previousVerdict()).isEqualTo(previous);
        assertThat(result.lastDecidedVerdict()).isEqualTo(savedLast);
        assertThat(result.shouldPublish()).isEqualTo(publish);
    }

    static Stream<Arguments> transitions() {
        return Stream
                .of(Arguments.of("new asset stamped NOT_READY", null, null, NOT_READY, null, NOT_READY, true), Arguments
                        .of("new UNKNOWN later becomes NOT_READY", UNKNOWN, null, NOT_READY, null, NOT_READY, true),
                        Arguments.of("READY becomes NOT_READY", READY, READY, NOT_READY, READY, NOT_READY, true),
                        Arguments
                                .of("NOT_APPLICABLE becomes NOT_READY", NOT_APPLICABLE, NOT_APPLICABLE, NOT_READY,
                                        NOT_APPLICABLE, NOT_READY, true),
                        Arguments
                                .of("existing UNKNOWN since ingest becomes NOT_READY", UNKNOWN, null, NOT_READY, null,
                                        NOT_READY, true),
                        Arguments
                                .of("NOT_READY becomes UNKNOWN without forgetting history", NOT_READY, NOT_READY,
                                        UNKNOWN, NOT_READY, NOT_READY, false),
                        Arguments
                                .of("NOT_READY through UNKNOWN returns to NOT_READY", UNKNOWN, NOT_READY, NOT_READY,
                                        NOT_READY, NOT_READY, false),
                        Arguments.of("NOT_READY becomes READY", NOT_READY, NOT_READY, READY, NOT_READY, READY, false),
                        Arguments
                                .of("NOT_READY through READY returns to NOT_READY", READY, READY, NOT_READY, READY,
                                        NOT_READY, true),
                        Arguments.of("NOT_READY restamp", NOT_READY, NOT_READY, NOT_READY, NOT_READY, NOT_READY, false),
                        Arguments
                                .of("pre-upgrade NOT_READY restamp", NOT_READY, null, NOT_READY, NOT_READY, NOT_READY,
                                        false),
                        Arguments
                                .of("pre-upgrade NOT_READY becomes UNKNOWN", NOT_READY, null, UNKNOWN, NOT_READY,
                                        NOT_READY, false),
                        Arguments
                                .of("pre-upgrade NOT_READY through UNKNOWN returns", UNKNOWN, NOT_READY, NOT_READY,
                                        NOT_READY, NOT_READY, false),
                        Arguments.of("pre-upgrade READY becomes UNKNOWN", READY, null, UNKNOWN, READY, READY, false),
                        Arguments
                                .of("recorded READY survives UNKNOWN", UNKNOWN, READY, NOT_READY, READY, NOT_READY,
                                        true),
                        Arguments.of("undecided UNKNOWN remains undecided", UNKNOWN, null, UNKNOWN, null, null, false),
                        Arguments
                                .of("clearing a verdict preserves decided history", NOT_READY, NOT_READY, null,
                                        NOT_READY, NOT_READY, false));
    }
}

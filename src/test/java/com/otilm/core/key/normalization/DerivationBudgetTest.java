package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import java.math.BigInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;

class DerivationBudgetTest {

    private static final String ITERATION_LIMIT = "The file exceeds the key derivation iteration limit of 10000000.";

    @Test
    void charge_acceptsDerivationsThatTogetherStayWithinTheFilesShare() {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when, then
        assertThatCode(() -> {
            budget.charge(BigInteger.valueOf(4_000_000));
            budget.charge(BigInteger.valueOf(6_000_000));
        }).doesNotThrowAnyException();
    }

    @Test
    void charge_refusesADerivationOnceTheFilesShareIsSpent() {
        // given
        DerivationBudget budget = DerivationBudget.forFile();
        budget.charge(BigInteger.valueOf(4_000_000));
        budget.charge(BigInteger.valueOf(6_000_000));

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> budget.charge(BigInteger.ONE));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ITERATION_LIMIT);
    }

    @ParameterizedTest
    @MethodSource("iterationsOutsideTheShare")
    void charge_refusesADerivationOutsideTheFilesShare(BigInteger iterations) {
        // given
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> budget.charge(iterations));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ITERATION_LIMIT);
    }

    static Stream<Named<BigInteger>> iterationsOutsideTheShare() {
        return Stream
                .of(named("one over the share", BigInteger.valueOf(10_000_001)),
                        named("a negative count", BigInteger.valueOf(-1)),
                        named("a count no integer holds", BigInteger.TWO.pow(64)));
    }
}

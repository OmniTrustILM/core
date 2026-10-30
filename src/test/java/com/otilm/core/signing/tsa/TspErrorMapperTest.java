package com.otilm.core.signing.tsa;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class TspErrorMapperTest {

    private static final Map<SigningEngineFailure, TspFailureInfo> EXPECTED = Map
            .of(SigningEngineFailure.INVALID_INPUT, TspFailureInfo.BAD_REQUEST, SigningEngineFailure.MALFORMED_INPUT,
                    TspFailureInfo.BAD_DATA_FORMAT, SigningEngineFailure.MISCONFIGURED, TspFailureInfo.SYSTEM_FAILURE,
                    SigningEngineFailure.TIME_UNAVAILABLE, TspFailureInfo.TIME_NOT_AVAILABLE,
                    SigningEngineFailure.CONNECTOR_FAULT, TspFailureInfo.SYSTEM_FAILURE,
                    SigningEngineFailure.BINDING_VIOLATION, TspFailureInfo.SYSTEM_FAILURE,
                    SigningEngineFailure.SIGNER_FAULT, TspFailureInfo.SYSTEM_FAILURE, SigningEngineFailure.STEP_FAILED,
                    TspFailureInfo.SYSTEM_FAILURE);

    /** Driving off the enum makes a new failure value fail here until it is given a TSP meaning. */
    @ParameterizedTest
    @EnumSource(SigningEngineFailure.class)
    void mapsEveryFailureToATspFailureInfo(SigningEngineFailure failure) {
        // when / then
        assertThat(failure).isIn(EXPECTED.keySet());
        assertThat(TspErrorMapper.toFailureInfo(failure)).isEqualTo(EXPECTED.get(failure));
    }

    @Test
    void preservesTheClientMessageAndChainsTheCause() {
        // given
        SigningEngineException engineException = SigningEngineException
                .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, "formatDtbs",
                        "formatting connector at https://fmt.internal returned 503", new IllegalStateException("503"),
                        "Internal error during DTBS formatting");

        // when
        TspException mapped = TspErrorMapper.toTspException(engineException);

        // then
        assertThat(mapped.getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        assertThat(mapped.getClientMessage()).isEqualTo("Internal error during DTBS formatting");
        assertThat(mapped.getMessage()).isEqualTo(engineException.operatorMessage());
        assertThat(mapped.getCause()).isSameAs(engineException);
    }
}

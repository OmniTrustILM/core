package com.otilm.core.signing.tsa;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;

/**
 * Maps the Signing Engine's error currency onto RFC 3161's. Only {@code INVALID_INPUT} and {@code MALFORMED_INPUT} are
 * attributable to the requester, and only {@code TIME_UNAVAILABLE} has a failure info of its own, so everything else
 * collapses onto {@code SYSTEM_FAILURE}.
 */
public final class TspErrorMapper {

    private TspErrorMapper() {
    }

    public static TspFailureInfo toFailureInfo(SigningEngineFailure failure) {
        return switch (failure) {
            case INVALID_INPUT -> TspFailureInfo.BAD_REQUEST;
            case MALFORMED_INPUT -> TspFailureInfo.BAD_DATA_FORMAT;
            case TIME_UNAVAILABLE -> TspFailureInfo.TIME_NOT_AVAILABLE;
            case MISCONFIGURED, CONNECTOR_FAULT, BINDING_VIOLATION, SIGNER_FAULT, STEP_FAILED ->
                TspFailureInfo.SYSTEM_FAILURE;
        };
    }

    public static TspException toTspException(SigningEngineException e) {
        return new TspException(toFailureInfo(e.failure()), e.operatorMessage(), e, e.clientMessage());
    }
}

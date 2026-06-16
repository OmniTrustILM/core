package com.otilm.core.signing.tsa.validator;

import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.model.signing.workflow.TimestampingWorkflow;
import com.otilm.core.signing.tsa.messages.TspRequest;
import org.springframework.stereotype.Component;

@Component
public class TspRequestValidator {

    public void validate(TimestampingWorkflow timestampingWorkflow, TspRequest request) throws TspRequestValidationException {
        validateHashAlgorithmAllowed(timestampingWorkflow, request);
        validatePolicy(timestampingWorkflow, request);
    }

    private void validateHashAlgorithmAllowed(TimestampingWorkflow timestampingWorkflow, TspRequest request) throws TspRequestValidationException {
        var allowed = timestampingWorkflow.allowedDigestAlgorithms();
        if (!allowed.isEmpty() && !allowed.contains(request.hashAlgorithm())) {
            throw new TspRequestValidationException(
                    TspFailureInfo.BAD_ALG,
                    "Hash algorithm '%s' is not accepted by the profile".formatted(request.hashAlgorithm().getCode()),
                    "Hash algorithm is not accepted by the chosen profile");
        }
    }

    private void validatePolicy(TimestampingWorkflow timestampingWorkflow, TspRequest request) throws TspRequestValidationException {
        if (timestampingWorkflow.allowedPolicyIds().isEmpty()) {
            return;
        }

        if (request.policy().isEmpty()) {
            return;
        }
        var requestedPolicy = request.policy().get();
        if (!timestampingWorkflow.allowedPolicyIds().contains(requestedPolicy)) {
            throw new TspRequestValidationException(
                    TspFailureInfo.UNACCEPTED_POLICY,
                    "Policy '%s' is not accepted by the profile".formatted(requestedPolicy),
                    "Policy ID is not accepted by the chosen profile");
        }
    }

}

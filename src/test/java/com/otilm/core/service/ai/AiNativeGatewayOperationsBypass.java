package com.otilm.core.service.ai;

import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.ai.AiRuntimeManagementGatewayAuthority;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;

/** Deliberate static architecture counterexample, never executed or registered as an application bean. */
public class AiNativeGatewayOperationsBypass {
    public Object run(AiRuntimeGatewayAuthority authority, AiModelRunDispatchService dispatch,
            AiModelRunOutcomeWriter outcomes) {
        return AiNativeGatewayOperations.run(authority, dispatch, outcomes, System::nanoTime, new AiFeatureGate(true));
    }

    public Object management(AiRuntimeManagementGatewayAuthority authority, AiModelManagementDispatchService dispatch,
            AiModelManagementGatewayWriter assignments, AiModelManagementOutcomeWriter outcomes) {
        return AiNativeGatewayOperations
                .management(authority, dispatch, assignments, outcomes, System::nanoTime, new AiFeatureGate(true));
    }
}

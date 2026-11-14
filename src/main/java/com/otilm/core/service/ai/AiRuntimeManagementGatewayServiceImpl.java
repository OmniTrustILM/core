package com.otilm.core.service.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.security.ai.AiRuntimeManagementGatewayAuthority;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.service.AiRuntimeManagementGatewayExternalService;
import com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter;
import com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter;
import java.io.InputStream;
import java.util.function.LongSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Fixed management native entrypoints. The closed operation object owns per-invocation phase state. */
@Service
@TraceMetadataOnly
public class AiRuntimeManagementGatewayServiceImpl implements AiRuntimeManagementGatewayExternalService {
    private final AiNativeGatewayOperations operations;

    @Autowired
    public AiRuntimeManagementGatewayServiceImpl(AiRuntimeManagementGatewayAuthority authority,
            AiModelManagementDispatchService dispatch, AiModelManagementGatewayWriter assignments,
            AiModelManagementOutcomeWriter outcomes, AiFeatureGate feature) {
        this(authority, dispatch, assignments, outcomes, System::nanoTime, feature);
    }

    AiRuntimeManagementGatewayServiceImpl(AiRuntimeManagementGatewayAuthority authority,
            AiModelManagementDispatchService dispatch, AiModelManagementGatewayWriter assignments,
            AiModelManagementOutcomeWriter outcomes, LongSupplier nanos, AiFeatureGate feature) {
        operations = AiNativeGatewayOperations.management(authority, dispatch, assignments, outcomes, nanos, feature);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> registration() {
        return operations.registration();
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> redeem(InputStream body) {
        return operations.redeem(body);
    }

    @Override
    @ProtocolEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<byte[]> outcome(InputStream body) {
        return operations.outcome(body);
    }
}

package com.otilm.core.service.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.security.ai.AiRuntimeGatewayAuthority;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.service.AiRuntimeGatewayExternalService;
import com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter;
import java.io.InputStream;
import java.util.function.LongSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Fixed run native entrypoints. The closed operation object owns per-invocation phase state. */
@Service
@TraceMetadataOnly
public class AiRuntimeGatewayServiceImpl implements AiRuntimeGatewayExternalService {
    private final AiNativeGatewayOperations operations;

    @Autowired
    public AiRuntimeGatewayServiceImpl(AiRuntimeGatewayAuthority authority, AiModelRunDispatchService dispatch,
            AiModelRunOutcomeWriter outcomes, AiFeatureGate feature) {
        this(authority, dispatch, outcomes, System::nanoTime, feature);
    }

    AiRuntimeGatewayServiceImpl(AiRuntimeGatewayAuthority authority, AiModelRunDispatchService dispatch,
            AiModelRunOutcomeWriter outcomes, LongSupplier nanos, AiFeatureGate feature) {
        operations = AiNativeGatewayOperations.run(authority, dispatch, outcomes, nanos, feature);
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

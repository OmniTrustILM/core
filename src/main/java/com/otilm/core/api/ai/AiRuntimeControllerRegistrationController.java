package com.otilm.core.api.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.service.AiRuntimeControllerRegistrationExternalService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@TraceMetadataOnly
public class AiRuntimeControllerRegistrationController {
    private final AiRuntimeControllerRegistrationExternalService service;

    public AiRuntimeControllerRegistrationController(AiRuntimeControllerRegistrationExternalService service) {
        this.service = service;
    }

    @PostMapping("/internal/ai-runtime/v1/controller/gateways/run/observe")
    public ResponseEntity<byte[]> observeRunGateway() {
        return service.observeRunGateway();
    }

    @PostMapping("/internal/ai-management/v1/controller/gateway/observe")
    public ResponseEntity<byte[]> observeManagementGateway() {
        return service.observeManagementGateway();
    }
}

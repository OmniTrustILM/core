package com.otilm.core.api.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.service.AiRuntimeControllerExternalService;
import java.io.InputStream;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@TraceMetadataOnly
@RequestMapping("/internal/ai-runtime/v1/controller")
public class AiRuntimeControllerController {
    private final AiRuntimeControllerExternalService service;

    public AiRuntimeControllerController(AiRuntimeControllerExternalService service) {
        this.service = service;
    }

    @PostMapping("/launches/reconcile")
    public ResponseEntity<byte[]> reconcile(InputStream body) {
        return service.reconcile(body);
    }

    @PostMapping("/workloads/register")
    public ResponseEntity<byte[]> register(InputStream body) {
        return service.register(body);
    }

    @PostMapping("/workloads/status")
    public ResponseEntity<byte[]> status(InputStream body) {
        return service.status(body);
    }

    @PostMapping("/cleanup/reconcile")
    public ResponseEntity<byte[]> cleanup(InputStream body) {
        return service.cleanup(body);
    }
}

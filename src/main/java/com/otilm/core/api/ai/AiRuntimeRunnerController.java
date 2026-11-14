package com.otilm.core.api.ai;

import com.otilm.core.service.AiRuntimeRunnerExternalService;
import java.io.InputStream;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/ai-runtime/v1/runner")
public class AiRuntimeRunnerController {
    private final AiRuntimeRunnerExternalService service;

    public AiRuntimeRunnerController(AiRuntimeRunnerExternalService service) {
        this.service = service;
    }

    @PostMapping("/bootstrap")
    public ResponseEntity<byte[]> bootstrap(InputStream body) {
        return service.bootstrap(body);
    }

    @PostMapping("/claims/heartbeat")
    public ResponseEntity<byte[]> heartbeat(InputStream body) {
        return service.heartbeat(body);
    }
}

package com.otilm.core.api.ai;

import com.otilm.core.service.AiRuntimeGatewayExternalService;
import java.io.InputStream;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/ai-runtime/v1/gateway/run")
public class AiRuntimeGatewayController {
    private final AiRuntimeGatewayExternalService service;

    public AiRuntimeGatewayController(AiRuntimeGatewayExternalService service) {
        this.service = service;
    }

    @GetMapping("/registration")
    public ResponseEntity<byte[]> registration() {
        return service.registration();
    }

    @PostMapping("/redeem")
    public ResponseEntity<byte[]> redeem(InputStream body) {
        return service.redeem(body);
    }

    @PostMapping("/outcomes")
    public ResponseEntity<byte[]> outcome(InputStream body) {
        return service.outcome(body);
    }
}

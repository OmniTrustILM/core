package com.otilm.core.service;

import java.io.InputStream;
import org.springframework.http.ResponseEntity;

/** Private run-gateway operations authenticated by the native workload transport. */
public interface AiRuntimeGatewayExternalService {
    ResponseEntity<byte[]> registration();

    ResponseEntity<byte[]> redeem(InputStream body);

    ResponseEntity<byte[]> outcome(InputStream body);
}

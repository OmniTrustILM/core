package com.otilm.core.service;

import java.io.InputStream;
import org.springframework.http.ResponseEntity;

/** Private native management operations only; no ordinary actor/session bootstrap or publisher route. */
public interface AiRuntimeManagementGatewayExternalService {
    ResponseEntity<byte[]> registration();

    ResponseEntity<byte[]> redeem(InputStream body);

    ResponseEntity<byte[]> outcome(InputStream body);
}

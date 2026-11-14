package com.otilm.core.service;

import java.io.InputStream;
import org.springframework.http.ResponseEntity;

/** Closed private runner operations; only the native runtime transport supplies caller identity. */
public interface AiRuntimeRunnerExternalService {
    ResponseEntity<byte[]> bootstrap(InputStream body);

    ResponseEntity<byte[]> heartbeat(InputStream body);
}

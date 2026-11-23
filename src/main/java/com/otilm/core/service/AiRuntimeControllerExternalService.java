package com.otilm.core.service;

import java.io.InputStream;
import org.springframework.http.ResponseEntity;

/** Fixed native controller operations; body identifiers are copyable metadata, not authority. */
public interface AiRuntimeControllerExternalService {
    ResponseEntity<byte[]> reconcile(InputStream body);

    ResponseEntity<byte[]> register(InputStream body);

    ResponseEntity<byte[]> status(InputStream body);

    ResponseEntity<byte[]> cleanup(InputStream body);
}

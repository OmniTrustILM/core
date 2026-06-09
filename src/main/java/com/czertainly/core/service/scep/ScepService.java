package com.czertainly.core.service.scep;

import com.otilm.api.exception.ScepException;
import org.springframework.http.ResponseEntity;

public interface ScepService {

    /**
     * Handle the GET request from the SCEP client
     * @param scepProfileName Name of the SCEP Profile
     * @param operation SCEP Operation
     * @param message SCEP Message
     * @return SCEP response
     */
    ResponseEntity<Object> handleGet(String scepProfileName, String operation, String message) throws ScepException;

    /**
     * Handle the POST request from the SCEP client
     * @param scepProfileName Name of the SCEP Profile
     * @param operation SCEP Operation
     * @param message SCEP Message
     * @return SCEP response
     */
    ResponseEntity<Object> handlePost(String scepProfileName, String operation, byte[] message) throws ScepException;
}

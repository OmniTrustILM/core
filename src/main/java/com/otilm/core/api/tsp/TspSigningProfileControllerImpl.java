package com.otilm.core.api.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.TspSigningProfileController;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.api.tsp.parser.TspRequestParser;
import com.otilm.core.logging.LogResource;
import com.otilm.core.signing.tsa.TsaService;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class TspSigningProfileControllerImpl implements TspSigningProfileController {

    private TsaService tsaService;

    @Autowired
    public void setTspService(TsaService tsaService) {
        this.tsaService = tsaService;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SIGNING_RECORD, affiliatedResource = Resource.SIGNING_PROFILE, operation = Operation.SIGN)
    public ResponseEntity<byte[]> timestamp(@LogResource(name = true, affiliated = true) String signingProfileName, byte[] request) {
        byte[] responseBytes;
        try {
            TspRequest parsedRequest = TspRequestParser.parse(request);
            TspResponse response = tsaService.processTspRequestForSigningProfile(signingProfileName, parsedRequest);

            responseBytes = TspResponseBuilder.fromEngineResponse(response);
        } catch (TspException e) {
            responseBytes = TspResponseBuilder.buildRejection(e.getFailureInfo(), e.getClientMessage());
            log.warn("TSP request failed with {}: {}", e.getFailureInfo(), e.getMessage());
        } catch (NotFoundException e) {
            responseBytes = TspResponseBuilder.buildRejection(TspFailureInfo.BAD_REQUEST, "Resource not found. See logs for details.");
            log.warn("Resource not found while processing TSP request for signing profile '{}': {}", signingProfileName,
                    e.getMessage());
        } catch (Exception e) {
            responseBytes = TspResponseBuilder.buildRejection(TspFailureInfo.SYSTEM_FAILURE, "An unexpected error occurred during timestamping.");
            log.error("Unexpected TSP processing failure", e);
        }

        return ResponseEntity.ok(responseBytes);
    }
}

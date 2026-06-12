package com.otilm.core.api.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.TspController;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.api.tsp.parser.TspRequestParser;
import com.otilm.core.signing.tsa.TsaService;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class TspControllerImpl implements TspController {

    private TsaService tsaService;

    @Autowired
    public void setTspService(TsaService tsaService) {
        this.tsaService = tsaService;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SIGNING_RECORD, affiliatedResource = Resource.TSP_PROFILE, operation = Operation.SIGN)
    public ResponseEntity<byte[]> timestamp(String tspProfileName, byte[] request) {
        byte[] responseBytes;
        try {
            TspRequest parsedRequest = TspRequestParser.parse(request);
            TspResponse response = tsaService.processTspRequestForTspProfile(tspProfileName, parsedRequest);

            responseBytes = TspResponseBuilder.fromEngineResponse(response);
        } catch (TspException e) {
            responseBytes = TspResponseBuilder.buildRejection(e.getFailureInfo(), e.getClientMessage());
            log.error("TSP request failed with {}: {}", e.getFailureInfo(), e.getMessage(), e);
        } catch (NotFoundException e) {
            responseBytes = TspResponseBuilder.buildRejection(TspFailureInfo.BAD_REQUEST, "TSP profile not found.");
            log.error("TSP profile '{}' not found", tspProfileName, e);
        } catch (Exception e) {
            responseBytes = TspResponseBuilder.buildRejection(TspFailureInfo.SYSTEM_FAILURE, "An unexpected error occurred during timestamping.");
            log.error("Unexpected TSP processing failure", e);
        }

        return ResponseEntity.ok(responseBytes);
    }
}

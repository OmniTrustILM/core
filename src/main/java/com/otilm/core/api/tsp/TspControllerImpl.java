package com.otilm.core.api.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.TspController;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.aop.AuditResultOverride;
import com.otilm.core.api.tsp.parser.TspRequestParser;
import com.otilm.core.logging.LogResource;
import com.otilm.core.signing.tsa.TsaService;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class TspControllerImpl implements TspController {

    private final TsaService tsaService;

    private final AuditResultOverride auditResultOverride;

    @Autowired
    public TspControllerImpl(TsaService tsaService, AuditResultOverride auditResultOverride) {
        this.tsaService = tsaService;
        this.auditResultOverride = auditResultOverride;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.SIGNING_RECORD, affiliatedResource = Resource.TSP_PROFILE, operation = Operation.SIGN)
    public ResponseEntity<byte[]> timestamp(@LogResource(name = true, affiliated = true) String tspProfileName, byte[] request) {
        byte[] responseBytes;
        try {
            TspRequest parsedRequest = TspRequestParser.parse(request);
            TspResponse response = tsaService.processTspRequestForTspProfile(tspProfileName, parsedRequest);

            if (response instanceof TspResponse.Rejected) {
                auditResultOverride.setFailure();
            }
            responseBytes = TspResponseBuilder.fromEngineResponse(response);
        } catch (TspException e) {
            auditResultOverride.setFailure();
            responseBytes = TspResponseBuilder.buildRejection(e.getFailureInfo(), e.getClientMessage());
            log.warn("TSP request rejected with {}: {}", e.getFailureInfo(), e.getMessage());
        } catch (NotFoundException e) {
            auditResultOverride.setFailure();
            responseBytes = TspResponseBuilder.buildRejection(TspFailureInfo.BAD_REQUEST, "Resource not found. See logs for details.");
            log.warn("Resource not found while processing TSP request for profile '{}': {}", tspProfileName, e.getMessage());
        } catch (AccessDeniedException e) {
            // An authorization denial is rendered as the same generic not-found rejection as a non-existent profile so
            // a caller cannot probe which profiles exist by observing differing outcomes (enumeration defense). The
            // real cause is logged for operators but never put on the wire.
            auditResultOverride.setFailure();
            responseBytes = TspResponseBuilder.buildRejection(TspFailureInfo.BAD_REQUEST, "Resource not found. See logs for details.");
            log.warn("Access denied while processing TSP request for profile '{}': {}", tspProfileName, e.getMessage());
        } catch (Exception e) {
            auditResultOverride.setFailure();
            responseBytes = TspResponseBuilder.buildRejection(TspFailureInfo.SYSTEM_FAILURE, "An unexpected error occurred during timestamping.");
            log.error("Unexpected TSP processing failure", e);
        }

        return ResponseEntity.ok(responseBytes);
    }
}

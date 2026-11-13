package com.otilm.core.api.est;

import com.otilm.api.interfaces.core.est.EstController;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.aop.AuditOperationOverride;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * The wire endpoints of EST. The service records the EST Profile of the route in the audit record once the route is
 * resolved, because the label is {@code null} on the route without one and the audit aspect cannot read a name from a
 * {@code null} parameter. The operation of each record is declared here, except for a re-enrolment: it is named a
 * renewal here and a rekey by the service once it sees a new key.
 */
@RestController
public class EstControllerImpl implements EstController {

    private final EstExternalService estService;
    private final AuditOperationOverride auditOperationOverride;
    private final HttpServletRequest httpRequest;
    private final String certificateHeaderName;

    public EstControllerImpl(EstExternalService estService, AuditOperationOverride auditOperationOverride,
            HttpServletRequest httpRequest,
            @Value("${server.ssl.certificate-header-name}") String certificateHeaderName) {
        this.estService = estService;
        this.auditOperationOverride = auditOperationOverride;
        this.httpRequest = httpRequest;
        this.certificateHeaderName = certificateHeaderName;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.EST_PROFILE,
            operation = Operation.GET_CHAIN)
    public ResponseEntity<byte[]> getCaCertificates(String label) {
        return estService.getCaCertificates(label);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.EST_PROFILE,
            operation = Operation.EST_CSR_ATTRIBUTES)
    public ResponseEntity<byte[]> getCsrAttributes(String label) {
        return estService.getCsrAttributes(label);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.EST_PROFILE,
            operation = Operation.ISSUE)
    public ResponseEntity<byte[]> simpleEnroll(String label, @Sensitive byte[] request) {
        return estService.simpleEnroll(label, request, readCredentials());
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.EST_PROFILE,
            operation = Operation.UNKNOWN)
    public ResponseEntity<byte[]> simpleReenroll(String label, @Sensitive byte[] request) {
        auditOperationOverride.set(Operation.RENEW);
        return estService.simpleReenroll(label, request, readCredentials());
    }

    /** The audit record is written before the private key leaves, as it is for a key export. */
    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.EST_PROFILE,
            operation = Operation.EST_SERVER_KEY_GENERATION, synchronous = true)
    public ResponseEntity<byte[]> serverKeyGeneration(String label, @Sensitive byte[] request) {
        return estService.serverKeyGeneration(label, request, readCredentials());
    }

    private EstClientCredentials readCredentials() {
        return EstClientCredentials.from(httpRequest, certificateHeaderName);
    }
}

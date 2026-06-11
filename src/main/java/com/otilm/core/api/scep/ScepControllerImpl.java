package com.otilm.core.api.scep;

import com.otilm.api.exception.ScepException;
import com.otilm.api.interfaces.core.scep.ScepController;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.service.scep.ScepService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ScepControllerImpl implements ScepController {

    private ScepService scepService;

    @Autowired
    public void setScepService(ScepService scepService) {
        this.scepService = scepService;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.SCEP_PROFILE, operation = Operation.UNKNOWN)
    public ResponseEntity<Object> doGet(@LogResource(name = true, affiliated = true) String scepProfileName, String operation, String message) throws ScepException {
        return scepService.handleGet(scepProfileName, operation, message);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.SCEP_PROFILE, operation = Operation.UNKNOWN)
    public ResponseEntity<Object> doPost(@LogResource(name = true, affiliated = true) String scepProfileName, String operation, byte[] request) throws ScepException {
        return scepService.handlePost(scepProfileName, operation, request);
    }
}

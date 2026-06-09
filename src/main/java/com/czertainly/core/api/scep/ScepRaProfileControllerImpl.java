package com.czertainly.core.api.scep;

import com.otilm.api.exception.ScepException;
import com.otilm.api.interfaces.core.scep.ScepRaProfileController;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.service.scep.ScepService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ScepRaProfileControllerImpl implements ScepRaProfileController {

    private ScepService scepService;

    @Autowired
    public void setScepService(ScepService scepService) {
        this.scepService = scepService;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.SCEP_PROFILE, operation = Operation.UNKNOWN)
    public ResponseEntity<Object> doGet(String raProfileName, String operation, String message) throws ScepException {
        return scepService.handleGet(raProfileName, operation, message);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.SCEP_PROFILE, operation = Operation.UNKNOWN)
    public ResponseEntity<Object> doPost(String raProfileName, String operation, byte[] request) throws ScepException {
        return scepService.handlePost(raProfileName, operation, request);
    }
}

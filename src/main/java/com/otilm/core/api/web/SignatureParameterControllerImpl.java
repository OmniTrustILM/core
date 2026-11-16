package com.otilm.core.api.web;

import com.otilm.api.interfaces.core.web.SignatureParameterController;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.signing.parameters.SignatureFamilyParameterGroupsDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.service.SignatureParameterExternalService;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignatureParameterControllerImpl implements SignatureParameterController {

    private final SignatureParameterExternalService signatureParameterService;

    @Autowired
    public SignatureParameterControllerImpl(SignatureParameterExternalService signatureParameterService) {
        this.signatureParameterService = signatureParameterService;
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_PROFILE, operation = Operation.LIST)
    public List<SignatureFamilyParameterGroupsDto> listSignatureParameterGroups() {
        return signatureParameterService.listSignatureParameterGroups();
    }
}

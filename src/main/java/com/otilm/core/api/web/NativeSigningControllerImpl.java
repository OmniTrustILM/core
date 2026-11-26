package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.NativeSigningController;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentResponseDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.NativeSigningExternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import java.util.UUID;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NativeSigningControllerImpl implements NativeSigningController {

    private final NativeSigningExternalService nativeSigningService;

    public NativeSigningControllerImpl(NativeSigningExternalService nativeSigningService) {
        this.nativeSigningService = nativeSigningService;
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_RECORD,
            affiliatedResource = Resource.SIGNING_PROFILE, operation = Operation.SIGN)
    public SignDocumentResponseDto signDocument(@LogResource(uuid = true, affiliated = true) UUID signingProfileUuid,
            @Sensitive SignDocumentRequestDto request) throws NotFoundException, SigningEngineException {
        return nativeSigningService.signDocument(SecuredUUID.fromUUID(signingProfileUuid), request);
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SIGNING_RECORD,
            affiliatedResource = Resource.SIGNING_PROFILE, operation = Operation.SIGN)
    public SignRawResponseDto signRaw(@LogResource(uuid = true, affiliated = true) UUID signingProfileUuid,
            @Sensitive SignRawRequestDto request) throws NotFoundException, SigningEngineException {
        return nativeSigningService.signRaw(SecuredUUID.fromUUID(signingProfileUuid), request);
    }
}

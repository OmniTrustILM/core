package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentResponseDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.signing.engine.error.SigningEngineException;

public interface NativeSigningExternalService {

    /**
     * Signs every document of the request at the Signing Profile's level in one run. The run succeeds or fails as a
     * whole and records its documents only on success.
     *
     * @throws NotFoundException if no Signing Profile has the UUID
     */
    SignDocumentResponseDto signDocument(SecuredUUID signingProfileUuid, SignDocumentRequestDto request)
            throws NotFoundException, SigningEngineException;
}

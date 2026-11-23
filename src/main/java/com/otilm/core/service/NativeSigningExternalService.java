package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignDocumentResponseDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawResponseDto;
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

    /**
     * Signs every digest of the request with the Signing Profile's key in one run. The run succeeds or fails as a whole
     * and records its digests only on success.
     *
     * @throws NotFoundException if no Signing Profile has the UUID
     * @throws ValidationException if the profile cannot serve native raw signing, or the request pins another
     * certificate than the profile's signing certificate
     */
    SignRawResponseDto signRaw(SecuredUUID signingProfileUuid, SignRawRequestDto request)
            throws NotFoundException, SigningEngineException;
}

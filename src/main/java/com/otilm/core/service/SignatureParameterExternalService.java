package com.otilm.core.service;

import com.otilm.api.model.core.signing.parameters.SignatureFamilyParameterGroupsDto;
import java.util.List;

public interface SignatureParameterExternalService {

    List<SignatureFamilyParameterGroupsDto> listSignatureParameterGroups();
}

package com.otilm.core.service.impl;

import com.otilm.api.model.core.signing.parameters.SignatureFamilyParameterGroupsDto;
import com.otilm.api.model.core.signing.parameters.SignatureParameterGroupTable;
import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.service.SignatureParameterExternalService;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class SignatureParameterServiceImpl implements SignatureParameterExternalService {

    @Override
    @AnyPrincipalEndpoint
    public List<SignatureFamilyParameterGroupsDto> listSignatureParameterGroups() {
        return SignatureParameterGroupTable.forEveryFamily();
    }
}

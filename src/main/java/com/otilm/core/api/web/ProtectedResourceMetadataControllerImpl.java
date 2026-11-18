package com.otilm.core.api.web;

import com.otilm.api.interfaces.core.web.ProtectedResourceMetadataController;
import com.otilm.api.model.core.auth.ProtectedResourceMetadataDto;
import com.otilm.core.service.ProtectedResourceMetadataExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

/**
 * The anonymous protected resource metadata surface. Like branding it is read-only by construction and deliberately not
 * audit-logged: an unauthenticated caller would otherwise be able to fill the audit log at will.
 */
@RestController
public class ProtectedResourceMetadataControllerImpl implements ProtectedResourceMetadataController {

    private ProtectedResourceMetadataExternalService metadataService;

    @Autowired
    public void setMetadataService(ProtectedResourceMetadataExternalService metadataService) {
        this.metadataService = metadataService;
    }

    @Override
    public ProtectedResourceMetadataDto getProtectedResourceMetadata() {
        return metadataService.getProtectedResourceMetadata();
    }
}

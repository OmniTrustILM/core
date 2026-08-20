package com.otilm.core.api.web;

import com.otilm.api.interfaces.core.web.BrandingController;
import com.otilm.api.model.core.branding.PublicBrandingDto;
import com.otilm.core.service.BrandingExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

/**
 * The anonymous branding surface. The controller interface declares a single {@code GET}, so the path is read-only by
 * construction. Deliberately not audit-logged: an unauthenticated caller would otherwise be able to fill the audit log
 * at will, with every entry naming the anonymous user.
 */
@RestController
public class BrandingControllerImpl implements BrandingController {

    private BrandingExternalService brandingService;

    @Autowired
    public void setBrandingService(BrandingExternalService brandingService) {
        this.brandingService = brandingService;
    }

    @Override
    public PublicBrandingDto getBranding() {
        return brandingService.getPublicBranding();
    }
}

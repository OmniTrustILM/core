package com.otilm.core.api.web;

import com.otilm.api.interfaces.core.web.BrandingController;
import com.otilm.api.model.core.branding.PublicBrandingDto;
import com.otilm.core.service.BrandingExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

/**
 * The anonymous branding surface. Read-only by construction: the controller interface declares a single {@code GET}, so
 * every other method against the path is refused by Spring's handler mapping rather than by a check that could be
 * forgotten.
 *
 * <p>
 * Deliberately not audit-logged. The login page calls this before anyone has authenticated, so every entry would name
 * the anonymous user, and an unauthenticated caller would be able to fill the audit log at will.
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

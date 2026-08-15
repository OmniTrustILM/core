package com.otilm.core.service;

import com.otilm.api.model.core.branding.PublicBrandingDto;

public interface BrandingExternalService {

    /**
     * Get the branding an unauthenticated client is allowed to read, so the login page can render the operator's
     * identity before anyone signs in.
     *
     * @return branding available anonymously {@link com.otilm.api.model.core.branding.PublicBrandingDto}
     */
    PublicBrandingDto getPublicBranding();
}

package com.otilm.core.service;

import com.otilm.core.security.authz.SecurityFilter;

public interface GroupInternalService extends ResourceExtensionService {

    /**
     * Get the number of groups per user for dashboard
     * @return Number of groups
     */
    Long statisticsGroupCount(SecurityFilter filter);
}

package com.otilm.core.service;

import com.otilm.api.model.core.settings.PlatformSettingsDto;

public interface SettingInternalService {

    /**
     * Re-seed the in-memory settings cache from the database. Used by tests to truncate and reset state.
     */
    void refreshCache();

    /**
     * Internal platform-settings read for engine/issuance code paths.
     *
     * @return platform settings
     * {@link com.otilm.api.model.core.settings.PlatformSettingsDto}
     */
    PlatformSettingsDto getPlatformSettingsInternal();

}

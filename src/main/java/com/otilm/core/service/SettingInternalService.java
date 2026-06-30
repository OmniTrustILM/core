package com.otilm.core.service;

public interface SettingInternalService {

    /**
     * Re-seed the in-memory settings cache from the database. Used by tests to truncate and reset state.
     */
    void refreshCache();

}

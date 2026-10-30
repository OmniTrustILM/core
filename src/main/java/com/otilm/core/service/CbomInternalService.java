package com.otilm.core.service;

import com.otilm.api.exception.CbomRepositoryException;

public interface CbomInternalService extends ResourceExtensionService {

    /**
     * Synchronize CBOMs from the CBOM repository. This version is intended for use by scheduled jobs where no
     * authorization context is available.
     *
     * @return A string message indicating the result of the synchronization process
     * @throws CbomRepositoryException if there are problems accessing the CBOM repository
     */
    String sync() throws CbomRepositoryException;

    /**
     * Reconcile Core against the CBOM repository's whole listing rather than against the window since the last
     * successful sync. Intended for the weekly scheduled job; it reads the same feed, stores the same way and respects
     * the same tombstones, and it neither advances nor holds back the hourly sync's watermark.
     *
     * @return A string message indicating the result of the reconciliation
     * @throws CbomRepositoryException if there are problems accessing the CBOM repository
     */
    String reconcile() throws CbomRepositoryException;

    /**
     * Check whether the CBOM repository client configuration is present.
     *
     * @return {@code true} if the CBOM repository base URL/client configuration is present and the client is considered
     * configured, {@code false} otherwise
     */
    boolean isCbomRepositoryClientConfigured();
}

package com.otilm.core.service;

import java.util.UUID;

public interface ListViewInternalService {

    /**
     * Removes every view of a user that no longer exists. There is no foreign key to cascade from - users live in the
     * identity service - so the rows are cleaned up where the platform learns of the deletion, in
     * {@link UserManagementExternalService#deleteUser(String)}.
     *
     * @return the number of views removed
     */
    int deleteViewsOfUser(UUID userUuid);
}

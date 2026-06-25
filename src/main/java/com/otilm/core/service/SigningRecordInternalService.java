package com.otilm.core.service;

import java.util.UUID;

public interface SigningRecordInternalService {

    boolean doesSigningRecordExistInternal(UUID uuid, int version);

    boolean doesSigningRecordExistForProfileInternal(UUID signingProfileUuid);
}

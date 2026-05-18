package com.czertainly.core.events.transaction;

public record UserCertificateAssignedEvent(String userUuid, String certificateUuid, String certificateFingerprint) {}

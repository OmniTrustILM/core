package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.core.certificate.CertificateEventHistoryDto;

import java.util.List;
import java.util.UUID;

public interface CertificateEventHistoryExternalService {

    List<CertificateEventHistoryDto> getCertificateEventHistory(UUID uuid) throws NotFoundException;
}

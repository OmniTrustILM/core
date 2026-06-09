package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateEventHistoryDto;

import java.util.List;
import java.util.UUID;

public interface CertificateEventHistoryExternalService {

    List<CertificateEventHistoryDto> getCertificateEventHistory(UUID uuid) throws NotFoundException;
}

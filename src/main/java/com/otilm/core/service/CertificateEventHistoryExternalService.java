package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateEventHistoryDto;
import com.otilm.core.security.authz.SecuredUUID;

import java.util.List;

public interface CertificateEventHistoryExternalService {

    List<CertificateEventHistoryDto> getCertificateEventHistory(SecuredUUID uuid) throws NotFoundException;
}

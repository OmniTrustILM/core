package com.czertainly.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventHistoryDto;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateEventHistory;
import com.czertainly.core.dao.repository.CertificateEventHistoryRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.events.transaction.UpdateCertificateHistoryEvent;
import com.otilm.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.service.CertificateEventHistoryExternalService;
import com.czertainly.core.service.CertificateEventHistoryInternalService;
import com.czertainly.core.util.MetaDefinitions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.HashMap;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class CertificateEventHistoryServiceImpl implements CertificateEventHistoryExternalService, CertificateEventHistoryInternalService {

    private static final Logger logger = LoggerFactory.getLogger(CertificateEventHistoryServiceImpl.class);

    private CertificateRepository certificateRepository;
    private CertificateEventHistoryRepository certificateEventHistoryRepository;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setCertificateEventHistoryRepository(CertificateEventHistoryRepository certificateEventHistoryRepository) {
        this.certificateEventHistoryRepository = certificateEventHistoryRepository;
    }

    @Override
    public void addEventHistory(UUID certificateUuid, CertificateEvent event, CertificateEventStatus status, String message, HashMap<String, Object> additionalInformation) {
        addEventHistory(certificateUuid, event, status, message, MetaDefinitions.serialize(additionalInformation));
    }

    @Override
    public void addEventHistory(UUID certificateUuid, CertificateEvent event, CertificateEventStatus status, String message, String additionalInformation) {
        CertificateEventHistory history = new CertificateEventHistory();
        history.setEvent(event);
        history.setCertificateUuid(certificateUuid);
        history.setStatus(status);
        history.setAdditionalInformation(additionalInformation);
        history.setMessage(message);
        certificateEventHistoryRepository.save(history);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void addEventHistorySurvivingRollback(UUID certificateUuid, CertificateEvent event, CertificateEventStatus status, String message, String additionalInformation) {
        addEventHistory(certificateUuid, event, status, message, additionalInformation);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public List<CertificateEventHistoryDto> getCertificateEventHistory(UUID uuid) throws NotFoundException {
        Certificate certificate = certificateRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Certificate.class, uuid));
        return certificateEventHistoryRepository.findByCertificateOrderByCreatedDesc(certificate).stream().map(CertificateEventHistory::mapToDto).toList();
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleUpdateCertificateHistoryEvent(UpdateCertificateHistoryEvent event) {
        logger.debug("UpdateCertificateHistoryEvent event handled. Certificate UUID: {}", event.certificateUuid());
        addEventHistory(event.certificateUuid(), event.certificateEvent(), event.eventStatus(), event.message(), event.detail());
    }

}

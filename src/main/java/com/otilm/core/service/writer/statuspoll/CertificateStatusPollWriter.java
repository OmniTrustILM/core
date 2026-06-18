package com.otilm.core.service.writer.statuspoll;

import com.otilm.core.dao.entity.CertificateStatusPoll;
import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.service.handler.authority.CertificateOperation;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Short transactional writes against {@code certificate_status_poll}. The repository carries no
 * {@code @Transactional} (per the repository rule); every guarded write goes through this bean in its
 * own {@code REQUIRES_NEW} transaction so it composes inside, but does not extend, the sweeper's
 * advisory-lock transaction or the listener's locked-certificate transaction.
 */
@Component
public class CertificateStatusPollWriter {

    private final CertificateStatusPollRepository pollRepository;

    public CertificateStatusPollWriter(CertificateStatusPollRepository pollRepository) {
        this.pollRepository = pollRepository;
    }

    /**
     * Records a new in-flight async operation due for its first poll at {@code nextPollAt}. Idempotent
     * on {@code certificateUuid} (unique): a concurrent second schedule for a certificate already polling
     * loses the unique-constraint race and is swallowed rather than surfaced as an error.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void schedule(UUID certificateUuid, CertificateOperation operation, OffsetDateTime nextPollAt) {
        if (pollRepository.existsByCertificateUuid(certificateUuid)) {
            return;
        }
        CertificateStatusPoll poll = new CertificateStatusPoll();
        poll.setCertificateUuid(certificateUuid);
        poll.setOperation(operation);
        poll.setAttempt(0);
        poll.setNextPollAt(nextPollAt);
        try {
            pollRepository.saveAndFlush(poll);
        } catch (DataIntegrityViolationException e) {
            // Lost the unique(certificate_uuid) race with a concurrent schedule — already polling, nothing to do.
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void delete(UUID certificateUuid) {
        pollRepository.deleteByCertificateUuid(certificateUuid);
    }
}

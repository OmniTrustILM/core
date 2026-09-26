package com.otilm.core.service.scep.impl;

import com.otilm.core.dao.entity.scep.ScepTransaction;
import com.otilm.core.dao.repository.scep.ScepTransactionRepository;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Commits SCEP registration tracking in its own transaction, independent of the request's outer transaction.
 *
 * <p>
 * Registration completion publishes the ISSUE message non-transactionally (a direct JMS send), so any tracking that
 * only becomes durable when the request's outer transaction commits could be rolled back after the message is already
 * on the broker — the certificate would then issue while the client's transactionId resolves to nothing. The poll
 * mapping is therefore recorded here, under {@code REQUIRES_NEW}, before the publish; a rejected completion (nothing
 * published) discards it again. A separate bean is required because {@code REQUIRES_NEW} advice is skipped on
 * self-invocation within the completing service.
 */
@Component
public class ScepRegistrationTrackingWriter {

    private ScepTransactionRepository scepTransactionRepository;

    @Autowired
    public void setScepTransactionRepository(ScepTransactionRepository scepTransactionRepository) {
        this.scepTransactionRepository = scepTransactionRepository;
    }

    /**
     * Records the transactionId -> certificate mapping the client polls against, committed before the ISSUE publish.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordPollMapping(String transactionId, UUID certificateUuid, UUID scepProfileUuid) {
        ScepTransaction scepTransaction = new ScepTransaction();
        scepTransaction.setTransactionId(transactionId);
        scepTransaction.setCertificateUuid(certificateUuid);
        scepTransaction.setScepProfileUuid(scepProfileUuid);
        scepTransactionRepository.save(scepTransaction);
    }

    /** Drops a mapping staged for a completion that was then rejected before anything was published. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void discardPollMapping(String transactionId, UUID scepProfileUuid) {
        scepTransactionRepository.deleteByTransactionIdAndScepProfileUuid(transactionId, scepProfileUuid);
    }
}

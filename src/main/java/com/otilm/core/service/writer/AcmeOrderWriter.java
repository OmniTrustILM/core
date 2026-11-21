package com.otilm.core.service.writer;

import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writer bean for what an ACME order records about the certificate requested for it.
 */
@Service
public class AcmeOrderWriter {

    private final AcmeOrderRepository acmeOrderRepository;

    public AcmeOrderWriter(AcmeOrderRepository acmeOrderRepository) {
        this.acmeOrderRepository = acmeOrderRepository;
    }

    /**
     * Records why the certificate failed to issue on the ACME order it was requested for, if any. The order reports the
     * reason to its client once it is invalid, so the reason must be one the client may read.
     */
    @Transactional
    public void recordIssuanceFailure(UUID certificateUuid, String reason) {
        acmeOrderRepository.recordErrorDetailByCertificate(certificateUuid, reason);
    }
}

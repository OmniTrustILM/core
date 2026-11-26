package com.otilm.core.service.renewal;

import com.otilm.core.dao.entity.Certificate;

/** Re-evaluates whether the authority's renewal information is fetched for a certificate. */
public interface RenewalEnrolmentHook {

    void enrol(Certificate certificate);
}

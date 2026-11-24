package com.otilm.core.service.renewal;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import java.util.UUID;

/**
 * The only writer of renewal windows. Each write locks the certificate's renewal row, applies
 * {@link RenewalWindowRules} and records a change of the window in the certificate history.
 */
public interface RenewalWindowWriter {

    /** Applies the write to the certificate; a certificate that does not exist is skipped. */
    void write(UUID certificateUuid, WindowWrite write);

    /**
     * Applies the advice of the authority, {@link WindowWrite.Authority} or {@link WindowWrite.AuthorityNoAdvice}, when
     * the certificate still takes it: its RA profile uses the authority's renewal information and it has no issued
     * successor. Answers whether it did.
     */
    boolean writeAuthorityAdvice(UUID certificateUuid, WindowWrite advice);

    /**
     * Sets the policy window on the issued, unexpired, non-archived certificates of the RA profile whose window is
     * missing or came from the policy, or removes the policy windows when the policy is off.
     */
    void recomputePolicy(RaProfile raProfile);

    /**
     * Drops the authority windows of the RA profile's certificates, as when their RA profile was reset: a live
     * certificate falls back to the policy window of its RA profile, or to none.
     */
    void dropAuthorityWindows(RaProfile raProfile);

    /** Gives a newly issued certificate the window of its RA profile policy. */
    void onIssued(Certificate certificate);

    /**
     * Treats a certificate whose RA profile was assigned, changed or removed as newly issued under its current RA
     * profile: a policy or authority window is replaced by the new policy window, or removed; a forced window stays.
     */
    void onRaProfileChanged(Certificate certificate, RaProfile oldProfile);
}

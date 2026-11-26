package com.otilm.core.service.renewal.auto;

import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.core.dao.entity.Certificate;

/**
 * Renews a certificate in one {@link AutoRenewalMode}. {@link AutoRenewalAction} calls it after claiming the firing,
 * outside any transaction, with the certificate detached; the handler reads what it needs and stores what it does in
 * short transactions of its own. It applies the unit guards of the units it tracks itself and stores the successors it
 * starts; for {@link AutoRenewalMode#ILM_KEY} the action has already applied them to the certificate's renewal row.
 */
public interface AutoRenewalHandler {

    AutoRenewalMode mode();

    void renew(Certificate certificate, RenewalContext context) throws AutoRenewalException;
}

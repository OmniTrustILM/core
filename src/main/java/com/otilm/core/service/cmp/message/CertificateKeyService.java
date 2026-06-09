package com.otilm.core.service.cmp.message;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.provider.CzertainlyProvider;
import com.otilm.core.provider.key.CzertainlyPrivateKey;

public interface CertificateKeyService {

    /**
     * @param cmpProfileName name of CMP profile
     * @param signingCertificate the certificate used for signing operations
     * @return provider for given CMP profile
     */
    CzertainlyProvider getProvider(String cmpProfileName, Certificate signingCertificate) throws NotFoundException;

    /**
     * @param certificate certificate
     * @return private key for given certificate
     */
    CzertainlyPrivateKey getPrivateKey(Certificate certificate);

}

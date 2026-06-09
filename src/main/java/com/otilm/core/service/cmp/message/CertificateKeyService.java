package com.otilm.core.service.cmp.message;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.provider.PlatformProvider;
import com.otilm.core.provider.key.PlatformPrivateKey;

public interface CertificateKeyService {

    /**
     * @param cmpProfileName name of CMP profile
     * @param signingCertificate the certificate used for signing operations
     * @return provider for given CMP profile
     */
    PlatformProvider getProvider(String cmpProfileName, Certificate signingCertificate) throws NotFoundException;

    /**
     * @param certificate certificate
     * @return private key for given certificate
     */
    PlatformPrivateKey getPrivateKey(Certificate certificate);

}

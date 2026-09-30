package com.otilm.core.service.handler;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.repository.TokenProfileRepository;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Whether a certificate can be downloaded with its private key, for showing. A certificate without content, not issued
 * yet, is unavailable. Otherwise the key's token profile is read for what it exports from the recorded answer only,
 * without ever asking its connector. A profile whose answer is not recorded yet shows as available: the download asks
 * the connector, records its answer, and refuses a key the profile does not export.
 */
@Component
public class KeystoreAvailability {

    private final KeyTransferCapabilityService capabilityService;
    private final TokenProfileRepository tokenProfileRepository;

    public KeystoreAvailability(KeyTransferCapabilityService capabilityService,
            TokenProfileRepository tokenProfileRepository) {
        this.capabilityService = capabilityService;
        this.tokenProfileRepository = tokenProfileRepository;
    }

    /**
     * Whether the certificate's key pair can be exported now, through a token profile that exports its algorithm.
     *
     * @param certificate the certificate
     * @return whether a keystore download of the certificate can succeed, the caller's permissions aside
     */
    public boolean of(Certificate certificate) {
        if (certificate.getCertificateContent() == null) {
            return false;
        }
        return CertificateKeyPair
                .of(certificate)
                .filter(pair -> pair.holds(certificate) && pair.exportableNow())
                .filter(this::exported)
                .isPresent();
    }

    private boolean exported(CertificateKeyPair pair) {
        CryptographicKey key = pair.key();
        if (key.getTokenProfileUuid() == null) {
            return false;
        }
        return tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(key.getTokenProfileUuid(),
                        key.getTokenInstanceReferenceUuid())
                .map(profile -> capabilityService
                        .recordedExportableKeyTypes(profile)
                        .map(exportableKeyTypes -> exportableKeyTypes
                                .getOrDefault(KeyRequestType.KEY_PAIR, Set.of())
                                .contains(pair.privateItem().getKeyAlgorithm()))
                        .orElse(true))
                .orElse(false);
    }
}

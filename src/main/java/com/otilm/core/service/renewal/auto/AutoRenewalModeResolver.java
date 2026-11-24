package com.otilm.core.service.renewal.auto;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateLocation;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.Location;
import java.util.List;

/**
 * Decides how a certificate is renewed automatically. A key-generating location renews the certificate by itself and
 * wins over a key the platform holds; a held key is renewed with the stored certificate request; without either the
 * certificate cannot be renewed automatically.
 */
public final class AutoRenewalModeResolver {

    public static final String NO_KEY = "no key-generating location holds the certificate and the platform does not "
            + "hold its private key";
    public static final String NO_STORED_REQUEST = "no stored certificate request";

    private AutoRenewalModeResolver() {
    }

    /** The mode of a certificate, with the reason when it is {@link AutoRenewalMode#NONE}. */
    public record ModeDecision(AutoRenewalMode mode, String blockedReason) {
    }

    public static ModeDecision resolve(Certificate certificate) {
        return resolve(certificate, false);
    }

    /**
     * @param locationRenewed whether locations renewed the certificate already: they replace it in their location, so
     * it may sit in none while their renewals are tracked
     */
    public static ModeDecision resolve(Certificate certificate, boolean locationRenewed) {
        if (locationRenewed || certificate.getLocations().stream().anyMatch(AutoRenewalModeResolver::isKeyGenerating)) {
            return new ModeDecision(AutoRenewalMode.LOCATION, null);
        }
        if (!holdsPrivateKey(certificate)) {
            return new ModeDecision(AutoRenewalMode.NONE, NO_KEY);
        }
        CertificateRequestEntity request = certificate.getCertificateRequest();
        if (request == null || request.getContent() == null) {
            return new ModeDecision(AutoRenewalMode.NONE, NO_STORED_REQUEST);
        }
        return new ModeDecision(AutoRenewalMode.ILM_KEY, null);
    }

    /**
     * An enabled location that manages keys and holds the CSR and push attributes of the certificate's entry, so it can
     * generate a new key and request, renew and push the result by itself.
     */
    public static boolean isKeyGenerating(CertificateLocation certificateLocation) {
        Location location = certificateLocation.getLocation();
        return location != null && Boolean.TRUE.equals(location.getEnabled()) && location.isSupportKeyManagement()
                && isPresent(certificateLocation.getCsrAttributes())
                && isPresent(certificateLocation.getPushAttributes());
    }

    private static boolean isPresent(List<?> attributes) {
        return attributes != null && !attributes.isEmpty();
    }

    private static boolean holdsPrivateKey(Certificate certificate) {
        CryptographicKey key = certificate.getKey();
        return certificate.getKeyUuid() != null && key != null
                && key
                        .getItems()
                        .stream()
                        .anyMatch(item -> item.getType() == KeyType.PRIVATE_KEY && item.getState() == KeyState.ACTIVE);
    }
}

package com.otilm.core.signing.engine.resolver;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Dereferences a cached {@link SigningSchemeModel}'s UUIDs into the transient {@link ResolvedManagedScheme}. Shared by
 * every workflow's resolver, because the scheme is a property of the profile rather than the workflow.
 */
@Component
public class ManagedSchemeResolver {

    private final CertificateInternalService certificateService;
    private final CryptographicKeyInternalService cryptographicKeyService;

    public ManagedSchemeResolver(CertificateInternalService certificateService,
            CryptographicKeyInternalService cryptographicKeyService) {
        this.certificateService = certificateService;
        this.cryptographicKeyService = cryptographicKeyService;
    }

    /**
     * Resolves a static-key managed scheme into its certificate, key items and validated chain.
     *
     * @throws SigningEngineException {@code MISCONFIGURED} when the scheme is not static-key managed, or when the
     * certificate, a key item or the chain is missing or unusable
     */
    public ResolvedManagedScheme resolve(String profileName, SigningSchemeModel scheme) throws SigningEngineException {
        if (!(scheme instanceof StaticKeyManagedSigning(UUID certificateUuid, List<RequestAttribute> signingOperationAttributes))) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing Profile '%s' uses an unsupported signing scheme: %s"
                            .formatted(profileName, scheme.getClass().getSimpleName()),
                    "The system is misconfigured.");
        }

        SigningCertificate certificate;
        try {
            certificate = certificateService.getSigningCertificate(certificateUuid);
        } catch (NotFoundException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing certificate not found: " + certificateUuid, e,
                    "Signing key certificate could not be found.");
        }

        List<CryptographicKeyItemOperationModel> keyItems = new ArrayList<>();
        for (UUID keyItemUuid : certificate.keyItemUuids()) {
            try {
                keyItems.add(cryptographicKeyService.getKeyItemModel(keyItemUuid));
            } catch (NotFoundException e) {
                throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                        "Key item %s referenced by signing certificate %s not found."
                                .formatted(keyItemUuid, certificateUuid),
                        e, "Signing key could not be found.");
            }
        }

        List<X509Certificate> chain;
        try {
            chain = certificateService.getCertificateChainForSigning(certificateUuid, true);
        } catch (CertificateException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Failed to decode certificate chain for %s. %s".formatted(certificateUuid, e.getLocalizedMessage()),
                    e, "Certificate chain could not be parsed.");
        }
        if (chain.isEmpty()) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing certificate or its chain is not available for UUID %s.".formatted(certificateUuid),
                    "Signing key certificate could not be found.");
        }

        CertificateChain certificateChain;
        try {
            certificateChain = CertificateChain.of(chain);
        } catch (IllegalArgumentException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing Profile '%s' has an invalid certificate chain for %s: %s"
                            .formatted(profileName, certificateUuid, e.getMessage()),
                    e, "The system is misconfigured.");
        }

        return new ResolvedStaticKeyManagedSigning(certificate, List.copyOf(keyItems), certificateChain,
                signingOperationAttributes);
    }
}

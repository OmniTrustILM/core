package com.otilm.core.service.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.certificate.KeystoreSource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateChainService;
import com.otilm.core.service.CertificateInternalService;
import java.util.Base64;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads what a keystore download needs from the inventory, in one transaction. It is not read-only: completing the
 * chain records each issuer it finds, in the inventory or over AIA, and clears an issuer reference it finds dangling.
 */
@Component
public class CertificateKeystoreSource {

    public static final String NOT_ISSUED = "Cannot download the certificate, certificate is not issued.";
    public static final String NO_PRIVATE_KEY = "Certificate %s has no private key in the platform.";
    public static final String KEY_MISMATCH = "The key of certificate %s does not hold its public key.";

    private final CertificateInternalService certificateService;
    private final CertificateChainService chainService;

    public CertificateKeystoreSource(CertificateInternalService certificateService,
            CertificateChainService chainService) {
        this.certificateService = certificateService;
        this.chainService = chainService;
    }

    /**
     * The certificate's key pair and chain. The private key item becomes the audit record's affiliated object as soon
     * as it is found, so a refusal after that names it too.
     *
     * @param uuid the certificate
     * @return what the download needs
     * @throws NotFoundException if the certificate does not exist, or its key holds no private key
     */
    @Transactional(rollbackFor = Exception.class)
    public KeystoreSource read(SecuredUUID uuid) throws NotFoundException {
        Certificate certificate = certificateService.getCertificateEntity(uuid);
        if (certificate.getCertificateContent() == null) {
            throw new ValidationException(NOT_ISSUED);
        }
        CertificateKeyPair pair = CertificateKeyPair
                .of(certificate)
                .orElseThrow(() -> new NotFoundException(NO_PRIVATE_KEY.formatted(certificate.getUuid())));
        LoggingHelper
                .putLogResourceInfo(Resource.CRYPTOGRAPHIC_KEY_ITEM, true, pair.privateItem().getUuid().toString(),
                        pair.privateItem().getName());
        if (!pair.holds(certificate)) {
            throw new ValidationException(ValidationError.create(KEY_MISMATCH.formatted(certificate.getUuid())));
        }
        List<Certificate> links = chainService.getCertificateChainInternal(certificate, true);
        boolean complete = chainService.completeCertificateChain(links.getLast(), links);
        List<byte[]> chain = links.stream().map(link -> Base64.getDecoder().decode(link.getContentData())).toList();
        return new KeystoreSource(certificate.getUuid(), certificate.getCommonName(), pair.key().getUuid(),
                pair.key().getName(), pair.privateItem().getUuid(), chain.getFirst(), issuersOf(chain, complete));
    }

    /**
     * The chain after its leaf, without the self-signed issuer that ends a complete chain: the trust anchor stays with
     * the recipient.
     */
    private static List<byte[]> issuersOf(List<byte[]> chain, boolean complete) {
        List<byte[]> issuers = chain.subList(1, chain.size());
        if (complete && !issuers.isEmpty()) {
            issuers = issuers.subList(0, issuers.size() - 1);
        }
        return List.copyOf(issuers);
    }
}

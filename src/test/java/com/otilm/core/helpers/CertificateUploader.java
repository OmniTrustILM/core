package com.otilm.core.helpers;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.UuidDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.impl.CertificateServiceImpl;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static com.otilm.core.util.builders.CertificateUpdateObjectsDtoBuilder.aCertificateUpdateObjectsRequest;
import static com.otilm.core.util.builders.UploadCertificateRequestDtoBuilder.anUploadCertificateRequest;

/**
 * Uploads X.509 certificates into the platform through {@link CertificateServiceImpl} and exposes the
 * follow-up actions a test typically needs (marking a CA trusted, running validation). Generation of
 * the certificate is the caller's concern (see {@code CertificateGeneratorHelper}); this class owns the
 * persistence boundary only.
 *
 * <p>Depends on the concrete {@code CertificateServiceImpl} rather than either split interface because
 * it calls methods from both the external face ({@code uploadSync}, {@code updateCertificateObjects},
 * {@code getCertificateValidationResult}) and the internal face ({@code getCertificateEntity}).</p>
 */
@Component
public class CertificateUploader {

    private final CertificateServiceImpl certificateService;

    public CertificateUploader(CertificateServiceImpl certificateService) {
        this.certificateService = certificateService;
    }

    public Certificate upload(X509Certificate certificate) throws CertificateException, AlreadyExistException, NotFoundException {
        UuidDto uploaded = certificateService.uploadSync(anUploadCertificateRequest().withCertificate(certificate).build());
        return certificateService.getCertificateEntity(SecuredUUID.fromString(uploaded.getUuid()));
    }

    public void markTrusted(Certificate certificate) throws NotFoundException, CertificateOperationException, AttributeException {
        certificateService.updateCertificateObjects(certificate.getSecuredUuid(), aCertificateUpdateObjectsRequest().withTrustedCa(true).build());
    }

    public void validate(Certificate certificate) throws NotFoundException {
        certificateService.getCertificateValidationResult(certificate.getSecuredUuid());
    }
}

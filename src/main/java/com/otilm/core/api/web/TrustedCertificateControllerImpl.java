package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.TrustedCertificateController;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateAddRequestDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateApplyRequestDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateBulkResultDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateRemoveRequestDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateUpdateRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.TrustedCertificateExternalService;
import java.security.cert.CertificateException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller implementation for trusted certificate management operations.
 */
@RestController
@RequiredArgsConstructor
public class TrustedCertificateControllerImpl implements TrustedCertificateController {

    private final TrustedCertificateExternalService trustedCertificateService;

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.TRUSTED_CERTIFICATE, operation = Operation.LIST)
    public List<TrustedCertificateDto> listTrustedCertificates() {
        return trustedCertificateService.listTrustedCertificates();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.TRUSTED_CERTIFICATE, operation = Operation.DETAIL)
    public TrustedCertificateDto getTrustedCertificate(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return trustedCertificateService.getTrustedCertificate(SecuredUUID.fromString(uuid));
    }

    @Override
    public TrustedCertificateBulkResultDto addTrustedCertificates(TrustedCertificateAddRequestDto request)
            throws CertificateException {
        return trustedCertificateService.addTrustedCertificates(request);
    }

    @Override
    public TrustedCertificateBulkResultDto updateTrustedCertificates(TrustedCertificateUpdateRequestDto request) {
        return trustedCertificateService.updateTrustedCertificates(request);
    }

    @Override
    public TrustedCertificateBulkResultDto removeTrustedCertificates(TrustedCertificateRemoveRequestDto request) {
        return trustedCertificateService.removeTrustedCertificates(request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.TRUSTED_CERTIFICATE, operation = Operation.DELETE)
    public void deleteTrustedCertificate(@LogResource(uuid = true) String uuid) throws NotFoundException {
        trustedCertificateService.deleteTrustedCertificate(SecuredUUID.fromString(uuid));
    }

    @Override
    public TrustedCertificateBulkResultDto applyTrustedCertificates(TrustedCertificateApplyRequestDto request) {
        return trustedCertificateService.applyTrustedCertificates(request);
    }

    @Override
    public TrustedCertificatePlatformDto getPlatformTrust() {
        return trustedCertificateService.getPlatformTrust();
    }

}

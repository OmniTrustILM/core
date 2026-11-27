package com.otilm.core.api.web.v2;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.v2.TrustedCertificateController;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateAddRequestDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateApplyRequestDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateBulkResultDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificatePlatformDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateRemoveRequestDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateUpdateRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.v2.TrustedCertificateExternalService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RestController;

@RestController("trustedCertificateControllerV2")
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
    public TrustedCertificateBulkResultDto addTrustedCertificates(TrustedCertificateAddRequestDto request) {
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
    public TrustedCertificateBulkResultDto applyTrustedCertificates(TrustedCertificateApplyRequestDto request) {
        return trustedCertificateService.applyTrustedCertificates(request);
    }

    @Override
    public TrustedCertificatePlatformDto getPlatformTrust() {
        return trustedCertificateService.getPlatformTrust();
    }

}

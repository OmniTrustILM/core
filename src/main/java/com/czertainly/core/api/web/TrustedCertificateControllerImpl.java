package com.czertainly.core.api.web;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.TrustedCertificateController;
import com.czertainly.api.model.client.trustedcertificate.TrustedCertificateRequestDto;
import com.czertainly.api.model.client.trustedcertificate.TrustedCertificateDto;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.TrustedCertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

/**
 * REST controller implementation for trusted certificate management operations.
 */
@RestController
@RequiredArgsConstructor
public class TrustedCertificateControllerImpl implements TrustedCertificateController {

    private final TrustedCertificateService trustedCertificateService;

    @Override
    @AuthEndpoint(resourceName = Resource.TRUSTED_CERTIFICATE)
    @AuditLogged(module = Module.CORE, resource = Resource.TRUSTED_CERTIFICATE, operation = Operation.LIST)
    public List<TrustedCertificateDto> listTrustedCertificates() {
        return trustedCertificateService.listTrustedCertificates();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.TRUSTED_CERTIFICATE, operation = Operation.DETAIL)
    public TrustedCertificateDto getTrustedCertificate(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        return trustedCertificateService.getTrustedCertificate(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.TRUSTED_CERTIFICATE, operation = Operation.CREATE)
    public ResponseEntity<?> createTrustedCertificate(@RequestBody TrustedCertificateRequestDto request) {
        TrustedCertificateDto trustedCertificateDto = trustedCertificateService.createTrustedCertificate(request);

        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{uuid}")
            .buildAndExpand(trustedCertificateDto.getUuid()).toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(trustedCertificateDto.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.TRUSTED_CERTIFICATE, operation = Operation.DELETE)
    public void deleteTrustedCertificate(@LogResource(uuid = true) @PathVariable String uuid) throws NotFoundException {
        trustedCertificateService.deleteTrustedCertificate(SecuredUUID.fromString(uuid));
    }

}
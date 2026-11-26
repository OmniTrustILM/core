package com.otilm.core.service.v2.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateAddRequestDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateApplyRequestDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateBulkResultDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificatePlatformDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateRemoveRequestDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateUpdateRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.provisioning.ProvisioningException;
import com.otilm.core.provisioning.TrustedCertificateProvisioningApiClient;
import com.otilm.core.provisioning.TrustedCertificateProvisioningDTO;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.v2.TrustedCertificateExternalService;
import jakarta.transaction.Transactional;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

/**
 * Implementation of {@link TrustedCertificateExternalService} for managing trusted certificates via the external
 * provisioning API.
 */
@Service(Resource.Codes.TRUSTED_CERTIFICATE)
@Transactional
@RequiredArgsConstructor
public class TrustedCertificateServiceImpl implements TrustedCertificateExternalService {

    private static final Logger logger = LoggerFactory.getLogger(TrustedCertificateServiceImpl.class);
    private static final String NOT_IMPLEMENTED_YET = "Not implemented yet";

    private final TrustedCertificateProvisioningApiClient trustedCertificateProvisioningApiClient;

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.LIST)
    public List<TrustedCertificateDto> listTrustedCertificates() {
        logger.debug("Listing trusted certificates");
        try {
            List<TrustedCertificateProvisioningDTO> provisioningDtos = trustedCertificateProvisioningApiClient
                    .listTrustedCertificates();
            List<TrustedCertificateDto> result = provisioningDtos.stream().map(this::mapToDto).toList();
            logger.debug("Found {} trusted certificates", result.size());
            return result;
        } catch (Exception e) {
            throw new ProvisioningException("Failed to list trusted certificates", e);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.DETAIL)
    public TrustedCertificateDto getTrustedCertificate(SecuredUUID uuid) throws NotFoundException {
        logger.debug("Getting trusted certificate with UUID: {}", uuid);
        try {
            TrustedCertificateProvisioningDTO provisioningDto = trustedCertificateProvisioningApiClient
                    .getTrustedCertificate(uuid.toString());
            return mapToDto(provisioningDto);
        } catch (HttpClientErrorException.NotFound e) {
            throw new NotFoundException("Trusted certificate", uuid.toString());
        } catch (Exception e) {
            throw new ProvisioningException("Failed to get trusted certificate " + uuid, e);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.CREATE)
    public TrustedCertificateBulkResultDto addTrustedCertificates(TrustedCertificateAddRequestDto request) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_YET);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.UPDATE)
    public TrustedCertificateBulkResultDto updateTrustedCertificates(TrustedCertificateUpdateRequestDto request) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_YET);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.DELETE)
    public TrustedCertificateBulkResultDto removeTrustedCertificates(TrustedCertificateRemoveRequestDto request) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_YET);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.UPDATE)
    public TrustedCertificateBulkResultDto applyTrustedCertificates(TrustedCertificateApplyRequestDto request) {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_YET);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.LIST)
    public TrustedCertificatePlatformDto getPlatformTrust() {
        throw new UnsupportedOperationException(NOT_IMPLEMENTED_YET);
    }

    private TrustedCertificateDto mapToDto(TrustedCertificateProvisioningDTO provisioningDto) {
        TrustedCertificateDto dto = new TrustedCertificateDto();
        dto.setUuid(provisioningDto.uuid());
        dto.setCertificateContent(provisioningDto.certificateContent());
        dto.setIssuer(provisioningDto.issuer());
        dto.setSan(provisioningDto.san());
        dto.setSerialNumber(provisioningDto.serialNumber());
        dto.setSubject(provisioningDto.subject());
        dto.setThumbprint(provisioningDto.thumbprint());
        dto.setNotBefore(atUtc(provisioningDto.notBefore()));
        dto.setNotAfter(atUtc(provisioningDto.notAfter()));
        return dto;
    }

    /** Provisioning reports certificate validity in UTC without the offset. */
    private static OffsetDateTime atUtc(LocalDateTime provisioningTime) {
        return provisioningTime == null ? null : provisioningTime.atOffset(ZoneOffset.UTC);
    }
}

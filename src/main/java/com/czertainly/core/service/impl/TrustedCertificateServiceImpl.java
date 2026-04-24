package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.trustedcertificate.TrustedCertificateDto;
import com.czertainly.api.model.client.trustedcertificate.TrustedCertificateRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.provisioning.ProvisioningException;
import com.czertainly.core.provisioning.TrustedCertificateProvisioningApiClient;
import com.czertainly.core.provisioning.TrustedCertificateProvisioningDTO;
import com.czertainly.core.provisioning.TrustedCertificateProvisioningRequestDTO;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.TrustedCertificateService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;

/**
 * Implementation of {@link TrustedCertificateService} for managing trusted certificates
 * via the external provisioning API.
 */
@Service(Resource.Codes.TRUSTED_CERTIFICATE)
@Transactional
@RequiredArgsConstructor
public class TrustedCertificateServiceImpl implements TrustedCertificateService {

    private static final Logger logger = LoggerFactory.getLogger(TrustedCertificateServiceImpl.class);

    private final TrustedCertificateProvisioningApiClient trustedCertificateProvisioningApiClient;

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.LIST)
    public List<TrustedCertificateDto> listTrustedCertificates() {
        logger.debug("Listing trusted certificates");
        try {
            List<TrustedCertificateProvisioningDTO> provisioningDtos = trustedCertificateProvisioningApiClient.listTrustedCertificates();
            List<TrustedCertificateDto> result = provisioningDtos.stream()
                    .map(this::mapToDto)
                    .toList();
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
            TrustedCertificateProvisioningDTO provisioningDto = trustedCertificateProvisioningApiClient.getTrustedCertificate(uuid.toString());
            return mapToDto(provisioningDto);
        } catch (HttpClientErrorException.NotFound e) {
            throw new NotFoundException("Trusted certificate", uuid.toString());
        } catch (Exception e) {
            throw new ProvisioningException("Failed to get trusted certificate " + uuid, e);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.CREATE)
    public TrustedCertificateDto createTrustedCertificate(TrustedCertificateRequestDto request) {
        logger.info("Creating trusted certificate");
        try {
            TrustedCertificateProvisioningRequestDTO provisioningRequest = new TrustedCertificateProvisioningRequestDTO(request.getCertificateContent());
            TrustedCertificateProvisioningDTO provisioningDto = trustedCertificateProvisioningApiClient.createTrustedCertificate(provisioningRequest);
            logger.info("Trusted certificate created successfully: {}", provisioningDto.uuid());
            return mapToDto(provisioningDto);
        } catch (Exception e) {
            throw new ProvisioningException("Failed to create trusted certificate", e);
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TRUSTED_CERTIFICATE, action = ResourceAction.DELETE)
    public void deleteTrustedCertificate(SecuredUUID uuid) throws NotFoundException {
        logger.info("Deleting trusted certificate with UUID: {}", uuid);
        try {
            trustedCertificateProvisioningApiClient.deleteTrustedCertificate(uuid.toString());
            logger.info("Trusted certificate deleted successfully: {}", uuid);
        } catch (HttpClientErrorException.NotFound e) {
            throw new NotFoundException("Trusted certificate", uuid.toString());
        } catch (Exception e) {
            throw new ProvisioningException("Failed to delete trusted certificate " + uuid, e);
        }
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
        dto.setNotBefore(provisioningDto.notBefore());
        dto.setNotAfter(provisioningDto.notAfter());
        return dto;
    }

}

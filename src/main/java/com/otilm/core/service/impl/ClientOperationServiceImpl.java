package com.otilm.core.service.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.authority.ClientAddEndEntityRequestDto;
import com.otilm.api.model.client.authority.LegacyClientCertificateRevocationDto;
import com.otilm.api.model.client.authority.LegacyClientCertificateSignRequestDto;
import com.otilm.api.model.client.authority.ClientCertificateSignResponseDto;
import com.otilm.api.model.client.authority.ClientEditEndEntityRequestDto;
import com.otilm.api.model.client.authority.ClientEndEntityDto;
import com.otilm.api.model.common.NameAndIdDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.AddEndEntityRequestDto;
import com.otilm.api.model.core.authority.CertRevocationDto;
import com.otilm.api.model.core.authority.CertificateSignRequestDto;
import com.otilm.api.model.core.authority.CertificateSignResponseDto;
import com.otilm.api.model.core.authority.EditEndEntityRequestDto;
import com.otilm.api.model.core.authority.EndEntityDto;
import com.otilm.api.model.core.raprofile.RaProfileDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.ClientOperationExternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.AopContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

@Service
@Transactional
public class ClientOperationServiceImpl implements ClientOperationExternalService {

    private static final Logger logger = LoggerFactory.getLogger(ClientOperationServiceImpl.class);

    private RaProfileRepository raProfileRepository;
    private ConnectorApiFactory connectorApiFactory;
    private CertificateInternalService certificateService;
    private AttributeEngine attributeEngine;
    private ConnectorInternalService connectorService;

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setConnectorService(ConnectorInternalService connectorService) {
        this.connectorService = connectorService;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public ClientCertificateSignResponseDto issueCertificate(String raProfileName, LegacyClientCertificateSignRequestDto request) throws AlreadyExistException, CertificateException, ConnectorException, NoSuchAlgorithmException, NotFoundException {
        RaProfile raProfile = getRaProfileEntityChecked(raProfileName);

        CertificateSignRequestDto caRequest = new CertificateSignRequestDto();
        caRequest.setUsername(request.getUsername());
        caRequest.setPassword(request.getPassword());
        caRequest.setPkcs10(request.getPkcs10());

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        CertificateSignResponseDto caResponse = connectorApiFactory.getCertificateApiClient(connectorDto).issueCertificate(
                connectorDto,
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                getEndEntityProfileName(raProfile),
                caRequest);

        Certificate certificate = certificateService.checkCreateCertificate(caResponse.getCertificateData());
        logger.info("Certificate Created. Adding the certificate to Inventory");
        logger.debug("UUID of the certificate is {}", certificate.getUuid());
        logger.debug("UUID of the RA Profile is {}", raProfile.getUuid());

        certificate.setRaProfile(raProfile);
        certificateService.validate(certificate);

        ClientCertificateSignResponseDto response = new ClientCertificateSignResponseDto();
        response.setCertificateData(caResponse.getCertificateData());
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.REVOKE)
    public void revokeCertificate(String raProfileName, LegacyClientCertificateRevocationDto request) throws ConnectorException, NotFoundException {
        RaProfile raProfile = getRaProfileEntityChecked(raProfileName);

        CertRevocationDto caRequest = new CertRevocationDto();
        caRequest.setCertificateSN(request.getCertificateSN());
        caRequest.setIssuerDN(request.getIssuerDN());
        caRequest.setReason(request.getReason());

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        connectorApiFactory.getCertificateApiClient(connectorDto).revokeCertificate(
                connectorDto,
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                getEndEntityProfileName(raProfile),
                caRequest);

        certificateService.revokeCertificate(request.getCertificateSN());
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.LIST)
    public List<ClientEndEntityDto> listEntities(String raProfileName) throws ConnectorException, NotFoundException {
        RaProfile raProfile = getRaProfileEntityChecked(raProfileName);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        List<EndEntityDto> endEntities = connectorApiFactory.getEndEntityApiClient(connectorDto).listEntities(
                connectorDto,
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                getEndEntityProfileName(raProfile));

        return endEntities == null ? null : endEntities.stream()
                .map(this::mapEndEntity)
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.UPDATE)
    public void addEndEntity(String raProfileName, ClientAddEndEntityRequestDto request) throws ConnectorException, NotFoundException {
        RaProfile raProfile = getRaProfileEntityChecked(raProfileName);
        RaProfileDto raProfileDto = raProfile.mapToDto();
        raProfileDto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));

        AddEndEntityRequestDto caRequest = new AddEndEntityRequestDto();
        caRequest.setUsername(request.getUsername());
        caRequest.setPassword(request.getPassword());
        caRequest.setEmail(request.getEmail());
        caRequest.setSubjectDN(request.getSubjectDN());
        caRequest.setSubjectAltName(request.getSubjectAltName());
        caRequest.setExtensionData(request.getExtensionData());
        caRequest.setRaProfile(raProfileDto);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        connectorApiFactory.getEndEntityApiClient(connectorDto).createEndEntity(
                connectorDto,
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                getEndEntityProfileName(raProfile),
                caRequest);
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL)
    public ClientEndEntityDto getEndEntity(String raProfileName, String username) throws ConnectorException, NotFoundException {
        RaProfile raProfile = getRaProfileEntityChecked(raProfileName);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        EndEntityDto endEntity = connectorApiFactory.getEndEntityApiClient(connectorDto).getEndEntity(
                connectorDto,
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                getEndEntityProfileName(raProfile),
                username);

        return endEntity == null ? null : mapEndEntity(endEntity);
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.UPDATE)
    public void editEndEntity(String raProfileName, String username, ClientEditEndEntityRequestDto request) throws ConnectorException, NotFoundException {
        RaProfile raProfile = getRaProfileEntityChecked(raProfileName);
        RaProfileDto raProfileDto = raProfile.mapToDto();
        raProfileDto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build()));

        EditEndEntityRequestDto caRequest = new EditEndEntityRequestDto();
        caRequest.setPassword(request.getPassword());
        caRequest.setEmail(request.getEmail());
        caRequest.setSubjectDN(request.getSubjectDN());
        caRequest.setSubjectAltName(request.getSubjectAltName());
        caRequest.setExtensionData(request.getExtensionData());
        caRequest.setStatus(request.getStatus());
        caRequest.setRaProfile(raProfileDto);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        connectorApiFactory.getEndEntityApiClient(connectorDto).updateEndEntity(
                connectorDto,
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                getEndEntityProfileName(raProfile),
                username,
                caRequest);
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.UPDATE)
    public void revokeAndDeleteEndEntity(String raProfileName, String username) throws ConnectorException, NotFoundException {
        RaProfile raProfile = getRaProfileEntityChecked(raProfileName);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        connectorApiFactory.getEndEntityApiClient(connectorDto).revokeAndDeleteEndEntity(
                connectorDto,
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                getEndEntityProfileName(raProfile),
                username);
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.UPDATE)
    public void resetPassword(String raProfileName, String username) throws ConnectorException, NotFoundException {
        RaProfile raProfile = getRaProfileEntityChecked(raProfileName);

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(raProfile.getAuthorityInstanceReference().getConnectorUuid());
        connectorApiFactory.getEndEntityApiClient(connectorDto).resetPassword(
                connectorDto,
                raProfile.getAuthorityInstanceReference().getAuthorityInstanceUuid(),
                getEndEntityProfileName(raProfile),
                username);
    }

    private String getEndEntityProfileName(RaProfile raProfile) {
        var raProfileAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid()).connector(raProfile.getAuthorityInstanceReference().getConnectorUuid()).build());
        if (raProfileAttributes == null || raProfileAttributes.stream().noneMatch(a -> a.getName().equals("endEntityProfile"))) {
            throw new ValidationException(ValidationError.create("EndEntityProfile not found in attributes"));
        }

        try {
            NameAndIdDto endEntityProfile = AttributeDefinitionUtils.getNameAndIdData("endEntityProfile", raProfileAttributes);
            if (endEntityProfile == null) {
                throw new ValidationException(ValidationError.create("EndEntityProfile not found in attributes"));
            }

            return endEntityProfile.getName();
        } catch (Exception e) {
            throw new ValidationException(ValidationError.create("EndEntityProfile could not be retrieved from attributes. {}", e.getMessage()));
        }
    }

    private ClientEndEntityDto mapEndEntity(EndEntityDto caDto) {
        ClientEndEntityDto dto = new ClientEndEntityDto();
        dto.setUsername(caDto.getUsername());
        dto.setEmail(caDto.getEmail());
        dto.setSubjectDN(caDto.getSubjectDN());
        dto.setSubjectAltName(caDto.getSubjectAltName());
        dto.setStatus(caDto.getStatus());
        dto.setExtensionData(caDto.getExtensionData());
        return dto;
    }

    private RaProfile getRaProfileEntityChecked(String raProfileName) throws NotFoundException {
        RaProfile raProfile = raProfileRepository.findByNameAndEnabledIsTrue(raProfileName)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileName));

        ((ClientOperationExternalService) AopContext.currentProxy()).checkAccessPermissions(raProfile.getSecuredUuid(), SecuredParentUUID.fromString(raProfile.getAuthorityInstanceReferenceUuid().toString()));

        return raProfile;
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.DETAIL, parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public void checkAccessPermissions(SecuredUUID raProfileUuid, SecuredParentUUID authorityUuid) {

    }
}

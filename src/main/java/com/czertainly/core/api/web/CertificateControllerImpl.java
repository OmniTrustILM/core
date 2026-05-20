package com.czertainly.core.api.web;

import com.czertainly.api.exception.*;
import com.czertainly.api.interfaces.core.web.CertificateController;
import com.czertainly.api.model.client.approval.ApprovalResponseDto;
import com.czertainly.api.model.client.certificate.*;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.location.LocationDto;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.v2.ClientCertificateRequestDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ApprovalService;
import com.czertainly.core.service.CertificateEventHistoryService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.converter.CertificateFormatConverter;
import com.czertainly.core.util.converter.CertificateFormatEncodingConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.UUID;


@RestController
public class CertificateControllerImpl implements CertificateController {

    private CertificateService certificateService;

    private CertificateEventHistoryService certificateEventHistoryService;

    private ClientOperationService clientOperationService;

    private ApprovalService approvalService;

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(CertificateFormat.class, new CertificateFormatConverter());
        webdataBinder.registerCustomEditor(CertificateFormatEncoding.class, new CertificateFormatEncodingConverter());
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.LIST)
    public CertificateResponseDto listCertificates(CertificateSearchRequestDto request) {
        return certificateService.listCertificates(SecurityFilter.create(), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.DETAIL)
    public CertificateDetailDto getCertificate(@LogResource(uuid = true) @PathVariable UUID uuid)
            throws NotFoundException, CertificateException, IOException {
        return certificateService.getCertificate(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.DOWNLOAD)
    public CertificateDownloadResponseDto downloadCertificate(@LogResource(uuid = true) UUID uuid, CertificateFormat certificateFormat, CertificateFormatEncoding encoding) throws CertificateException, NotFoundException, IOException {
        return certificateService.downloadCertificate(uuid, certificateFormat, encoding);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.DELETE)
    public void deleteCertificate(@LogResource(uuid = true) @PathVariable UUID uuid) throws NotFoundException {
        certificateService.deleteCertificate(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.UPDATE)
    public void updateCertificateObjects(@LogResource(uuid = true) UUID uuid, CertificateUpdateObjectsDto request) throws NotFoundException, CertificateOperationException, AttributeException {
        certificateService.updateCertificateObjects(SecuredUUID.fromUUID(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.UPDATE)
    public void bulkUpdateCertificateObjects(MultipleCertificateObjectUpdateDto request) throws NotFoundException, NotSupportedException {
        if (request.getFilters() != null && !request.getFilters().isEmpty() && (request.getCertificateUuids() == null || request.getCertificateUuids().isEmpty())) {
            throw new NotSupportedException("Bulk updating of certificates by filters is not supported.");
        }
        certificateService.bulkUpdateCertificatesObjects(SecurityFilter.create(), request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.UPLOAD)
    public FingerprintDto uploadAsync(UploadCertificateRequestDto request) throws AlreadyExistException, CertificateException {
        return certificateService.uploadAsync(request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.UPLOAD)
    public ResponseEntity<UuidDto> upload(@RequestBody UploadCertificateRequestDto request)
            throws AlreadyExistException, CertificateException, NoSuchAlgorithmException, NotFoundException, AttributeException {
        UuidDto dto = certificateService.uploadSync(request);
        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(dto.getUuid())
                .toUri();
        UuidDto responseDto = new UuidDto();
        responseDto.setUuid(dto.getUuid());
        return ResponseEntity.created(location).body(responseDto);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.DELETE)
    public BulkOperationResponse bulkDeleteCertificate(@RequestBody RemoveCertificateDto request) throws NotFoundException, NotSupportedException {
        BulkOperationResponse response = new BulkOperationResponse();
        if (request.getFilters() != null && !request.getFilters().isEmpty() && (request.getUuids() == null || request.getUuids().isEmpty())) {
            throw new NotSupportedException("Bulk delete of certificates by filters is not supported.");
        }
        certificateService.bulkDeleteCertificate(SecurityFilter.create(), request);
        response.setMessage("Initiated bulk delete Certificates. Please refresh after some time");
        response.setStatus(BulkOperationStatus.SUCCESS);
        return response;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.CERTIFICATE, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return certificateService.getSearchableFieldInformationByGroup();
    }


    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.HISTORY)
    public List<CertificateEventHistoryDto> getCertificateEventHistory(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return certificateEventHistoryService.getCertificateEventHistory(uuid);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.LOCATION, operation = Operation.LIST)
    public List<LocationDto> listLocations(@LogResource(uuid = true) UUID certificateUuid) throws NotFoundException {
        return certificateService.listLocations(SecuredUUID.fromUUID(certificateUuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.CHECK_COMPLIANCE)
    public void checkCompliance(CertificateComplianceCheckDto request) throws NotFoundException {
        certificateService.checkCompliance(request);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.CHECK_VALIDATION)
    public CertificateValidationResultDto getCertificateValidationResult(@LogResource(uuid = true) UUID uuid) throws NotFoundException, CertificateException {
        return certificateService.getCertificateValidationResult(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.ATTRIBUTE, name = "csr", affiliatedResource = Resource.CERTIFICATE, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> getCsrGenerationAttributes() {
        return certificateService.getCsrGenerationAttributes();
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.GET_CONTENT)
    public List<CertificateContentDto> getCertificateContent(@LogResource(uuid = true) List<UUID> uuids) {
        return certificateService.getCertificateContent(uuids);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.REQUEST)
    public CertificateDetailDto submitCertificateRequest(ClientCertificateRequestDto request) throws ValidationException, ConnectorException, CertificateException, NoSuchAlgorithmException, AttributeException, CertificateRequestException, NotFoundException {
        return clientOperationService.submitCertificateRequest(request, null);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.GET_CHAIN)
    public CertificateChainResponseDto getCertificateChain(@LogResource(uuid = true) UUID uuid, boolean withEndCertificate) throws NotFoundException {
        return certificateService.getCertificateChain(SecuredUUID.fromUUID(uuid), withEndCertificate);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.DOWNLOAD_CHAIN)
    public CertificateChainDownloadResponseDto downloadCertificateChain(@LogResource(uuid = true) UUID uuid, CertificateFormat certificateFormat, boolean withEndCertificate, CertificateFormatEncoding encoding) throws NotFoundException, CertificateException {
        return certificateService.downloadCertificateChain(SecuredUUID.fromUUID(uuid), certificateFormat, withEndCertificate, encoding);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, affiliatedResource = Resource.APPROVAL, operation = Operation.LIST)
    public ApprovalResponseDto listCertificateApprovals(@LogResource(uuid = true) final UUID uuid, final PaginationRequestDto paginationRequestDto) {
        return approvalService.listApprovalsByObject(SecurityFilter.create(), Resource.CERTIFICATE, uuid, paginationRequestDto);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.ARCHIVE)
    public void archiveCertificate(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        certificateService.archiveCertificate(uuid);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.UNARCHIVE)
    public void unarchiveCertificate(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        certificateService.unarchiveCertificate(uuid);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.ARCHIVE)
    public void bulkArchiveCertificate(List<UUID> uuids) {
        certificateService.bulkArchiveCertificates(uuids);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.UNARCHIVE)
    public void bulkUnarchiveCertificate(List<UUID> uuids) {
        certificateService.bulkUnarchiveCertificates(uuids);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.GET_ASSOCIATIONS)
    public CertificateRelationsDto getCertificateRelations(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return certificateService.getCertificateRelations(uuid);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.ASSOCIATE, affiliatedResource = Resource.CERTIFICATE)
    public void associateCertificates(@LogResource(uuid = true) UUID uuid, @LogResource(uuid = true, affiliated = true) UUID certificateUuid) throws NotFoundException {
        certificateService.associateCertificates(uuid, certificateUuid);
    }

    @Override
    @AuditLogged(module = Module.CERTIFICATES, resource = Resource.CERTIFICATE, operation = Operation.DISASSOCIATE, affiliatedResource = Resource.CERTIFICATE)
    public void removeCertificateAssociation(@LogResource(uuid = true) UUID uuid, @LogResource(uuid = true, affiliated = true) UUID certificateUuid) throws NotFoundException {
        certificateService.removeCertificateAssociation(uuid, certificateUuid);
    }

    // SETTERs

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setApprovalService(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }
}
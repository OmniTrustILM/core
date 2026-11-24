package com.otilm.core.service.renewal.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.BulkOperationResponse;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.BulkEarlyRenewalRequestDto;
import com.otilm.api.model.core.certificate.BulkOperationStatus;
import com.otilm.api.model.core.certificate.EarlyRenewalRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Certificate_;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.renewal.EarlyRenewalExternalService;
import com.otilm.core.service.renewal.RenewalEligibility;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.BiFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class EarlyRenewalServiceImpl implements EarlyRenewalExternalService {

    private static final Logger logger = LoggerFactory.getLogger(EarlyRenewalServiceImpl.class);

    private static final String PARTIAL_MESSAGE = "Early renewal was requested for %d certificates; "
            + "%d certificates were skipped because they are not eligible or not permitted";

    private final RaProfileRepository raProfileRepository;
    private final CertificateRepository certificateRepository;
    private final RenewalWindowWriter renewalWindowWriter;

    public EarlyRenewalServiceImpl(RaProfileRepository raProfileRepository, CertificateRepository certificateRepository,
            RenewalWindowWriter renewalWindowWriter) {
        this.raProfileRepository = raProfileRepository;
        this.certificateRepository = certificateRepository;
        this.renewalWindowWriter = renewalWindowWriter;
    }

    @Override
    @ExternalAuthorization(resource = Resource.RA_PROFILE, action = ResourceAction.UPDATE,
            parentResource = Resource.AUTHORITY, parentAction = ResourceAction.DETAIL)
    public long requestForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid,
            EarlyRenewalRequestDto request) throws NotFoundException {
        RaProfile raProfile = raProfileRepository
                .findByUuid(raProfileUuid)
                .filter(profile -> authorityUuid.getValue().equals(profile.getAuthorityInstanceReferenceUuid()))
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        List<UUID> eligibleUuids = findAwaitingRenewal(SecurityFilter.create(),
                (root, cb) -> cb.equal(root.get(Certificate_.raProfileUuid), raProfile.getUuid()));
        forceWindow(eligibleUuids, request);
        logger
                .info("Early renewal requested for {} certificates of RA profile {}", eligibleUuids.size(),
                        raProfile.getUuid());
        return eligibleUuids.size();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.RENEW,
            parentResource = Resource.RA_PROFILE, parentAction = ResourceAction.DETAIL)
    public BulkOperationResponse requestForCertificates(SecurityFilter filter, BulkEarlyRenewalRequestDto request) {
        filter.setParentRefProperty(Certificate_.raProfileUuid.getName());
        List<UUID> requestedUuids = request.getUuids().stream().distinct().toList();
        List<UUID> eligibleUuids = findAwaitingRenewal(filter,
                (root, cb) -> root.get(Certificate_.uuid).in(requestedUuids));
        forceWindow(eligibleUuids, request);
        int skipped = requestedUuids.size() - eligibleUuids.size();
        logger
                .info("Early renewal requested for {} of {} selected certificates", eligibleUuids.size(),
                        requestedUuids.size());
        return bulkResponse(eligibleUuids.size(), skipped);
    }

    private List<UUID> findAwaitingRenewal(SecurityFilter filter,
            BiFunction<Root<Certificate>, CriteriaBuilder, Predicate> scope) {
        return certificateRepository
                .findUuidsUsingSecurityFilter(filter,
                        (root, cb, cr) -> cb
                                .and(scope.apply(root, cb), RenewalEligibility.awaitingRenewal(root, cb, cr)),
                        null, null);
    }

    private void forceWindow(List<UUID> certificateUuids, EarlyRenewalRequestDto request) {
        Instant now = Instant.now();
        WindowWrite forced = new WindowWrite.Forced(new Window(now, now.plusSeconds(request.getSpreadSeconds())),
                request.getExplanationUrl());
        certificateUuids.forEach(certificateUuid -> renewalWindowWriter.write(certificateUuid, forced));
    }

    private static BulkOperationResponse bulkResponse(int forced, int skipped) {
        BulkOperationResponse response = new BulkOperationResponse();
        response.setFailedItem((long) skipped);
        if (skipped == 0) {
            response.setStatus(BulkOperationStatus.SUCCESS);
            response.setMessage("Early renewal was requested for %d certificates".formatted(forced));
        } else {
            response.setStatus(forced == 0 ? BulkOperationStatus.FAILED : BulkOperationStatus.PARTIAL);
            response.setMessage(PARTIAL_MESSAGE.formatted(forced, skipped));
        }
        return response;
    }
}

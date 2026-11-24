package com.otilm.core.service.writer;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository.PolicyWindowChange;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.renewal.PolicyWindow;
import com.otilm.core.service.renewal.RenewalEnrolmentHook;
import com.otilm.core.service.renewal.RenewalState;
import com.otilm.core.service.renewal.RenewalWindowRules;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.service.renewal.WindowWrite.AuthorityNoAdvice;
import com.otilm.core.service.renewal.WindowWrite.Policy;
import com.otilm.core.service.renewal.WindowWrite.RaProfileReset;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class RenewalWindowWriterImpl implements RenewalWindowWriter {

    private static final Logger logger = LoggerFactory.getLogger(RenewalWindowWriterImpl.class);

    private final CertificateRenewalInfoRepository renewalInfoRepository;
    private final CertificateRenewalLocationRepository renewalLocationRepository;
    private final CertificateRepository certificateRepository;
    private final CertificateEventHistoryInternalService eventHistoryService;
    private final RenewalEnrolmentHook enrolmentHook;

    public RenewalWindowWriterImpl(CertificateRenewalInfoRepository renewalInfoRepository,
            CertificateRenewalLocationRepository renewalLocationRepository, CertificateRepository certificateRepository,
            CertificateEventHistoryInternalService eventHistoryService, RenewalEnrolmentHook enrolmentHook) {
        this.renewalInfoRepository = renewalInfoRepository;
        this.renewalLocationRepository = renewalLocationRepository;
        this.certificateRepository = certificateRepository;
        this.eventHistoryService = eventHistoryService;
        this.enrolmentHook = enrolmentHook;
    }

    @Override
    public void write(UUID certificateUuid, WindowWrite write) {
        certificateRepository
                .findByUuid(certificateUuid)
                .ifPresentOrElse(certificate -> apply(certificate, write), () -> logger
                        .debug("Certificate {} no longer exists; its renewal window is not written", certificateUuid));
    }

    @Override
    public boolean writeAuthorityAdvice(UUID certificateUuid, UUID raProfileUuid, WindowWrite advice) {
        if (renewalInfoRepository
                .lockRaProfileWhenRefreshEligible(certificateUuid, Instant.now())
                .filter(raProfileUuid::equals)
                .isEmpty()) {
            logger
                    .debug("Certificate {} no longer takes the advice of the authority of RA profile {}",
                            certificateUuid, raProfileUuid);
            return false;
        }
        write(certificateUuid, advice);
        return true;
    }

    @Override
    public void recomputePolicy(RaProfile raProfile) {
        Instant now = Instant.now();
        if (raProfile.isRenewalWindowEnabled()) {
            List<PolicyWindowChange> changed = renewalInfoRepository
                    .upsertPolicyWindows(raProfile.getUuid(), raProfile.getRenewalWindowStartPercent(),
                            raProfile.getRenewalWindowEndPercent(), now);
            resetOpenLocationAttempts(changed.stream().map(PolicyWindowChange::getCertificateUuid).toList());
            changed
                    .forEach(change -> recordChange(change.getCertificateUuid(),
                            new RenewalState(change.getWindowStart(), change.getWindowEnd(), null,
                                    RenewalWindowSource.POLICY, now, false)));
            List<UUID> emptied = renewalInfoRepository
                    .clearEmptyPolicyWindows(raProfile.getUuid(), raProfile.getRenewalWindowStartPercent(),
                            raProfile.getRenewalWindowEndPercent(), now);
            resetOpenLocationAttempts(emptied);
            emptied.forEach(certificateUuid -> recordChange(certificateUuid, RenewalState.NONE));
            logger
                    .debug("Policy renewal windows of RA profile {} recomputed for {} certificates",
                            raProfile.getUuid(), changed.size());
        } else {
            List<UUID> cleared = renewalInfoRepository.clearPolicyWindows(raProfile.getUuid(), now);
            resetOpenLocationAttempts(cleared);
            cleared.forEach(certificateUuid -> recordChange(certificateUuid, RenewalState.NONE));
            logger
                    .debug("Policy renewal windows of RA profile {} removed from {} certificates", raProfile.getUuid(),
                            cleared.size());
        }
    }

    @Override
    public void dropAuthorityWindows(RaProfile raProfile) {
        List<UUID> certificateUuids = renewalInfoRepository
                .findCertificateUuidsByRaProfileAndSource(raProfile.getUuid(), RenewalWindowSource.AUTHORITY);
        certificateUuids.forEach(certificateUuid -> write(certificateUuid, new RaProfileReset()));
        logger
                .debug("Authority renewal windows of RA profile {} dropped for {} certificates", raProfile.getUuid(),
                        certificateUuids.size());
    }

    @Override
    public void onIssued(Certificate certificate) {
        apply(certificate, new Policy(policyWindow(certificate)));
        enrolmentHook.enrol(certificate);
    }

    @Override
    public void onRaProfileChanged(Certificate certificate, RaProfile oldProfile) {
        logger
                .debug("RA profile of certificate {} changed from {}; renewal window re-evaluated",
                        certificate.getUuid(), oldProfile == null ? null : oldProfile.getUuid());
        apply(certificate, new RaProfileReset());
        enrolmentHook.enrol(certificate);
    }

    private void apply(Certificate certificate, WindowWrite write) {
        Instant now = Instant.now();
        UUID certificateUuid = certificate.getUuid();
        Optional<CertificateRenewalInfo> locked = renewalInfoRepository.findAndLockByCertificateUuid(certificateUuid);
        RenewalState current = locked.map(RenewalWindowWriterImpl::toState).orElse(RenewalState.NONE);
        RenewalState next = decide(certificate, current, write, now);
        if (next.sameWindowAs(current)) {
            return;
        }
        CertificateRenewalInfo row;
        if (locked.isPresent()) {
            row = locked.get();
        } else {
            row = createLocked(certificateUuid, now);
            // Another writer may have created the row first; decide again on what it holds.
            current = toState(row);
            next = decide(certificate, current, write, now);
            if (next.sameWindowAs(current)) {
                return;
            }
        }
        store(row, next);
        resetOpenLocationAttempts(List.of(certificateUuid));
        certificate.setRenewalInfo(row);
        recordChange(certificateUuid, next);
    }

    /**
     * Applies the write and, when it removed an authority or policy window, falls back to the policy window of the
     * certificate's current RA profile. A certificate that is no longer live keeps its window as history against the
     * policy, as the bulk recomputation leaves it.
     */
    private static RenewalState decide(Certificate certificate, RenewalState current, WindowWrite write, Instant now) {
        boolean policyDriven = write instanceof Policy || write instanceof RaProfileReset
                || write instanceof AuthorityNoAdvice;
        if (policyDriven && !isLive(certificate, now)) {
            return current;
        }
        RenewalState next = RenewalWindowRules.apply(current, write, now).next();
        if (write instanceof RaProfileReset || write instanceof AuthorityNoAdvice) {
            next = RenewalWindowRules.apply(next, new Policy(policyWindow(certificate)), now).next();
        }
        return next.sameWindowAs(current) ? current : next;
    }

    /** Issued, not archived and not expired: the certificates the policy gives a window. */
    private static boolean isLive(Certificate certificate, Instant now) {
        return certificate.getState() == CertificateState.ISSUED && !certificate.isArchived()
                && certificate.getNotAfter() != null && certificate.getNotAfter().toInstant().isAfter(now);
    }

    private static Window policyWindow(Certificate certificate) {
        RaProfile raProfile = certificate.getRaProfile();
        if (raProfile == null || !raProfile.isRenewalWindowEnabled() || certificate.getNotBefore() == null
                || certificate.getNotAfter() == null) {
            return null;
        }
        return PolicyWindow
                .compute(certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant(),
                        raProfile.getRenewalWindowStartPercent(), raProfile.getRenewalWindowEndPercent())
                .orElse(null);
    }

    private CertificateRenewalInfo createLocked(UUID certificateUuid, Instant now) {
        renewalInfoRepository.insertIfAbsent(UUID.randomUUID(), certificateUuid, now);
        return renewalInfoRepository
                .findAndLockByCertificateUuid(certificateUuid)
                .orElseThrow(() -> new IllegalStateException(
                        "Renewal row of certificate %s was not created".formatted(certificateUuid)));
    }

    /** A new window gives the locations still to be renewed fresh failure counters, as the certificate row gets. */
    private void resetOpenLocationAttempts(List<UUID> certificateUuids) {
        if (!certificateUuids.isEmpty()) {
            renewalLocationRepository.resetOpenAttempts(certificateUuids);
        }
    }

    private void recordChange(UUID certificateUuid, RenewalState next) {
        String message = next.hasWindow()
                ? "Renewal window from %s to %s, source: %s"
                        .formatted(next.windowStart(), next.windowEnd(), next.source().getLabel())
                : "Renewal window removed";
        logger.debug("Certificate {}: {}", certificateUuid, message);
        eventHistoryService
                .addEventHistory(certificateUuid, CertificateEvent.UPDATE_RENEWAL_WINDOW,
                        CertificateEventStatus.SUCCESS, message, "");
    }

    private static void store(CertificateRenewalInfo row, RenewalState state) {
        row.setWindowStart(state.windowStart());
        row.setWindowEnd(state.windowEnd());
        row.setExplanationUrl(state.explanationUrl());
        row.setSource(state.source());
        row.setUpdatedAt(state.updatedAt());
        row.setAdvanced(state.advanced());
        // A new window gets a new renewal time and fresh failure counters; in-flight work stays tracked.
        row.setRenewAt(null);
        row.setRenewAttempt(0);
        row.setRenewNotBefore(null);
    }

    private static RenewalState toState(CertificateRenewalInfo row) {
        return new RenewalState(row.getWindowStart(), row.getWindowEnd(), row.getExplanationUrl(), row.getSource(),
                row.getUpdatedAt(), row.isAdvanced());
    }
}

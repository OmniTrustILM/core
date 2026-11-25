package com.otilm.core.service.writer;

import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository.RefreshClaim;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.function.IntFunction;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Writes the refresh state of the renewal information of certificates, each write one atomic statement. */
@Service
@Transactional
public class RenewalRefreshWriter {

    private final CertificateRenewalInfoRepository renewalInfoRepository;

    public RenewalRefreshWriter(CertificateRenewalInfoRepository renewalInfoRepository) {
        this.renewalInfoRepository = renewalInfoRepository;
    }

    /** Sets when the certificate is refreshed next, how many refreshes failed in a row and the unsupported mark. */
    public void schedule(UUID certificateUuid, Instant nextRefreshAt, int attempt, boolean unsupported) {
        renewalInfoRepository.updateRefreshState(certificateUuid, nextRefreshAt, attempt, unsupported);
    }

    /**
     * Counts one more failed refresh and sets the next refresh time from the new count. The counter is incremented by
     * the statement itself and the row stays locked until the time is set, so concurrent failures never lose a count.
     */
    public void backOff(UUID certificateUuid, IntFunction<Instant> nextRefreshAt) {
        Integer attempt = renewalInfoRepository.incrementRefreshAttempt(certificateUuid);
        if (attempt != null) {
            renewalInfoRepository.updateNextRefreshAt(List.of(certificateUuid), nextRefreshAt.apply(attempt));
        }
    }

    /**
     * Re-evaluates the refresh of the certificate: its refresh state starts over, it is enrolled with a first refresh
     * within {@code maxDelaySeconds} when eligible, and once issued it ends the refresh of the certificates it renews.
     */
    public void reEnrol(UUID certificateUuid, Instant now, int maxDelaySeconds) {
        renewalInfoRepository.resetRefresh(List.of(certificateUuid));
        renewalInfoRepository.enrolCertificate(certificateUuid, now, maxDelaySeconds);
        renewalInfoRepository.resetPredecessorRefresh(certificateUuid);
    }

    /** Starts the refresh of the RA profile's eligible certificates, spreading their first refresh. */
    public int startRaProfile(UUID raProfileUuid, Instant now, int spreadSeconds) {
        renewalInfoRepository.resetRaProfileRefresh(raProfileUuid);
        return renewalInfoRepository.enrolRaProfile(raProfileUuid, now, spreadSeconds);
    }

    /** Stops the refresh of the RA profile's certificates and forgets the unsupported marks. */
    public void stopRaProfile(UUID raProfileUuid) {
        renewalInfoRepository.resetRaProfileRefresh(raProfileUuid);
    }

    /** Ends the refresh of due certificates that are no longer eligible; answers how many. */
    public int stopIneligibleDue(Instant now) {
        return renewalInfoRepository.resetIneligibleDue(now);
    }

    /** Enrols up to {@code limit} eligible certificates, spreading their first refresh; answers how many. */
    public int enrolEligible(Instant now, int spreadSeconds, int limit) {
        return renewalInfoRepository.enrolEligible(now, spreadSeconds, limit);
    }

    /**
     * Claims the due eligible certificates, at most {@code maxPerAuthority} of each authority, until
     * {@code leaseUntil}.
     */
    public List<RefreshClaim> claimDue(Instant now, int maxPerAuthority, Instant leaseUntil) {
        return renewalInfoRepository.claimDue(now, maxPerAuthority, leaseUntil);
    }

    /** Postpones the refresh of the certificates to the given time. */
    public void postpone(Collection<UUID> certificateUuids, Instant nextRefreshAt) {
        if (!certificateUuids.isEmpty()) {
            renewalInfoRepository.updateNextRefreshAt(certificateUuids, nextRefreshAt);
        }
    }
}

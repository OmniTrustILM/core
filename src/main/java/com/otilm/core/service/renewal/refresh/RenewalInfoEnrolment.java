package com.otilm.core.service.renewal.refresh;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.SettingInternalService;
import com.otilm.core.service.renewal.RenewalEnrolmentHook;
import com.otilm.core.service.writer.RenewalRefreshWriter;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Decides which certificates have the renewal information of their authority refreshed. A certificate is enrolled when
 * it becomes issued under, or is assigned to, an RA profile that uses the authority's renewal information through a
 * connector that offers it; turning the RA profile setting on or off starts or stops the refresh of its certificates.
 */
@Component
public class RenewalInfoEnrolment implements RenewalEnrolmentHook {

    /** A newly enrolled certificate is refreshed within this many seconds. */
    public static final int ENROL_DELAY_SECONDS = 300;

    private static final Logger logger = LoggerFactory.getLogger(RenewalInfoEnrolment.class);

    private final RenewalRefreshWriter refreshWriter;
    private final SettingInternalService settingService;

    public RenewalInfoEnrolment(RenewalRefreshWriter refreshWriter, SettingInternalService settingService) {
        this.refreshWriter = refreshWriter;
        this.settingService = settingService;
    }

    /**
     * Re-evaluates the refresh of the certificate. Under an RA profile that does not use the authority's renewal
     * information nothing is written: the certificate cannot be enrolled, and refresh state left from another profile
     * or from its predecessors is ended by the sweep, which claims only eligible certificates.
     */
    @Override
    public void enrol(Certificate certificate) {
        RaProfile raProfile = certificate.getRaProfile();
        if (raProfile == null || !raProfile.isRenewalUseAuthorityInfo()) {
            return;
        }
        refreshWriter.reEnrol(certificate.getUuid(), Instant.now(), ENROL_DELAY_SECONDS);
    }

    /** Starts the refresh of the RA profile's certificates, their first refreshes spread over the default interval. */
    public void start(RaProfile raProfile) {
        int enrolled = refreshWriter
                .startRaProfile(raProfile.getUuid(), Instant.now(),
                        RenewalInfoSettings.current(settingService).defaultIntervalSeconds());
        logger
                .info("Renewal information refresh started for {} certificates of RA profile {}", enrolled,
                        raProfile.getUuid());
    }

    /** Stops the refresh of the RA profile's certificates. */
    public void stop(RaProfile raProfile) {
        refreshWriter.stopRaProfile(raProfile.getUuid());
        logger.info("Renewal information refresh stopped for RA profile {}", raProfile.getUuid());
    }
}

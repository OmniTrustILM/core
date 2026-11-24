package com.otilm.core.service.acme.impl;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.acme.RenewalInfo;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.service.acme.AcmeRenewalInfoExternalService;
import com.otilm.core.service.acme.AriCertId;
import com.otilm.core.service.acme.AriCertificateLookup;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AcmeRenewalInfoServiceImpl implements AcmeRenewalInfoExternalService {

    private static final Logger logger = LoggerFactory.getLogger(AcmeRenewalInfoServiceImpl.class);

    /** The longest Retry-After of a window that was forced, so that clients pick it up soon. */
    private static final long FORCED_MAX_RETRY_AFTER_SECONDS = Duration.ofHours(1).toSeconds();

    private AcmeProfileRepository acmeProfileRepository;
    private RaProfileRepository raProfileRepository;
    private AriCertificateLookup ariCertificateLookup;
    private CertificateRenewalInfoRepository renewalInfoRepository;

    @Autowired
    public void setAcmeProfileRepository(AcmeProfileRepository acmeProfileRepository) {
        this.acmeProfileRepository = acmeProfileRepository;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setAriCertificateLookup(AriCertificateLookup ariCertificateLookup) {
        this.ariCertificateLookup = ariCertificateLookup;
    }

    @Autowired
    public void setRenewalInfoRepository(CertificateRenewalInfoRepository renewalInfoRepository) {
        this.renewalInfoRepository = renewalInfoRepository;
    }

    @Override
    @ProtocolEndpoint
    @Transactional(readOnly = true)
    public ResponseEntity<RenewalInfo> getRenewalInfo(String profileName, boolean raProfileFamily, String certId)
            throws AcmeProblemDocumentException {
        Optional<ServingProfile> serving = findServingProfile(profileName, raProfileFamily);
        if (serving.isEmpty()) {
            logger.debug("ACME renewal information is not served for {}", profileName);
            return ResponseEntity.notFound().build();
        }

        AriCertId id;
        try {
            id = AriCertId.parse(certId);
        } catch (IllegalArgumentException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "The certificate identifier is malformed");
        }

        Optional<CertificateRenewalInfo> window = ariCertificateLookup
                .find(serving.get().raProfileUuid(), id)
                .flatMap(certificate -> renewalInfoRepository.findByCertificateUuid(certificate.getUuid()))
                .filter(info -> info.getWindowStart() != null && info.getWindowEnd() != null);
        if (window.isEmpty()) {
            logger.debug("No renewal window for the requested certificate under {}", profileName);
            return ResponseEntity.notFound().build();
        }
        return respond(serving.get().acmeProfile(), window.get());
    }

    /**
     * The ACME profile and the RA profile its certificates are issued under: the profile's own RA profile in the ACME
     * URL family, the RA profile of the URL in the RA profile family.
     */
    private Optional<ServingProfile> findServingProfile(String profileName, boolean raProfileFamily) {
        Optional<ServingProfile> serving;
        if (raProfileFamily) {
            serving = raProfileRepository
                    .findByName(profileName)
                    .filter(ra -> ra.getAcmeProfile() != null && Boolean.TRUE.equals(ra.getEnabled()))
                    .map(ra -> new ServingProfile(ra.getAcmeProfile(), ra.getUuid()));
        } else {
            serving = acmeProfileRepository
                    .findByName(profileName)
                    .filter(acme -> acme.getRaProfile() != null
                            && Boolean.TRUE.equals(acme.getRaProfile().getEnabled()))
                    .map(acme -> new ServingProfile(acme, acme.getRaProfileUuid()));
        }
        return serving
                .filter(s -> Boolean.TRUE.equals(s.acmeProfile().isEnabled())
                        && s.acmeProfile().isRenewalInfoEnabled());
    }

    private ResponseEntity<RenewalInfo> respond(AcmeProfile profile, CertificateRenewalInfo info) {
        long retryAfter = profile.getRenewalInfoRetryAfter();
        if (info.getSource() == RenewalWindowSource.FORCED) {
            retryAfter = Math.min(retryAfter, FORCED_MAX_RETRY_AFTER_SECONDS);
        }

        RenewalInfo body = new RenewalInfo();
        body
                .setSuggestedWindow(
                        new RenewalInfo.SuggestedWindow(rfc3339(info.getWindowStart()), rfc3339(info.getWindowEnd())));
        body.setExplanationUrl(info.getExplanationUrl());

        return ResponseEntity
                .ok()
                .header(HttpHeaders.RETRY_AFTER, Long.toString(retryAfter))
                .cacheControl(CacheControl.maxAge(Duration.ofSeconds(retryAfter)))
                .body(body);
    }

    private static String rfc3339(Instant instant) {
        return instant.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    private record ServingProfile(AcmeProfile acmeProfile, UUID raProfileUuid) {
    }
}

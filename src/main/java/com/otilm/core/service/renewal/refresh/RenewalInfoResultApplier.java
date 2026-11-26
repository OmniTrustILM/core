package com.otilm.core.service.renewal.refresh;

import com.otilm.api.model.connector.v3.certificate.CertificateRenewalInfoResponseDto;
import com.otilm.api.model.connector.v3.certificate.CertificateRenewalInfoResultDtoV3;
import com.otilm.core.messaging.jms.configuration.RenewalInfoProperties;
import com.otilm.core.service.SettingInternalService;
import com.otilm.core.service.handler.authority.RenewalInfoCallResult;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.service.writer.RenewalRefreshWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoubleSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Applies the answer of a connector to the renewal state of the certificates it was asked about: the windows the
 * authority advises, and when each certificate is refreshed next. All state lives in the database; nothing is kept in
 * memory between calls.
 */
@Component
public class RenewalInfoResultApplier {

    private static final Logger logger = LoggerFactory.getLogger(RenewalInfoResultApplier.class);
    private static final int MAX_EXPLANATION_URL_LENGTH = 2048;

    private final RenewalWindowWriter windowWriter;
    private final RenewalRefreshWriter refreshWriter;
    private final SettingInternalService settingService;
    private final RenewalInfoProperties properties;
    private final DoubleSupplier random;

    @Autowired
    public RenewalInfoResultApplier(RenewalWindowWriter windowWriter, RenewalRefreshWriter refreshWriter,
            SettingInternalService settingService, RenewalInfoProperties properties) {
        this(windowWriter, refreshWriter, settingService, properties, () -> ThreadLocalRandom.current().nextDouble());
    }

    RenewalInfoResultApplier(RenewalWindowWriter windowWriter, RenewalRefreshWriter refreshWriter,
            SettingInternalService settingService, RenewalInfoProperties properties, DoubleSupplier random) {
        this.windowWriter = windowWriter;
        this.refreshWriter = refreshWriter;
        this.settingService = settingService;
        this.properties = properties;
        this.random = random;
    }

    /**
     * Applies the result to the certificates of the batch.
     *
     * @param raProfileUuid the RA profile the batch was claimed for; a certificate that has left it takes no advice
     * @param referenceToCertificate the references sent to the connector and the certificates they stand for
     */
    public void apply(UUID raProfileUuid, Map<String, UUID> referenceToCertificate, RenewalInfoCallResult result,
            Instant now) {
        RenewalInfoSettings settings = settings();
        switch (result) {
            case RenewalInfoCallResult.Answered(var response) ->
                applyAnswer(raProfileUuid, referenceToCertificate, response, settings, now);
            case RenewalInfoCallResult.BackOff(var reason) -> {
                logger
                        .warn("Renewal information refresh of {} certificates backs off: {}",
                                referenceToCertificate.size(), reason);
                backOffAll(referenceToCertificate.values(), now);
            }
            case RenewalInfoCallResult.Suspend(var authority, var reason) -> {
                logger.warn("Renewal information refresh for authority {} suspended: {}", authority, reason);
                refreshWriter
                        .postpone(referenceToCertificate.values(), now.plusSeconds(settings.recheckIntervalSeconds()));
            }
        }
    }

    private void applyAnswer(UUID raProfileUuid, Map<String, UUID> referenceToCertificate,
            CertificateRenewalInfoResponseDto response, RenewalInfoSettings settings, Instant now) {
        Map<String, CertificateRenewalInfoResultDtoV3> results = resultsByReference(response);
        Integer responseRetryAfter = response == null ? null : response.getRetryAfter();
        for (Map.Entry<String, UUID> entry : referenceToCertificate.entrySet()) {
            UUID certificateUuid = entry.getValue();
            try {
                CertificateRenewalInfoResultDtoV3 item = results.get(entry.getKey());
                if (!applyItem(raProfileUuid, certificateUuid, item, responseRetryAfter, settings, now)) {
                    backOff(certificateUuid, item == null ? null : item.getRetryAfter(), responseRetryAfter, settings,
                            now);
                }
            } catch (RuntimeException e) {
                // The refresh lease returns the certificate to the next sweep.
                logger.warn("Renewal information of certificate {} could not be applied", certificateUuid, e);
            }
        }
    }

    /** The results by reference; a reference the connector answered more than once has no usable result. */
    private static Map<String, CertificateRenewalInfoResultDtoV3> resultsByReference(
            CertificateRenewalInfoResponseDto response) {
        Map<String, CertificateRenewalInfoResultDtoV3> results = new HashMap<>();
        if (response == null || response.getResults() == null) {
            return results;
        }
        Set<String> duplicated = new HashSet<>();
        for (CertificateRenewalInfoResultDtoV3 result : response.getResults()) {
            if (result != null && result.getReference() != null
                    && results.putIfAbsent(result.getReference(), result) != null) {
                duplicated.add(result.getReference());
            }
        }
        results.keySet().removeAll(duplicated);
        return results;
    }

    /** Applies a usable result; answers false when the item is to be retried instead. */
    private boolean applyItem(UUID raProfileUuid, UUID certificateUuid, CertificateRenewalInfoResultDtoV3 item,
            Integer responseRetryAfter, RenewalInfoSettings settings, Instant now) {
        if (item == null || item.getStatus() == null) {
            logger.debug("Certificate {}: no usable renewal information result", certificateUuid);
            return false;
        }
        switch (item.getStatus()) {
            case AVAILABLE -> {
                Window window = validWindow(item);
                if (window == null) {
                    logger.debug("Certificate {}: renewal window of the authority is invalid", certificateUuid);
                    return false;
                }
                WindowWrite advice = new WindowWrite.Authority(window, explanationUrl(item.getExplanationUrl()));
                if (windowWriter.writeAuthorityAdvice(certificateUuid, raProfileUuid, advice)) {
                    refreshWriter
                            .schedule(certificateUuid,
                                    RefreshSchedule
                                            .next(now, item.getRetryAfter(), responseRetryAfter, settings, random),
                                    0, false);
                }
                return true;
            }
            case UNKNOWN, NOT_SUPPORTED -> {
                logger
                        .debug("Certificate {}: the authority gives no renewal advice ({})", certificateUuid,
                                item.getStatus().getCode());
                if (windowWriter
                        .writeAuthorityAdvice(certificateUuid, raProfileUuid, new WindowWrite.AuthorityNoAdvice())) {
                    refreshWriter
                            .schedule(certificateUuid, now.plusSeconds(settings.recheckIntervalSeconds()), 0, true);
                }
                return true;
            }
            default -> {
                return false;
            }
        }
    }

    /** The explanation URL of the authority when it is an absolute http or https URL that fits; otherwise none. */
    static String explanationUrl(String url) {
        if (url == null || url.length() > MAX_EXPLANATION_URL_LENGTH) {
            return null;
        }
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            boolean web = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
            return web && uri.getHost() != null ? url : null;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static Window validWindow(CertificateRenewalInfoResultDtoV3 item) {
        OffsetDateTime start = item.getWindowStart();
        OffsetDateTime end = item.getWindowEnd();
        if (start == null || end == null || !end.isAfter(start)) {
            return null;
        }
        return new Window(start.toInstant(), end.toInstant());
    }

    private void backOffAll(Collection<UUID> certificateUuids, Instant now) {
        RenewalInfoSettings settings = settings();
        for (UUID certificateUuid : certificateUuids) {
            try {
                backOff(certificateUuid, null, null, settings, now);
            } catch (RuntimeException e) {
                logger
                        .warn("Renewal information refresh of certificate {} could not be rescheduled", certificateUuid,
                                e);
            }
        }
    }

    private void backOff(UUID certificateUuid, Integer itemRetryAfter, Integer responseRetryAfter,
            RenewalInfoSettings settings, Instant now) {
        boolean retryAfterGiven = itemRetryAfter != null || responseRetryAfter != null;
        refreshWriter
                .backOff(certificateUuid,
                        attempt -> retryAfterGiven
                                ? RefreshSchedule.next(now, itemRetryAfter, responseRetryAfter, settings, random)
                                : RefreshSchedule.backoff(now, attempt, properties.backoff()));
    }

    private RenewalInfoSettings settings() {
        return RenewalInfoSettings.current(settingService);
    }
}

package com.otilm.core.service.renewal.refresh;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.jms.configuration.RenewalInfoProperties;
import com.otilm.core.service.handler.authority.AuthorityProviderV3Adapter;
import com.otilm.core.service.handler.authority.RenewalInfoCallResult;
import com.otilm.core.service.handler.authority.RenewalInfoItem;
import jakarta.annotation.PreDestroy;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Refreshes claimed renewal information on a bounded thread pool, outside any lock or transaction. Batches of one
 * authority run in sequence; unfinished work is left to the lease and claimed again when it ends.
 */
@Component
public class RenewalInfoRefreshRunner {

    /** Authorities waiting for a thread, per thread. */
    static final int QUEUE_PER_THREAD = 25;

    private static final long SHUTDOWN_WAIT_SECONDS = 20;

    private static final Logger logger = LoggerFactory.getLogger(RenewalInfoRefreshRunner.class);

    private final RenewalInfoRefreshClaimer claimer;
    private final CertificateRepository certificateRepository;
    private final AttributeEngine attributeEngine;
    private final AuthorityProviderV3Adapter adapter;
    private final RenewalInfoResultApplier applier;
    private final ThreadPoolExecutor executor;

    @Autowired
    public RenewalInfoRefreshRunner(RenewalInfoRefreshClaimer claimer, CertificateRepository certificateRepository,
            AttributeEngine attributeEngine, AuthorityProviderV3Adapter adapter, RenewalInfoResultApplier applier,
            RenewalInfoProperties properties) {
        this(claimer, certificateRepository, attributeEngine, adapter, applier, properties.executorThreads(),
                properties.executorThreads() * QUEUE_PER_THREAD);
    }

    /** A runner with its own pool, for callers that size it themselves. */
    public RenewalInfoRefreshRunner(RenewalInfoRefreshClaimer claimer, CertificateRepository certificateRepository,
            AttributeEngine attributeEngine, AuthorityProviderV3Adapter adapter, RenewalInfoResultApplier applier,
            int threads, int queueCapacity) {
        this.claimer = claimer;
        this.certificateRepository = certificateRepository;
        this.attributeEngine = attributeEngine;
        this.adapter = adapter;
        this.applier = applier;
        this.executor = new ThreadPoolExecutor(threads, threads, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity), threadFactory(), new ThreadPoolExecutor.AbortPolicy());
    }

    /** Claims the due certificates and hands each authority's batches to the pool. */
    public void sweep() {
        claimer.claim(Instant.now()).forEach(this::submit);
    }

    /** Hands the batches to the pool; answers false when the pool is full or stopping, leaving them to the lease. */
    public boolean submit(AuthorityRefresh refresh) {
        try {
            executor.execute(() -> run(refresh));
            return true;
        } catch (RejectedExecutionException e) {
            logger
                    .warn("Renewal information refresh of {} certificates of authority {} deferred: no thread free; "
                            + "they are claimed again when their lease ends", refresh.certificateCount(),
                            refresh.authorityUuid());
            return false;
        }
    }

    /** Refreshes the batches of one authority one after another; a failing batch does not stop the others. */
    public void run(AuthorityRefresh refresh) {
        for (RefreshBatch batch : refresh.batches()) {
            try {
                refresh(batch);
            } catch (RuntimeException e) {
                logger
                        .warn("Renewal information refresh of {} certificates of RA profile {} failed; they are "
                                + "claimed again when their lease ends", batch.certificateUuids().size(),
                                batch.raProfileUuid(), e);
            }
        }
    }

    private void refresh(RefreshBatch batch) {
        List<Certificate> certificates = certificateRepository
                .findForRenewalInfoByUuidIn(batch.certificateUuids())
                .stream()
                .filter(certificate -> certificate.getRaProfile() != null
                        && batch.raProfileUuid().equals(certificate.getRaProfile().getUuid()))
                .toList();
        if (certificates.isEmpty()) {
            return;
        }
        RaProfile raProfile = certificates.get(0).getRaProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        Map<String, UUID> referenceToCertificate = new LinkedHashMap<>();
        List<RenewalInfoItem> items = new ArrayList<>(certificates.size());
        for (Certificate certificate : certificates) {
            if (certificate.getCertificateContent() == null) {
                logger.debug("Certificate {} has no content to ask for renewal information", certificate.getUuid());
                continue;
            }
            String reference = certificate.getUuid().toString();
            referenceToCertificate.put(reference, certificate.getUuid());
            items
                    .add(new RenewalInfoItem(reference, certificate.getCertificateContent().getContent(),
                            attributeEngine
                                    .getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo
                                            .builder(Resource.CERTIFICATE, certificate.getUuid())
                                            .connector(authority.getConnectorUuid())
                                            .build())));
        }
        if (items.isEmpty()) {
            return;
        }
        RenewalInfoCallResult result = adapter.renewalInfo(authority, raProfile, items);
        applier.apply(referenceToCertificate, result, Instant.now());
        logger
                .debug("Renewal information of {} certificates of RA profile {} refreshed: {}", items.size(),
                        raProfile.getUuid(), result.getClass().getSimpleName());
    }

    /** Stops taking work and waits a while for the batches in progress; the lease heals what is left. */
    @PreDestroy
    public void shutdown() {
        executor.shutdown();
        executor.getQueue().clear();
        try {
            if (!executor.awaitTermination(SHUTDOWN_WAIT_SECONDS, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private static ThreadFactory threadFactory() {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, "renewal-info-refresh-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}

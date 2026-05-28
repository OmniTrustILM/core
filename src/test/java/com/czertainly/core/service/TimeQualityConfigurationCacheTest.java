package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests verifying that the TQC cache is correctly populated on lookup
 * and evicted after mutations that change the configuration's observable state.
 */
class TimeQualityConfigurationCacheTest extends BaseSpringBootTest {

    @Autowired
    private TimeQualityConfigurationService timeQualityConfigurationService;

    @Autowired
    private TimeQualityConfigurationRepository timeQualityConfigurationRepository;

    @Autowired
    private CacheManager cacheManager;

    private TimeQualityConfiguration config;

    @BeforeEach
    void setUp() {
        Cache cache = cacheManager.getCache(CacheConfig.TIME_QUALITY_CONFIGURATION_CACHE);
        if (cache != null) {
            cache.clear();
        }

        config = new TimeQualityConfiguration();
        config.setName("test-tqc");
        config.setAccuracy(Duration.ofSeconds(1));
        config.setNtpServers(List.of("pool.ntp.org"));
        config.setNtpCheckInterval(Duration.ofSeconds(30));
        config.setNtpSamplesPerServer(4);
        config.setNtpCheckTimeout(Duration.ofSeconds(5));
        config.setNtpServersMinReachable(1);
        config.setMaxClockDrift(Duration.ofSeconds(1));
        config.setLeapSecondGuard(true);
        config = timeQualityConfigurationRepository.saveAndFlush(config);
    }

    @Test
    void firstLookupPopulatesCache() throws NotFoundException {
        Cache cache = cacheManager.getCache(CacheConfig.TIME_QUALITY_CONFIGURATION_CACHE);

        // given - cache is cold for this UUID
        assertThat(cache.get(config.getUuid(), TimeQualityConfigurationModel.class)).isNull();

        // when
        timeQualityConfigurationService.getTimeQualityConfigurationModel(config.getUuid());

        // then - model is stored in the cache keyed by UUID
        assertThat(cache.get(config.getUuid(), TimeQualityConfigurationModel.class)).isNotNull();
    }

    @Test
    void secondLookupReturnsCachedInstance() throws NotFoundException {
        // given - populate cache on first call
        TimeQualityConfigurationModel first =
                timeQualityConfigurationService.getTimeQualityConfigurationModel(config.getUuid());

        // when - second call for the same UUID
        TimeQualityConfigurationModel second =
                timeQualityConfigurationService.getTimeQualityConfigurationModel(config.getUuid());

        // then - the same Java object is returned, proving no second DB round-trip was made
        assertThat(second).isSameAs(first);
    }

    @Test
    void cacheIsEvictedAfterUpdate() throws AlreadyExistException, AttributeException, NotFoundException {
        // given - cache is warm
        timeQualityConfigurationService.getTimeQualityConfigurationModel(config.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.TIME_QUALITY_CONFIGURATION_CACHE);
        assertThat(cache.get(config.getUuid(), TimeQualityConfigurationModel.class)).isNotNull();

        // when - configuration is updated
        TimeQualityConfigurationRequestDto request = buildUpdateRequest("test-tqc-updated");
        timeQualityConfigurationService.updateTimeQualityConfiguration(
                SecuredUUID.fromUUID(config.getUuid()), request);

        // then - stale entry is gone
        assertThat(cache.get(config.getUuid(), TimeQualityConfigurationModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterDelete() throws NotFoundException {
        // given - cache is warm
        timeQualityConfigurationService.getTimeQualityConfigurationModel(config.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.TIME_QUALITY_CONFIGURATION_CACHE);
        assertThat(cache.get(config.getUuid(), TimeQualityConfigurationModel.class)).isNotNull();

        // when - configuration is deleted
        timeQualityConfigurationService.deleteTimeQualityConfiguration(
                SecuredUUID.fromUUID(config.getUuid()));

        // then - stale entry is gone
        assertThat(cache.get(config.getUuid(), TimeQualityConfigurationModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterBulkDelete() throws NotFoundException {
        // given - a second configuration and both are warm in the cache
        TimeQualityConfiguration second = new TimeQualityConfiguration();
        second.setName("test-tqc-2");
        second.setAccuracy(Duration.ofSeconds(2));
        second.setNtpServers(List.of("time.cloudflare.com"));
        second.setNtpCheckInterval(Duration.ofSeconds(60));
        second.setNtpSamplesPerServer(2);
        second.setNtpCheckTimeout(Duration.ofSeconds(3));
        second.setNtpServersMinReachable(1);
        second.setMaxClockDrift(Duration.ofSeconds(2));
        second.setLeapSecondGuard(false);
        second = timeQualityConfigurationRepository.saveAndFlush(second);

        timeQualityConfigurationService.getTimeQualityConfigurationModel(config.getUuid());
        timeQualityConfigurationService.getTimeQualityConfigurationModel(second.getUuid());

        Cache cache = cacheManager.getCache(CacheConfig.TIME_QUALITY_CONFIGURATION_CACHE);
        assertThat(cache.get(config.getUuid(), TimeQualityConfigurationModel.class)).isNotNull();
        assertThat(cache.get(second.getUuid(), TimeQualityConfigurationModel.class)).isNotNull();

        // when
        List<BulkActionMessageDto> errors = timeQualityConfigurationService.bulkDeleteTimeQualityConfigurations(
                List.of(SecuredUUID.fromUUID(config.getUuid()),
                        SecuredUUID.fromUUID(second.getUuid())));
        assertThat(errors).isEmpty();

        // then - both entries are evicted
        assertThat(cache.get(config.getUuid(), TimeQualityConfigurationModel.class)).isNull();
        assertThat(cache.get(second.getUuid(), TimeQualityConfigurationModel.class)).isNull();
    }

    // ──────────────────────────────────────────────────────────────────────────

    private TimeQualityConfigurationRequestDto buildUpdateRequest(String name) {
        TimeQualityConfigurationRequestDto request = new TimeQualityConfigurationRequestDto();
        request.setName(name);
        request.setAccuracy(Duration.ofSeconds(1));
        request.setNtpServers(List.of("pool.ntp.org"));
        request.setNtpCheckInterval(Duration.ofSeconds(30));
        request.setNtpSamplesPerServer(4);
        request.setNtpCheckTimeout(Duration.ofSeconds(5));
        request.setNtpServersMinReachable(1);
        request.setMaxClockDrift(Duration.ofSeconds(1));
        request.setLeapSecondGuard(true);
        request.setCustomAttributes(List.of());
        return request;
    }
}

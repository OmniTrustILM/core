package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.signing.TspProfileRepository;
import com.czertainly.core.model.signing.TspProfileModel;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests verifying that the TSP profile cache is correctly populated on lookup
 * and evicted after mutations that change the profile's observable state.
 */
class TspProfileCacheTest extends BaseSpringBootTest {

    @Autowired
    private TspProfileService tspProfileService;

    @Autowired
    private TspProfileRepository tspProfileRepository;

    @Autowired
    private CacheManager cacheManager;

    private TspProfile profile;

    @BeforeEach
    void setUp() {
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        if (cache != null) {
            cache.clear();
        }

        profile = new TspProfile();
        profile.setName("test-tsp-profile");
        profile.setDescription("test description");
        profile.setEnabled(true);
        profile = tspProfileRepository.saveAndFlush(profile);
    }

    @Test
    void firstLookupPopulatesCache() throws NotFoundException {
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);

        // given - cache is cold for this profile name
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();

        // when
        tspProfileService.getTspProfile(profile.getName());

        // then - the model is stored in the cache keyed by profile name
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();
    }

    @Test
    void secondLookupReturnsCachedInstance() throws NotFoundException {
        // given - populate cache on first call
        TspProfileModel first = tspProfileService.getTspProfile(profile.getName());

        // when - second call for the same profile name
        TspProfileModel second = tspProfileService.getTspProfile(profile.getName());

        // then - the same Java object is returned, proving no second DB round-trip was made
        assertThat(second).isSameAs(first);
    }

    @Test
    void cacheIsEvictedAfterUpdate() throws AlreadyExistException, AttributeException, NotFoundException {
        // given - cache is warm under the original name
        tspProfileService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - profile is renamed; the service captures oldName and evicts after commit
        String oldName = profile.getName();
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("renamed-tsp-profile");
        request.setDescription(profile.getDescription());
        request.setCustomAttributes(List.of());
        tspProfileService.updateTspProfile(SecuredUUID.fromUUID(profile.getUuid()), request);

        // then - old name entry is gone
        assertThat(cache.get(oldName, TspProfileModel.class)).isNull();

        // and - subsequent lookup under new name re-populates the cache
        tspProfileService.getTspProfile("renamed-tsp-profile");
        assertThat(cache.get("renamed-tsp-profile", TspProfileModel.class)).isNotNull();
    }

    @Test
    void cacheIsEvictedAfterSameNameUpdate() throws AlreadyExistException, AttributeException, NotFoundException {
        // given - cache is warm
        tspProfileService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - description is updated but name is unchanged
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(profile.getName());
        request.setDescription("updated description");
        request.setCustomAttributes(List.of());
        tspProfileService.updateTspProfile(SecuredUUID.fromUUID(profile.getUuid()), request);

        // then - stale entry (old description) is gone
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterDelete() throws NotFoundException {
        // given - cache is warm
        tspProfileService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - profile is deleted
        tspProfileService.deleteTspProfile(SecuredUUID.fromUUID(profile.getUuid()));

        // then - stale entry is gone
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterEnable() throws NotFoundException {
        // given - profile is disabled and cache is warm
        profile.setEnabled(false);
        profile = tspProfileRepository.saveAndFlush(profile);
        tspProfileService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - profile is enabled; the service evicts the entry after the transaction commits
        tspProfileService.enableTspProfile(SecuredUUID.fromUUID(profile.getUuid()));

        // then - stale entry (showing enabled=false) is gone
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();

        // and - subsequent lookup re-populates the cache with the updated state
        TspProfileModel repopulated = tspProfileService.getTspProfile(profile.getName());
        assertThat(repopulated.enabled()).isTrue();
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();
    }

    @Test
    void cacheIsEvictedAfterDisable() throws NotFoundException {
        // given - profile is enabled and cache is warm
        tspProfileService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - profile is disabled
        tspProfileService.disableTspProfile(SecuredUUID.fromUUID(profile.getUuid()));

        // then - stale entry (showing enabled=true) is gone
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();

        // and - subsequent lookup re-populates the cache with the updated state
        TspProfileModel repopulated = tspProfileService.getTspProfile(profile.getName());
        assertThat(repopulated.enabled()).isFalse();
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();
    }

    @Test
    void bulkDeleteEvictsAllProfileCacheEntries() throws NotFoundException {
        // given - a second profile and both are warm in the cache
        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        second.setEnabled(true);
        second = tspProfileRepository.saveAndFlush(second);
        tspProfileService.getTspProfile(profile.getName());
        tspProfileService.getTspProfile(second.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();
        assertThat(cache.get(second.getName(), TspProfileModel.class)).isNotNull();

        // when
        tspProfileService.bulkDeleteTspProfiles(List.of(
                SecuredUUID.fromUUID(profile.getUuid()),
                SecuredUUID.fromUUID(second.getUuid())
        ));

        // then - both entries are evicted
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();
        assertThat(cache.get(second.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void bulkEnableEvictsAllProfileCacheEntries() throws NotFoundException {
        // given - two disabled profiles with warm cache entries
        profile.setEnabled(false);
        profile = tspProfileRepository.saveAndFlush(profile);
        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        second.setEnabled(false);
        second = tspProfileRepository.saveAndFlush(second);
        tspProfileService.getTspProfile(profile.getName());
        tspProfileService.getTspProfile(second.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();
        assertThat(cache.get(second.getName(), TspProfileModel.class)).isNotNull();

        // when
        tspProfileService.bulkEnableTspProfiles(List.of(
                SecuredUUID.fromUUID(profile.getUuid()),
                SecuredUUID.fromUUID(second.getUuid())
        ));

        // then - both stale entries are evicted
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();
        assertThat(cache.get(second.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void bulkDisableEvictsAllProfileCacheEntries() throws NotFoundException {
        // given - two enabled profiles with warm cache entries
        TspProfile second = new TspProfile();
        second.setName("second-tsp-profile");
        second.setEnabled(true);
        second = tspProfileRepository.saveAndFlush(second);
        tspProfileService.getTspProfile(profile.getName());
        tspProfileService.getTspProfile(second.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();
        assertThat(cache.get(second.getName(), TspProfileModel.class)).isNotNull();

        // when
        tspProfileService.bulkDisableTspProfiles(List.of(
                SecuredUUID.fromUUID(profile.getUuid()),
                SecuredUUID.fromUUID(second.getUuid())
        ));

        // then - both stale entries are evicted
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();
        assertThat(cache.get(second.getName(), TspProfileModel.class)).isNull();
    }
}

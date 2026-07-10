package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.TspProfileExternalService;
import com.otilm.core.service.TspProfileInternalService;
import com.otilm.core.util.BaseSpringBootTest;
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
class TspProfileCacheITest extends BaseSpringBootTest {

    private static final String BASE_URL = "http://localhost";

    @Autowired
    private TspProfileExternalService tspProfileService;

    @Autowired
    private TspProfileInternalService tspProfileInternalService;

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
        tspProfileInternalService.getTspProfile(profile.getName());

        // then - the model is stored in the cache keyed by profile name
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();
    }

    @Test
    void secondLookupReturnsCachedInstance() throws NotFoundException {
        // given - populate cache on first call
        TspProfileModel first = tspProfileInternalService.getTspProfile(profile.getName());

        // when - second call for the same profile name
        TspProfileModel second = tspProfileInternalService.getTspProfile(profile.getName());

        // then - the same Java object is returned, proving no second DB round-trip was made
        assertThat(second).isSameAs(first);
    }

    @Test
    void cacheIsEvictedAfterUpdate() throws AlreadyExistException, AttributeException, NotFoundException {
        // given - cache is warm under the original name
        tspProfileInternalService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - profile is renamed; the service captures oldName and evicts after commit
        String oldName = profile.getName();
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("renamed-tsp-profile");
        request.setDescription(profile.getDescription());
        request.setCustomAttributes(List.of());
        tspProfileService.updateTspProfile(SecuredUUID.fromUUID(profile.getUuid()), request, BASE_URL);

        // then - old name entry is gone
        assertThat(cache.get(oldName, TspProfileModel.class)).isNull();

        // and - subsequent lookup under new name re-populates the cache
        tspProfileInternalService.getTspProfile("renamed-tsp-profile");
        assertThat(cache.get("renamed-tsp-profile", TspProfileModel.class)).isNotNull();
    }

    @Test
    void uuidLookupPopulatesCacheUnderUuidKey() throws NotFoundException {
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);

        // given - cache is cold for this profile UUID
        assertThat(cache.get(profile.getUuid(), TspProfileModel.class)).isNull();

        // when - looked up by UUID (the signing-profile hot path)
        tspProfileInternalService.getTspProfile(profile.getUuid());

        // then - the model is stored keyed by UUID
        assertThat(cache.get(profile.getUuid(), TspProfileModel.class)).isNotNull();
    }

    @Test
    void uuidLookupSurvivesRename() throws AlreadyExistException, AttributeException, NotFoundException {
        // given - cache is warm under the original UUID, the signing-profile path's stable reference
        tspProfileInternalService.getTspProfile(profile.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getUuid(), TspProfileModel.class)).isNotNull();

        // when - the profile is renamed
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName("renamed-tsp-profile");
        request.setDescription(profile.getDescription());
        request.setCustomAttributes(List.of());
        tspProfileService.updateTspProfile(SecuredUUID.fromUUID(profile.getUuid()), request, BASE_URL);

        // then - the stale UUID entry is evicted (would otherwise carry the old name)
        assertThat(cache.get(profile.getUuid(), TspProfileModel.class)).isNull();

        // and - a fresh UUID lookup still resolves and reflects the new name; the rename never dangles
        TspProfileModel repopulated = tspProfileInternalService.getTspProfile(profile.getUuid());
        assertThat(repopulated.name()).isEqualTo("renamed-tsp-profile");
        assertThat(cache.get(profile.getUuid(), TspProfileModel.class)).isNotNull();
    }

    @Test
    void cacheIsEvictedAfterSameNameUpdate() throws AlreadyExistException, AttributeException, NotFoundException {
        // given - cache is warm
        tspProfileInternalService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - description is updated but name is unchanged
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(profile.getName());
        request.setDescription("updated description");
        request.setCustomAttributes(List.of());
        tspProfileService.updateTspProfile(SecuredUUID.fromUUID(profile.getUuid()), request, BASE_URL);

        // then - stale entry (old description) is gone
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterDelete() throws NotFoundException {
        // given - cache is warm
        tspProfileInternalService.getTspProfile(profile.getName());
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
        tspProfileInternalService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - profile is enabled; the service evicts the entry after the transaction commits
        tspProfileService.enableTspProfile(SecuredUUID.fromUUID(profile.getUuid()));

        // then - stale entry (showing enabled=false) is gone
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();

        // and - subsequent lookup re-populates the cache with the updated state
        TspProfileModel repopulated = tspProfileInternalService.getTspProfile(profile.getName());
        assertThat(repopulated.enabled()).isTrue();
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();
    }

    @Test
    void cacheIsEvictedAfterDisable() throws NotFoundException {
        // given - profile is enabled and cache is warm
        tspProfileInternalService.getTspProfile(profile.getName());
        Cache cache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNotNull();

        // when - profile is disabled
        tspProfileService.disableTspProfile(SecuredUUID.fromUUID(profile.getUuid()));

        // then - stale entry (showing enabled=true) is gone
        assertThat(cache.get(profile.getName(), TspProfileModel.class)).isNull();

        // and - subsequent lookup re-populates the cache with the updated state
        TspProfileModel repopulated = tspProfileInternalService.getTspProfile(profile.getName());
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
        tspProfileInternalService.getTspProfile(profile.getName());
        tspProfileInternalService.getTspProfile(second.getName());
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
        tspProfileInternalService.getTspProfile(profile.getName());
        tspProfileInternalService.getTspProfile(second.getName());
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
        tspProfileInternalService.getTspProfile(profile.getName());
        tspProfileInternalService.getTspProfile(second.getName());
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

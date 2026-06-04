package com.czertainly.core.service.signingprofile;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.profile.SigningProfileDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileRequestDto;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.model.signing.TspProfileModel;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.TspProfileService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that every signing-profile mutation invalidates {@link CacheConfig#TSP_PROFILE_CACHE},
 * so cached {@link TspProfileModel} instances that transitively depend on signing-profile state
 * never serve stale data after a commit.
 */
class SigningProfileCacheCoherenceTest extends SigningProfileTestBase {

    @Autowired
    private TspProfileService tspProfileService;

    @Autowired
    private CacheManager cacheManager;

    private TspProfile warmTspProfile() {
        TspProfile tsp = new TspProfile();
        tsp.setName("tsp-for-cache-coherence");
        tsp.setEnabled(true);
        tsp = tspRepository.saveAndFlush(tsp);
        return tsp;
    }

    private Cache cache() {
        Cache c = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        if (c != null) c.clear();
        return c;
    }

    @Test
    void cacheIsClearedAfterSigningProfileUpdate()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // given - a warm TSP cache entry
        TspProfile tsp = warmTspProfile();
        Cache cache = cache();
        tspProfileService.getTspProfile(tsp.getName());
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNotNull();

        // when - the signing profile is updated
        SigningProfileRequestDto update = buildDelegatedRawRequest(savedProfile.getName());
        update.setDescription("updated description");
        signingProfileService.updateSigningProfile(SecuredUUID.fromUUID(savedProfile.getUuid()), update);

        // then - the TSP cache entry has been evicted
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void cacheIsClearedAfterSigningProfileDelete()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // given - a warm TSP cache entry and a deletable signing profile (not referenced as default)
        SigningProfileDto deletable = signingProfileService.createSigningProfile(
                buildDelegatedRawRequest("deletable-signing-profile"));
        TspProfile tsp = warmTspProfile();
        Cache cache = cache();
        tspProfileService.getTspProfile(tsp.getName());
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNotNull();

        // when
        signingProfileService.deleteSigningProfile(SecuredUUID.fromString(deletable.getUuid()));

        // then
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void cacheIsClearedAfterSigningProfileEnable() throws NotFoundException {
        // given - a disabled signing profile and a warm TSP cache entry
        savedProfile.setEnabled(false);
        signingProfileRepository.saveAndFlush(savedProfile);
        TspProfile tsp = warmTspProfile();
        Cache cache = cache();
        tspProfileService.getTspProfile(tsp.getName());
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNotNull();

        // when
        signingProfileService.enableSigningProfile(SecuredUUID.fromUUID(savedProfile.getUuid()));

        // then
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void cacheIsClearedAfterSigningProfileDisable() throws NotFoundException {
        // given - an enabled signing profile (default after setUp) and a warm TSP cache entry
        TspProfile tsp = warmTspProfile();
        Cache cache = cache();
        tspProfileService.getTspProfile(tsp.getName());
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNotNull();

        // when
        signingProfileService.disableSigningProfile(SecuredUUID.fromUUID(savedProfile.getUuid()));

        // then
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void cacheIsClearedAfterTspActivation()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // given - a signing profile whose workflow supports TSP activation, and a warm TSP cache entry
        SigningProfileDto profileDto = signingProfileService.createSigningProfile(
                buildDelegatedTimestampingRequest("timestamping-for-cache-activate"));
        TspProfile tsp = warmTspProfile();
        Cache cache = cache();
        tspProfileService.getTspProfile(tsp.getName());
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNotNull();

        // when - this signing profile is activated as the TSP backend
        signingProfileService.activateTsp(SecuredUUID.fromString(profileDto.getUuid()), tsp.getSecuredUuid());

        // then - the TSP cache entry has been evicted
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNull();
    }

    @Test
    void cacheIsClearedAfterTspDeactivation()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // given - a signing profile already activated against a TSP profile, with a warm cache entry
        SigningProfileDto profileDto = signingProfileService.createSigningProfile(
                buildDelegatedTimestampingRequest("timestamping-for-cache-deactivate"));
        TspProfile tsp = warmTspProfile();
        signingProfileService.activateTsp(SecuredUUID.fromString(profileDto.getUuid()), tsp.getSecuredUuid());
        Cache cache = cache();
        tspProfileService.getTspProfile(tsp.getName());
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNotNull();

        // when
        signingProfileService.deactivateTsp(SecuredUUID.fromString(profileDto.getUuid()));

        // then
        assertThat(cache.get(tsp.getName(), TspProfileModel.class)).isNull();
    }
}

package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningRecordRetentionSweeperTest extends BaseSpringBootTest {

    @Autowired
    private SigningRecordRetentionSweeper sweeper;
    @Autowired
    private SigningProfileRepository profileRepository;
    @Autowired
    private SigningProfileVersionRepository profileVersionRepository;
    @Autowired
    private SigningRecordRepository recordRepository;

    @Test
    void sweep_deletesOnlyRecordsOlderThanProfileRetention() {
        // given
        var retentionDays = 7;
        var beforeRetentionWindow = Instant.now().minus(Duration.ofDays(10));
        var withinRetentionWindow = Instant.now();
        SigningProfile profile = insertProfileWithRetention("ret", retentionDays);
        insertRecordSignedAt(profile, beforeRetentionWindow);
        SigningRecord fresh = insertRecordSignedAt(profile, withinRetentionWindow);

        // when
        sweeper.sweep();

        // then
        assertEquals(1, recordRepository.count());
        assertEquals(fresh.getUuid(), recordRepository.findAll().getFirst().getUuid());
    }

    @Test
    void sweep_keepsRecordsWhenProfileHasNoRetention() {
        // given
        var signedLongAgo = Instant.now().minus(Duration.ofDays(365));
        SigningProfile profile = insertProfileWithoutRetention("ret-null");
        SigningRecord old = insertRecordSignedAt(profile, signedLongAgo);

        // when
        sweeper.sweep();

        // then
        assertEquals(1, recordRepository.count());
        assertTrue(recordRepository.existsById(old.getUuid()));
    }

    private SigningProfile insertProfileWithRetention(String name, int retentionDays) {
        return insertProfile(name, retentionDays);
    }

    private SigningProfile insertProfileWithoutRetention(String name) {
        return insertProfile(name, null);
    }

    private SigningProfile insertProfile(String name, Integer retentionDays) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(1);
        profile = profileRepository.saveAndFlush(profile);
        insertProfileVersion(profile, 1, retentionDays);
        return profile;
    }

    private SigningRecord insertRecordSignedAt(SigningProfile profile, Instant signingTime) {
        return insertRecordSignedAt(profile.getUuid(), signingTime);
    }

    private SigningRecord insertRecordSignedAt(UUID signingProfileUuid, Instant signingTime) {
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setSigningProfileUuid(signingProfileUuid);
        signingRecord.setSigningProfileVersion(1);
        signingRecord.setProtocol(SigningProtocol.TSP);
        signingRecord.setSigningTime(signingTime);
        return recordRepository.saveAndFlush(signingRecord);
    }

    /**
     * Persists the version row a record references by int, mirroring {@link com.otilm.core.integration.dao.repository.signing.SigningRecordRepositoryITest SigningRecordRepositoryITest}, so the
     * fixtures stay valid should the {@code (signing_profile_uuid, signing_profile_version)} reference ever
     * become a hard FK.
     */
    private void insertProfileVersion(SigningProfile profile, int version, Integer retentionDays) {
        SigningProfileVersion profileVersion = new SigningProfileVersion();
        profileVersion.setSigningProfile(profile);
        profileVersion.setVersion(version);
        profileVersion.setSigningScheme(SigningScheme.DELEGATED);
        profileVersion.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profileVersion.setRetentionDays(retentionDays);
        profileVersionRepository.saveAndFlush(profileVersion);
    }
}

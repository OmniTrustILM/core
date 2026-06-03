package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestPropertySource(properties = "scheduled-tasks.enabled=true")
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

    @Test
    void sweep_keepsOrphanRecordsWithoutProfile() {
        // given
        var signedLongAgo = Instant.now().minus(Duration.ofDays(365));
        SigningRecord orphan = insertOrphanRecordSignedAt(signedLongAgo);

        // when
        sweeper.sweep();

        // then
        assertEquals(1, recordRepository.count());
        assertTrue(recordRepository.existsById(orphan.getUuid()));
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
        profile.setRetentionDays(retentionDays);
        profile = profileRepository.saveAndFlush(profile);
        insertProfileVersion(profile, 1);
        return profile;
    }

    private SigningRecord insertRecordSignedAt(SigningProfile profile, Instant signingTime) {
        return insertRecordSignedAt(profile.getUuid(), signingTime);
    }

    private SigningRecord insertOrphanRecordSignedAt(Instant signingTime) {
        return insertRecordSignedAt((UUID) null, signingTime);
    }

    private SigningRecord insertRecordSignedAt(UUID signingProfileUuid, Instant signingTime) {
        SigningRecord record = new SigningRecord();
        record.setSigningProfileUuid(signingProfileUuid);
        record.setSigningProfileVersion(1);
        record.setSigningTime(signingTime);
        return recordRepository.saveAndFlush(record);
    }

    /**
     * Persists the version row a record references by int, mirroring {@code SigningRecordRepositoryTest}, so the
     * fixtures stay valid should the {@code (signing_profile_uuid, signing_profile_version)} reference ever
     * become a hard FK.
     */
    private void insertProfileVersion(SigningProfile profile, int version) {
        SigningProfileVersion profileVersion = new SigningProfileVersion();
        profileVersion.setSigningProfile(profile);
        profileVersion.setVersion(version);
        profileVersion.setSigningScheme(SigningScheme.DELEGATED);
        profileVersion.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profileVersionRepository.saveAndFlush(profileVersion);
    }
}

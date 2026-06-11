package com.otilm.core.service.writer.signingrecord;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the single {@link SigningRecordWriter}'s deletion contribution on top of the repository queries (the
 * queries' retention/null/flag semantics are covered in {@code SigningRecordRepositoryTest}): each call runs in
 * its own {@code REQUIRES_NEW} transaction, so it deletes and commits with no ambient transaction held by the
 * caller. For {@code deleteExpiredBatch} the {@code limit} bounds a single batch, which is the signal the
 * sweeper uses to detect a full batch and keep looping; {@code deleteByUuid} removes the single
 * operator-selected row. The writer's inbound and drain paths are covered through the strategy integration
 * tests and {@code SigningRecordOutboxDrainerTest}.
 */
class SigningRecordWriterTest extends BaseSpringBootTest {

    private static final int LIMIT_LARGER_THAN_FIXTURES = 1000;

    @Autowired
    private SigningRecordWriter writer;
    @Autowired
    private SigningProfileRepository profileRepository;
    @Autowired
    private SigningProfileVersionRepository profileVersionRepository;
    @Autowired
    private SigningRecordRepository recordRepository;

    @Test
    void deleteByUuid_deletesTheSelectedRecordAndCommitsWithoutAmbientTransaction() {
        // given
        var anyRetentionDays = 7;
        SigningProfile profile = insertProfileWithRetention("del-by-uuid", anyRetentionDays);
        SigningRecord signingRecord = insertRecordSignedAt(profile, Instant.now());

        // when
        writer.deleteByUuid(signingRecord.getUuid());

        // then
        assertFalse(recordRepository.existsById(signingRecord.getUuid()));
    }

    @Test
    void deleteExpiredBatch_deletesExpiredRecordAndCommitsWithoutAmbientTransaction() {
        // given
        var retentionDays = 7;
        var beforeRetentionWindow = Instant.now().minus(Duration.ofDays(10));
        SigningProfile profile = insertProfileWithRetention("ret-expired", retentionDays);
        SigningRecord expired = insertRecordSignedAt(profile, beforeRetentionWindow);

        // when
        int deleted = writer.deleteExpiredBatch(LIMIT_LARGER_THAN_FIXTURES);

        // then
        assertEquals(1, deleted);
        assertFalse(recordRepository.existsById(expired.getUuid()));
    }

    @Test
    void deleteExpiredBatch_returnsZeroAndKeepsRecordWithinRetention() {
        // given
        var retentionDays = 30;
        var withinRetentionWindow = Instant.now().minus(Duration.ofDays(5));
        SigningProfile profile = insertProfileWithRetention("ret-within", retentionDays);
        SigningRecord fresh = insertRecordSignedAt(profile, withinRetentionWindow);

        // when
        int deleted = writer.deleteExpiredBatch(LIMIT_LARGER_THAN_FIXTURES);

        // then
        assertEquals(0, deleted);
        assertTrue(recordRepository.existsById(fresh.getUuid()));
    }

    @Test
    void deleteExpiredBatch_deletesAtMostLimitRecordsPerCall() {
        // given
        var retentionDays = 7;
        var beforeRetentionWindow = Instant.now().minus(Duration.ofDays(10));
        var expiredRecordCount = 3;
        var batchLimit = 2;
        SigningProfile profile = insertProfileWithRetention("ret-batch", retentionDays);
        for (int i = 0; i < expiredRecordCount; i++) {
            insertRecordSignedAt(profile, beforeRetentionWindow);
        }

        // when
        int deleted = writer.deleteExpiredBatch(batchLimit);

        // then
        assertEquals(batchLimit, deleted);
        assertEquals(expiredRecordCount - batchLimit, recordRepository.count());
    }

    @Test
    void deleteExpiredBatch_committedCallsClearTheBacklogAcrossInvocations() {
        // given
        var retentionDays = 7;
        var beforeRetentionWindow = Instant.now().minus(Duration.ofDays(10));
        var expiredRecordCount = 3;
        var batchLimit = 2;
        SigningProfile profile = insertProfileWithRetention("ret-drain", retentionDays);
        for (int i = 0; i < expiredRecordCount; i++) {
            insertRecordSignedAt(profile, beforeRetentionWindow);
        }

        // when
        int firstBatch = writer.deleteExpiredBatch(batchLimit);
        int secondBatch = writer.deleteExpiredBatch(batchLimit);

        // then
        assertEquals(batchLimit, firstBatch);
        assertEquals(expiredRecordCount - batchLimit, secondBatch);
        assertEquals(0, recordRepository.count());
    }

    private SigningProfile insertProfileWithRetention(String name, int retentionDays) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setEnabled(false);
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(1);
        profile = profileRepository.saveAndFlush(profile);
        insertProfileVersion(profile, 1, retentionDays);
        return profile;
    }

    private SigningRecord insertRecordSignedAt(SigningProfile profile, Instant signingTime) {
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setSigningProfileUuid(profile.getUuid());
        signingRecord.setSigningProfileVersion(1);
        signingRecord.setSigningTime(signingTime);
        return recordRepository.saveAndFlush(signingRecord);
    }

    /**
     * Persists the version row a record references by int, mirroring {@code SigningRecordRepositoryTest}, so the
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

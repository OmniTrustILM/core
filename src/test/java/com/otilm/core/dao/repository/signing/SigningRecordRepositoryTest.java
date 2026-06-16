package com.otilm.core.dao.repository.signing;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.IntSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningRecordRepositoryTest extends BaseSpringBootTest {

    private static final int BATCH_LIMIT_LARGER_THAN_FIXTURES = 1000;

    @Autowired
    private SigningRecordRepository repository;

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    /**
     * Wraps the {@code @Modifying} native delete queries, which require an active transaction. Fixtures are
     * committed outside it, mirroring the retention sweeper running the delete over already-persisted data.
     */
    private TransactionTemplate transactionTemplate;

    @BeforeEach
    void initTransactionTemplate() {
        transactionTemplate = new TransactionTemplate(transactionManager);
    }

    /**
     * Runs a {@code @Modifying} delete (which requires an active transaction) in its own short transaction over
     * the already-committed fixtures, returning the affected row count as a primitive.
     */
    private int doInTransaction(IntSupplier delete) {
        return Objects.requireNonNull(transactionTemplate.execute(status -> delete.getAsInt()));
    }

    @Test
    void existsBySigningProfileUuidAndSigningProfileVersion_trueWhenRecordExists() {
        // given
        var version = 3;
        SigningProfile profile = insertProfile("exists-match");
        insertProfileVersion(profile, version);
        insertRecord(profile, version);

        // when
        boolean exists = repository.existsBySigningProfileUuidAndSigningProfileVersion(profile.getUuid(), version);

        // then
        assertTrue(exists);
    }

    @Test
    void existsBySigningProfileUuidAndSigningProfileVersion_falseForDifferentVersion() {
        // given
        var recordedVersion = 1;
        var queriedVersion = 2;
        SigningProfile profile = insertProfile("exists-other-version");
        insertProfileVersion(profile, recordedVersion);
        insertRecord(profile, recordedVersion);

        // when
        boolean exists = repository.existsBySigningProfileUuidAndSigningProfileVersion(profile.getUuid(), queriedVersion);

        // then
        assertFalse(exists);
    }

    @Test
    void protocol_roundTripsThroughThePersistedRecord() {
        // given
        SigningProfile profile = insertProfile("protocol-roundtrip");
        insertProfileVersion(profile, 1);
        SigningRecord record = insertRecordWithProtocol(profile, SigningProtocol.CSC_API);

        // when
        SigningRecord reloaded = repository.findById(record.getUuid()).orElseThrow();

        // then
        assertEquals(SigningProtocol.CSC_API, reloaded.getProtocol());
    }

    @Test
    void deleteExpiredByRetention_deletesRecordsOlderThanRetentionWindow() {
        // given
        var retentionDays = 7;
        var beforeRetentionWindow = Instant.now().minus(Duration.ofDays(10));
        SigningProfile profile = insertProfile("retention-expired");
        insertProfileVersion(profile, 1, retentionDays, false);
        SigningRecord expired = insertRecordSignedAt(profile, 1, beforeRetentionWindow);

        // when
        int deleted = doInTransaction(() -> repository.deleteExpiredByRetention(BATCH_LIMIT_LARGER_THAN_FIXTURES));

        // then
        assertEquals(1, deleted);
        assertFalse(repository.existsById(expired.getUuid()));
    }

    @Test
    void deleteExpiredByRetention_keepsRecordsWithinRetentionWindow() {
        // given
        var retentionDays = 30;
        var withinRetentionWindow = Instant.now().minus(Duration.ofDays(5));
        SigningProfile profile = insertProfile("retention-within");
        insertProfileVersion(profile, 1, retentionDays, false);
        SigningRecord fresh = insertRecordSignedAt(profile, 1, withinRetentionWindow);

        // when
        int deleted = doInTransaction(() -> repository.deleteExpiredByRetention(BATCH_LIMIT_LARGER_THAN_FIXTURES));

        // then
        assertEquals(0, deleted);
        assertTrue(repository.existsById(fresh.getUuid()));
    }

    @Test
    void deleteExpiredByRetention_keepsRecordsOfProfilesWithoutRetention() {
        // given
        var noRetention = (Integer) null;
        var createdLongAgo = Instant.now().minus(Duration.ofDays(1000));
        SigningProfile profile = insertProfile("retention-disabled");
        insertProfileVersion(profile, 1, noRetention, false);
        SigningRecord old = insertRecordSignedAt(profile, 1, createdLongAgo);

        // when
        int deleted = doInTransaction(() -> repository.deleteExpiredByRetention(BATCH_LIMIT_LARGER_THAN_FIXTURES));

        // then
        assertEquals(0, deleted);
        assertTrue(repository.existsById(old.getUuid()));
    }

    @Test
    void deleteRetrievedAndFlagged_deletesRetrievedRecordsOfFlaggedProfiles() {
        // given
        var retrievedAt = Instant.now();
        SigningProfile profile = insertProfile("flagged-retrieved");
        insertProfileVersion(profile, 1, null, true);
        SigningRecord retrieved = insertRecord(profile, 1, retrievedAt);

        // when
        int deleted = doInTransaction(() -> repository.deleteRetrievedAndFlagged(BATCH_LIMIT_LARGER_THAN_FIXTURES));

        // then
        assertEquals(1, deleted);
        assertFalse(repository.existsById(retrieved.getUuid()));
    }

    @Test
    void deleteRetrievedAndFlagged_keepsRetrievedRecordsWhenProfileNotFlagged() {
        // given
        var retrievedAt = Instant.now();
        SigningProfile profile = insertProfile("not-flagged-retrieved");
        insertProfileVersion(profile, 1);
        SigningRecord retrieved = insertRecord(profile, 1, retrievedAt);

        // when
        int deleted = doInTransaction(() -> repository.deleteRetrievedAndFlagged(BATCH_LIMIT_LARGER_THAN_FIXTURES));

        // then
        assertEquals(0, deleted);
        assertTrue(repository.existsById(retrieved.getUuid()));
    }

    @Test
    void deleteRetrievedAndFlagged_keepsNotYetRetrievedRecordsOfFlaggedProfiles() {
        // given
        var notRetrieved = (Instant) null;
        SigningProfile profile = insertProfile("flagged-not-retrieved");
        insertProfileVersion(profile, 1, null, true);
        SigningRecord pending = insertRecord(profile, 1, notRetrieved);

        // when
        int deleted = doInTransaction(() -> repository.deleteRetrievedAndFlagged(BATCH_LIMIT_LARGER_THAN_FIXTURES));

        // then
        assertEquals(0, deleted);
        assertTrue(repository.existsById(pending.getUuid()));
    }

    private SigningProfile insertProfile(String name) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setEnabled(false);
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(1);
        return signingProfileRepository.saveAndFlush(profile);
    }

    private SigningRecord insertRecord(SigningProfile profile, int version) {
        return insertRecord(profile, version, null, Instant.now());
    }

    private SigningRecord insertRecord(SigningProfile profile, int version, Instant signedDocumentRetrievedAt) {
        return insertRecord(profile, version, signedDocumentRetrievedAt, Instant.now());
    }

    private SigningRecord insertRecordSignedAt(SigningProfile profile, int version, Instant createdAt) {
        return insertRecord(profile, version, null, createdAt);
    }

    private SigningRecord insertRecord(SigningProfile profile, int version, Instant signedDocumentRetrievedAt,
                                       Instant signingTime) {
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setSigningProfileUuid(profile.getUuid());
        signingRecord.setSigningProfileVersion(version);
        signingRecord.setProtocol(SigningProtocol.TSP);
        signingRecord.setSigningTime(signingTime);
        signingRecord.setSignedDocumentRetrievedAt(signedDocumentRetrievedAt);
        return repository.saveAndFlush(signingRecord);
    }

    private SigningRecord insertRecordWithProtocol(SigningProfile profile, SigningProtocol protocol) {
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setSigningProfileUuid(profile.getUuid());
        signingRecord.setSigningProfileVersion(1);
        signingRecord.setProtocol(protocol);
        signingRecord.setSigningTime(Instant.now());
        return repository.saveAndFlush(signingRecord);
    }

    private void insertProfileVersion(SigningProfile profile, int version) {
        insertProfileVersion(profile, version, null, false);
    }

    /**
     * Persists the version row a record references by int, carrying the versioned retention / delete-after-retrieval
     * policy the sweep queries now join on, so the fixtures stay valid should the
     * {@code (signing_profile_uuid, signing_profile_version)} reference ever become a hard FK.
     */
    private void insertProfileVersion(SigningProfile profile, int version, Integer retentionDays, boolean deleteAfterRetrieval) {
        SigningProfileVersion profileVersion = new SigningProfileVersion();
        profileVersion.setSigningProfile(profile);
        profileVersion.setVersion(version);
        profileVersion.setSigningScheme(SigningScheme.DELEGATED);
        profileVersion.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profileVersion.setRetentionDays(retentionDays);
        profileVersion.setDeleteAfterRetrieval(deleteAfterRetrieval);
        signingProfileVersionRepository.saveAndFlush(profileVersion);
    }
}

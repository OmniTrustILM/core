package com.otilm.core.integration.signing.record;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.signing.record.SigningRecordRetrievalHook;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningRecordRetrievalHookITest extends BaseSpringBootTest {

    @Autowired
    private SigningRecordRetrievalHook hook;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningProfileVersionRepository versionRepo;
    @Autowired
    private SigningRecordRepository recordRepo;
    @Autowired
    private PlatformTransactionManager txm;

    @Test
    void onSignedDocumentServed_stampsRetrievedAtAndDeletesRecord_whenDeleteAfterRetrievalEnabled() throws NotFoundException {
        // given
        SigningProfile profile = insertProfileWithDeleteAfterRetrieval();
        SigningRecord signingRecord = insertRecord(profile);

        // when
        Instant stampedAt = serveSignedDocumentAndReadStampInTransaction(signingRecord.getUuid());

        // then
        assertNotNull(stampedAt);
        assertFalse(recordRepo.existsById(signingRecord.getUuid()));
    }

    @Test
    void onSignedDocumentServed_stampsRetrievedAtAndKeepsRecord_whenDeleteAfterRetrievalDisabled() throws NotFoundException {
        // given
        SigningProfile profile = insertProfileWithoutDeleteAfterRetrieval();
        SigningRecord signingRecord = insertRecord(profile);

        // when
        serveSignedDocumentInTransaction(signingRecord.getUuid());

        // then
        SigningRecord stamped = recordRepo.findById(signingRecord.getUuid()).orElseThrow();
        assertNotNull(stamped.getSignedDocumentRetrievedAt());
    }

    @Test
    void onSignedDocumentServed_throwsNotFoundException_whenRecordDoesNotExist() {
        // given
        var missingRecordUuid = UUID.randomUUID();

        // when
        Executable serve = () -> serveSignedDocumentInTransaction(missingRecordUuid);

        // then
        assertThrows(NotFoundException.class, serve);
    }

    @Test
    void runFallbackSweep_deletesRetrievedRecords_whenDeleteAfterRetrievalEnabled() {
        // given
        SigningProfile profile = insertProfileWithDeleteAfterRetrieval();
        SigningRecord retrieved = insertRetrievedRecord(profile);

        // when
        hook.runFallbackSweep();

        // then
        assertFalse(recordRepo.existsById(retrieved.getUuid()));
    }

    /**
     * Runs the hook inside an ambient transaction (it is {@code @Transactional(MANDATORY)}) and re-throws the
     * checked {@link NotFoundException} transparently, so callers can assert on it without unwrapping the
     * {@link TransactionTemplate} carrier.
     */
    private void serveSignedDocumentInTransaction(UUID recordUuid) throws NotFoundException {
        try {
            new TransactionTemplate(txm).executeWithoutResult(status -> {
                try {
                    hook.onSignedDocumentServed(recordUuid);
                } catch (NotFoundException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException e) {
            if (e.getCause() instanceof NotFoundException notFound) {
                throw notFound;
            }
            throw e;
        }
    }

    /**
     * Serves the document and reads back the retrieved-at stamp within the same ambient transaction. The
     * delete-after-retrieval path removes the row in an {@code afterCommit} hook, so the stamp is only
     * observable before the transaction commits.
     */
    private Instant serveSignedDocumentAndReadStampInTransaction(UUID recordUuid) throws NotFoundException {
        try {
            return new TransactionTemplate(txm).execute(status -> {
                try {
                    hook.onSignedDocumentServed(recordUuid);
                } catch (NotFoundException e) {
                    throw new RuntimeException(e);
                }
                return recordRepo.findById(recordUuid).orElseThrow().getSignedDocumentRetrievedAt();
            });
        } catch (RuntimeException e) {
            if (e.getCause() instanceof NotFoundException notFound) {
                throw notFound;
            }
            throw e;
        }
    }

    private SigningProfile insertProfileWithDeleteAfterRetrieval() {
        return insertProfile(true);
    }

    private SigningProfile insertProfileWithoutDeleteAfterRetrieval() {
        return insertProfile(false);
    }

    private SigningProfile insertProfile(boolean deleteAfterRetrieval) {
        SigningProfile profile = new SigningProfile();
        profile.setName("retrieval-hook-" + System.nanoTime());
        profile.setSigningScheme(SigningScheme.MANAGED);
        profile.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        profile.setLatestVersion(1);
        profile = profileRepo.saveAndFlush(profile);

        // delete-after-retrieval is versioned; the hook reads it from the record's version row (version 1 here)
        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(profile);
        version.setVersion(1);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        version.setDeleteAfterRetrieval(deleteAfterRetrieval);
        versionRepo.saveAndFlush(version);
        return profile;
    }

    private SigningRecord insertRecord(SigningProfile profile) {
        return persistRecord(profile.getUuid(), null);
    }

    private SigningRecord insertRetrievedRecord(SigningProfile profile) {
        var retrievedYesterday = Instant.now().minus(1, ChronoUnit.DAYS);
        return persistRecord(profile.getUuid(), retrievedYesterday);
    }

    private SigningRecord persistRecord(UUID signingProfileUuid, Instant signedDocumentRetrievedAt) {
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setUuid(UUID.randomUUID());
        signingRecord.setSigningProfileUuid(signingProfileUuid);
        signingRecord.setSigningProfileVersion(1);
        signingRecord.setProtocol(SigningProtocol.TSP);
        signingRecord.setSigningTime(Instant.now());
        signingRecord.setSignedDocumentRetrievedAt(signedDocumentRetrievedAt);
        return recordRepo.saveAndFlush(signingRecord);
    }
}

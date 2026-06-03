package com.czertainly.core.signing.record;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.util.BaseSpringBootTest;
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

class SigningRecordRetrievalHookTest extends BaseSpringBootTest {

    @Autowired
    private SigningRecordRetrievalHook hook;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningRecordRepository recordRepo;
    @Autowired
    private PlatformTransactionManager txm;

    @Test
    void onSignedDocumentServed_stampsRetrievedAtAndDeletesRecord_whenDeleteAfterRetrievalEnabled() throws NotFoundException {
        // given
        SigningProfile profile = insertProfileWithDeleteAfterRetrieval();
        SigningRecord record = insertRecord(profile);

        // when
        serveSignedDocumentInTransaction(record.getUuid());

        // then
        assertFalse(recordRepo.existsById(record.getUuid()));
    }

    @Test
    void onSignedDocumentServed_stampsRetrievedAtAndKeepsRecord_whenDeleteAfterRetrievalDisabled() throws NotFoundException {
        // given
        SigningProfile profile = insertProfileWithoutDeleteAfterRetrieval();
        SigningRecord record = insertRecord(profile);

        // when
        serveSignedDocumentInTransaction(record.getUuid());

        // then
        SigningRecord stamped = recordRepo.findById(record.getUuid()).orElseThrow();
        assertNotNull(stamped.getSignedDocumentRetrievedAt());
    }

    @Test
    void onSignedDocumentServed_keepsRecord_whenProfileMissing() throws NotFoundException {
        // given
        SigningRecord orphan = insertRecordWithoutProfile();

        // when
        serveSignedDocumentInTransaction(orphan.getUuid());

        // then
        SigningRecord stamped = recordRepo.findById(orphan.getUuid()).orElseThrow();
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
        profile.setDeleteAfterRetrieval(deleteAfterRetrieval);
        return profileRepo.saveAndFlush(profile);
    }

    private SigningRecord insertRecord(SigningProfile profile) {
        return persistRecord(profile.getUuid(), null);
    }

    private SigningRecord insertRetrievedRecord(SigningProfile profile) {
        var retrievedYesterday = Instant.now().minus(1, ChronoUnit.DAYS);
        return persistRecord(profile.getUuid(), retrievedYesterday);
    }

    private SigningRecord insertRecordWithoutProfile() {
        return persistRecord(null, null);
    }

    private SigningRecord persistRecord(UUID signingProfileUuid, Instant signedDocumentRetrievedAt) {
        SigningRecord record = new SigningRecord();
        record.setUuid(UUID.randomUUID());
        record.setSigningProfileUuid(signingProfileUuid);
        record.setSigningProfileVersion(1);
        record.setSigningTime(Instant.now());
        record.setSignedDocumentRetrievedAt(signedDocumentRetrievedAt);
        return recordRepo.saveAndFlush(record);
    }
}

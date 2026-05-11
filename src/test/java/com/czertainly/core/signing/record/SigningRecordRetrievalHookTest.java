package com.czertainly.core.signing.record;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.signing.record.SigningRecordRetrievalHook;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallbackWithoutResult;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SigningRecordRetrievalHookTest extends BaseSpringBootTest {

    @Autowired private SigningRecordRetrievalHook hook;
    @Autowired private SigningProfileRepository profileRepo;
    @Autowired private SigningRecordRepository recordRepo;
    @Autowired private PlatformTransactionManager txm;

    private SigningRecord seed(boolean deleteAfterRetrieval) {
        SigningProfile p = new SigningProfile();
        p.setName("dr-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p.setDeleteAfterRetrieval(deleteAfterRetrieval);
        p = profileRepo.saveAndFlush(p);
        SigningRecord r = new SigningRecord();
        r.setUuid(UUID.randomUUID());
        r.setSigningProfileUuid(p.getUuid());
        r.setSigningProfileVersion(1);
        r.setSigningTime(OffsetDateTime.now());
        return recordRepo.saveAndFlush(r);
    }

    @Test
    void stampsRetrievedAtAndDeletesPostCommitWhenFlagTrue() {
        SigningRecord r = seed(true);

        new TransactionTemplate(txm).execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                hook.onSignedDocumentServed(r.getUuid());
            }
        });

        assertFalse(recordRepo.existsById(r.getUuid()));
    }

    @Test
    void onlyStampsRetrievedAtWhenFlagFalse() {
        SigningRecord r = seed(false);

        new TransactionTemplate(txm).execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                hook.onSignedDocumentServed(r.getUuid());
            }
        });

        SigningRecord stamped = recordRepo.findById(r.getUuid()).orElseThrow();
        assertNotNull(stamped.getSignedDocumentRetrievedAt());
    }

    @Test
    void fallbackSweepDeletesRetrievedButUndeletedRecords() {
        SigningProfile p = new SigningProfile();
        p.setName("dr-fb-" + System.nanoTime());
        p.setSigningScheme(SigningScheme.MANAGED);
        p.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        p.setLatestVersion(1);
        p.setDeleteAfterRetrieval(true);
        p = profileRepo.saveAndFlush(p);

        SigningRecord r = new SigningRecord();
        r.setUuid(UUID.randomUUID());
        r.setSigningProfileUuid(p.getUuid());
        r.setSigningProfileVersion(1);
        r.setSigningTime(OffsetDateTime.now());
        r.setSignedDocumentRetrievedAt(OffsetDateTime.now().minusDays(1));
        recordRepo.saveAndFlush(r);

        hook.runFallbackSweep();

        assertEquals(0, recordRepo.count());
    }
}

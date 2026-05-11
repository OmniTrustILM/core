package com.czertainly.core.dao.repository.signing;

import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SigningRecordOutboxRepositoryTest extends BaseSpringBootTest {

    @Autowired private SigningRecordOutboxRepository repository;

    @Test
    @Transactional
    void claimsBatchWithSkipLockedAndOrdersByCreatedAt() {
        OffsetDateTime t0 = OffsetDateTime.now();
        for (int i = 0; i < 5; i++) {
            SigningRecordOutbox row = new SigningRecordOutbox();
            row.setUuid(UUID.randomUUID());
            row.setSigningProfileVersion(1);
            row.setSigningTime(t0);
            row.setCreatedAt(t0.plusSeconds(i));
            repository.saveAndFlush(row);
        }

        List<SigningRecordOutbox> claimed = repository.claimBatchSkipLocked(3);

        assertEquals(3, claimed.size());
        for (int i = 1; i < claimed.size(); i++) {
            assert !claimed.get(i).getCreatedAt().isBefore(claimed.get(i - 1).getCreatedAt());
        }
    }

    @Test
    void countAndOldestExposedForGauges() {
        OffsetDateTime t0 = OffsetDateTime.now().minusMinutes(5);
        for (int i = 0; i < 2; i++) {
            SigningRecordOutbox row = new SigningRecordOutbox();
            row.setUuid(UUID.randomUUID());
            row.setSigningProfileVersion(1);
            row.setSigningTime(t0);
            row.setCreatedAt(t0.plusSeconds(i));
            repository.saveAndFlush(row);
        }

        assertEquals(2, repository.count());
        assertEquals(t0.toEpochSecond(), repository.findOldestCreatedAt().orElseThrow().toEpochSecond());
    }
}

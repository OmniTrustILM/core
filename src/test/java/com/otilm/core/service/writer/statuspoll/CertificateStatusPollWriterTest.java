package com.otilm.core.service.writer.statuspoll;

import com.otilm.core.dao.repository.CertificateStatusPollRepository;
import com.otilm.core.service.handler.authority.CertificateOperation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class CertificateStatusPollWriterTest {

    @Mock private CertificateStatusPollRepository pollRepository;

    private CertificateStatusPollWriter writer;

    private static final UUID CERT_UUID = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        writer = new CertificateStatusPollWriter(pollRepository);
    }

    @Test
    void schedule_delegatesToIdempotentInsert() {
        OffsetDateTime due = OffsetDateTime.now();

        writer.schedule(CERT_UUID, CertificateOperation.ISSUE, due);

        verify(pollRepository).scheduleIfAbsent(any(UUID.class), eq(CERT_UUID), eq("ISSUE"), eq(due));
    }

    @Test
    void reschedule_delegatesToRepository() {
        OffsetDateTime next = OffsetDateTime.now();

        writer.reschedule(CERT_UUID, 4, next);

        verify(pollRepository).reschedule(CERT_UUID, 4, next);
    }

    @Test
    void delete_delegatesToRepository() {
        writer.delete(CERT_UUID);

        verify(pollRepository).deleteByCertificateUuid(CERT_UUID);
    }
}

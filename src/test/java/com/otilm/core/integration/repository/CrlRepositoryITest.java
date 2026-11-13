package com.otilm.core.integration.repository;

import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.core.dao.entity.Crl;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.dao.repository.CrlRepository.CrlStateView;
import com.otilm.core.service.writer.CrlEntryData;
import com.otilm.core.service.writer.CrlWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CrlBuilder.aCrl;
import static org.assertj.core.api.Assertions.assertThat;

class CrlRepositoryITest extends BaseSpringBootTest {

    private static final String LISTED_SERIAL_NUMBER = "1a2b";
    private static final String UNLISTED_SERIAL_NUMBER = "3c4d";

    @Autowired
    private CrlRepository crlRepository;

    @Autowired
    private CrlWriter crlWriter;

    private final Date nextUpdate = Date.from(Instant.now().plus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS));
    private final Date nextUpdateDelta = Date
            .from(Instant.now().plus(2, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS));
    private UUID crlUuid;

    @BeforeEach
    void storeACrlThatListsOneSerialNumber() {
        Crl crl = aCrl()
                .withIssuerDn("CN=Crl Repository Test CA")
                .withSerialNumber("5e6f")
                .withCrlIssuerDn("CN=Crl Repository Test CA")
                .withCrlNumber("7")
                .build();
        crl.setUuid(UUID.randomUUID());
        crl.setNextUpdate(nextUpdate);
        CrlEntryData listed = new CrlEntryData(LISTED_SERIAL_NUMBER, new Date(),
                CertificateRevocationReason.KEY_COMPROMISE.name());
        crlUuid = crlWriter.persistCrlAndEntries(crl, true, List.of(listed), new Date()).crlUuid();
        crlWriter.applyDeltaCrl(crlUuid, "7", List.of(), List.of(), "8", nextUpdateDelta, new Date());
    }

    @Test
    void returnsTheListedFlagAndBothDates_whenTheSerialNumberIsListed() {
        // given — a stored CRL with a delta CRL applied, which lists the serial number

        // when
        Optional<CrlStateView> state = crlRepository.findStateByUuidAndSerialNumber(crlUuid, LISTED_SERIAL_NUMBER);

        // then
        assertThat(state).hasValueSatisfying(view -> {
            assertThat(view.lists()).isTrue();
            assertThat(view.getNextUpdate().toInstant()).isEqualTo(nextUpdate.toInstant());
            assertThat(view.getNextUpdateDelta().toInstant()).isEqualTo(nextUpdateDelta.toInstant());
        });
    }

    @Test
    void returnsNoListing_whenTheSerialNumberIsNotListed() {
        // given — a stored CRL that lists another serial number

        // when
        Optional<CrlStateView> state = crlRepository.findStateByUuidAndSerialNumber(crlUuid, UNLISTED_SERIAL_NUMBER);

        // then
        assertThat(state).hasValueSatisfying(view -> {
            assertThat(view.lists()).isFalse();
            assertThat(view.getNextUpdate().toInstant()).isEqualTo(nextUpdate.toInstant());
            assertThat(view.getNextUpdateDelta().toInstant()).isEqualTo(nextUpdateDelta.toInstant());
        });
    }

    @Test
    void returnsNothing_whenNoCrlIsStoredUnderTheUuid() {
        // given — a uuid that no CRL has

        // when
        Optional<CrlStateView> state = crlRepository
                .findStateByUuidAndSerialNumber(UUID.randomUUID(), LISTED_SERIAL_NUMBER);

        // then
        assertThat(state).isEmpty();
    }
}

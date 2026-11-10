package com.otilm.core.integration.service.writer;

import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.core.dao.entity.Crl;
import com.otilm.core.dao.entity.CrlEntry;
import com.otilm.core.dao.entity.CrlEntryId;
import com.otilm.core.dao.repository.CrlEntryRepository;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.service.writer.CrlEntryData;
import com.otilm.core.service.writer.CrlWriter;
import com.otilm.core.service.writer.CrlWriter.CrlWrite;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CrlBuilder.aCrl;
import static org.assertj.core.api.Assertions.assertThat;

class CrlWriterITest extends BaseSpringBootTest {

    private static final String ISSUER_DN = "CN=Crl Writer Test CA";
    private static final String ISSUER_SERIAL = "1a2b";
    private static final Date REVOKED_AT = Date.from(Instant.parse("2026-01-02T03:04:05Z"));
    private static final Date NEXT_UPDATE = Date.from(Instant.now().plus(7, ChronoUnit.DAYS));
    /** More entries than one statement carries, so writing them takes several statements. */
    private static final int ENTRIES_OVER_SEVERAL_STATEMENTS = 2_500;

    @Autowired
    private CrlWriter crlWriter;

    @Autowired
    private CrlRepository crlRepository;

    @Autowired
    private CrlEntryRepository crlEntryRepository;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private Statistics statistics;

    @BeforeEach
    void recordStatementStatistics() {
        statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.setStatisticsEnabled(true);
        statistics.clear();
    }

    @AfterEach
    void stopRecordingStatementStatistics() {
        statistics.setStatisticsEnabled(false);
    }

    @Nested
    class PersistCrlAndEntries {

        @Test
        void storesEveryEntry_whenCrlListsMoreThanOneStatementCarries() {
            // given
            var entries = entries(0, ENTRIES_OVER_SEVERAL_STATEMENTS);

            // when
            crlWriter.persistCrlAndEntries(newCrl("5"), true, entries, REVOKED_AT);

            // then
            assertThat(crlEntryRepository.count()).isEqualTo(ENTRIES_OVER_SEVERAL_STATEMENTS);
        }

        @Test
        void insertsEntriesInFewStatements_whenCrlListsThousands() {
            // given
            var entries = entries(0, ENTRIES_OVER_SEVERAL_STATEMENTS);

            // when
            crlWriter.persistCrlAndEntries(newCrl("5"), true, entries, REVOKED_AT);

            // then
            assertThat(statistics.getPrepareStatementCount()).isLessThan(10);
        }

        @Test
        void keepsOnlyRefreshedEntries_whenRefreshingStoredCrl() {
            // given
            UUID crlUuid = storeCrl("5", entries(0, 3));
            var refreshedEntries = entries(100, 2);

            // when
            crlWriter.persistCrlAndEntries(storedCrlWithNumber(crlUuid, "6"), false, refreshedEntries, REVOKED_AT);

            // then
            assertThat(storedSerials()).containsExactlyInAnyOrderElementsOf(serials(refreshedEntries));
        }

        @Test
        void replacesEntriesWithoutLoadingThem_whenRefreshingStoredCrl() {
            // given
            UUID crlUuid = storeCrl("5", entries(0, ENTRIES_OVER_SEVERAL_STATEMENTS));
            var refreshedEntries = entries(10_000, 10);
            statistics.clear();

            // when
            crlWriter.persistCrlAndEntries(storedCrlWithNumber(crlUuid, "6"), false, refreshedEntries, REVOKED_AT);

            // then
            assertThat(statistics.getEntityStatistics(CrlEntry.class.getName()).getLoadCount()).isZero();
        }

        @Test
        void keepsNewerStoredCrl_whenRefreshCarriesOlderNumber() {
            // given
            var storedEntries = entries(0, 3);
            UUID crlUuid = storeCrl("7", storedEntries);
            Crl olderRefresh = storedCrlWithNumber(crlUuid, "6");

            // when
            CrlWrite write = crlWriter.persistCrlAndEntries(olderRefresh, false, entries(100, 2), REVOKED_AT);

            // then
            assertThat(write.written()).isFalse();
            assertThat(storedCrl().getCrlNumber()).isEqualTo("7");
            assertThat(storedSerials()).containsExactlyInAnyOrderElementsOf(serials(storedEntries));
        }

        @Test
        void keepsStoredEntries_whenAnotherWriterStoredSameNewCrlFirst() {
            // given
            var firstWritersEntries = entries(0, 3);
            UUID firstWritersUuid = storeCrl("3", firstWritersEntries);

            // when
            CrlWrite write = crlWriter.persistCrlAndEntries(newCrl("3"), true, entries(100, 2), REVOKED_AT);

            // then
            assertThat(write).isEqualTo(new CrlWrite(firstWritersUuid, false));
            assertThat(storedSerials()).containsExactlyInAnyOrderElementsOf(serials(firstWritersEntries));
        }

        @Test
        void replacesEntries_whenAnotherWriterStoredOlderNewCrlFirst() {
            // given
            UUID firstWritersUuid = storeCrl("3", entries(0, 3));
            var newerEntries = entries(100, 2);

            // when
            CrlWrite write = crlWriter.persistCrlAndEntries(newCrl("4"), true, newerEntries, REVOKED_AT);

            // then
            assertThat(write).isEqualTo(new CrlWrite(firstWritersUuid, true));
            assertThat(storedCrl().getCrlNumber()).isEqualTo("4");
            assertThat(storedSerials()).containsExactlyInAnyOrderElementsOf(serials(newerEntries));
        }
    }

    @Nested
    class ApplyDeltaCrl {

        @Test
        void appliesEveryChange_whenDeltaCrlListsMoreThanOneStatementCarries() {
            // given
            UUID crlUuid = storeCrl("5", entries(0, ENTRIES_OVER_SEVERAL_STATEMENTS));
            var removals = serials(entries(0, 1_200));
            var upserts = entries(50_000, 1_300);

            // when
            crlWriter.applyDeltaCrl(crlUuid, "5", removals, upserts, "6", NEXT_UPDATE, REVOKED_AT);

            // then
            assertThat(crlEntryRepository.count()).isEqualTo(ENTRIES_OVER_SEVERAL_STATEMENTS - 1_200 + 1_300);
        }

        @Test
        void writesChangesInFewStatements_whenDeltaCrlListsThousands() {
            // given
            UUID crlUuid = storeCrl("5", entries(0, ENTRIES_OVER_SEVERAL_STATEMENTS));
            var removals = serials(entries(0, 1_200));
            var upserts = entries(50_000, 1_300);
            statistics.clear();

            // when
            crlWriter.applyDeltaCrl(crlUuid, "5", removals, upserts, "6", NEXT_UPDATE, REVOKED_AT);

            // then
            assertThat(statistics.getPrepareStatementCount()).isLessThan(10);
        }

        @Test
        void keepsLastListing_whenDeltaCrlListsSerialTwice() {
            // given
            UUID crlUuid = storeCrl("5", List.of());
            var firstListing = new CrlEntryData("abc", REVOKED_AT, CertificateRevocationReason.KEY_COMPROMISE.name());
            var lastListing = new CrlEntryData("abc", REVOKED_AT, CertificateRevocationReason.CA_COMPROMISE.name());

            // when
            crlWriter
                    .applyDeltaCrl(crlUuid, "5", List.of(), List.of(firstListing, lastListing), "6", NEXT_UPDATE,
                            REVOKED_AT);

            // then
            CrlEntry stored = crlEntryRepository.findById(new CrlEntryId(crlUuid, "abc")).orElseThrow();
            assertThat(stored.getRevocationReason()).isEqualTo(CertificateRevocationReason.CA_COMPROMISE);
        }

        @Test
        void skipsDeltaCrl_whenStoredBaseCrlChanged() {
            // given
            var storedEntries = entries(0, 2);
            UUID crlUuid = storeCrl("6", storedEntries);

            // when
            boolean applied = crlWriter
                    .applyDeltaCrl(crlUuid, "5", serials(storedEntries), entries(100, 1), "7", NEXT_UPDATE, REVOKED_AT);

            // then
            assertThat(applied).isFalse();
            assertThat(storedCrl().getCrlNumberDelta()).isNull();
            assertThat(storedSerials()).containsExactlyInAnyOrderElementsOf(serials(storedEntries));
        }

        @Test
        void skipsDeltaCrl_whenNewerDeltaCrlIsStored() {
            // given
            UUID crlUuid = storeCrl("5", List.of());
            crlWriter.applyDeltaCrl(crlUuid, "5", List.of(), entries(0, 1), "8", NEXT_UPDATE, REVOKED_AT);

            // when
            boolean applied = crlWriter
                    .applyDeltaCrl(crlUuid, "5", List.of(), entries(100, 1), "7", NEXT_UPDATE, REVOKED_AT);

            // then
            assertThat(applied).isFalse();
            assertThat(storedCrl().getCrlNumberDelta()).isEqualTo("8");
            assertThat(storedSerials()).containsExactly(Integer.toHexString(0));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UUID storeCrl(String crlNumber, List<CrlEntryData> entries) {
        return crlWriter.persistCrlAndEntries(newCrl(crlNumber), true, entries, REVOKED_AT).crlUuid();
    }

    private Crl storedCrl() {
        return crlRepository.findByIssuerDnAndSerialNumber(ISSUER_DN, ISSUER_SERIAL).orElseThrow();
    }

    private List<String> storedSerials() {
        return crlEntryRepository.findAll().stream().map(entry -> entry.getId().getSerialNumber()).toList();
    }

    private static Crl newCrl(String crlNumber) {
        Crl crl = aCrl()
                .withIssuerDn(ISSUER_DN)
                .withSerialNumber(ISSUER_SERIAL)
                .withCrlIssuerDn(ISSUER_DN)
                .withCrlNumber(crlNumber)
                .build();
        crl.setUuid(UUID.randomUUID());
        crl.setNextUpdate(NEXT_UPDATE);
        return crl;
    }

    private static Crl storedCrlWithNumber(UUID crlUuid, String crlNumber) {
        Crl crl = newCrl(crlNumber);
        crl.setUuid(crlUuid);
        return crl;
    }

    private static List<CrlEntryData> entries(int firstSerial, int count) {
        return IntStream
                .range(firstSerial, firstSerial + count)
                .mapToObj(serial -> new CrlEntryData(Integer.toHexString(serial), REVOKED_AT,
                        CertificateRevocationReason.UNSPECIFIED.name()))
                .toList();
    }

    private static List<String> serials(List<CrlEntryData> entries) {
        return entries.stream().map(CrlEntryData::serialNumber).toList();
    }
}

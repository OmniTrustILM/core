package com.otilm.core.service.writer;

import com.otilm.core.dao.entity.Crl;
import com.otilm.core.dao.entity.CrlEntry;
import com.otilm.core.dao.repository.CrlEntryRepository;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.service.CrlService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import org.hibernate.query.NativeQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writer bean for CRL and CRL-entry inserts.
 *
 * <p>
 * Methods use the default propagation ({@code REQUIRED}) — they join an ambient transaction if one is active, or open a
 * new one if no ambient transaction exists. Each method locks the CRL row before it writes, so writers storing CRLs of
 * one issuer, also from different Core instances, take turns, and each checks under the lock that what it writes is
 * still newer than what the row holds.
 *
 * <p>
 * Entries are written in statements of up to {@link #ENTRIES_PER_STATEMENT} rows, so a CRL listing hundreds of
 * thousands of certificates takes hundreds of statements rather than one per certificate. Each statement declares the
 * entry table, so Hibernate flushes nothing unrelated before it.
 *
 * @see CrlService
 */
@Service
public class CrlWriter {

    /** Rows one statement writes; at four parameters a row this stays far below PostgreSQL's parameter limit. */
    static final int ENTRIES_PER_STATEMENT = 1_000;

    private static final String ENTRY_COLUMNS = "INSERT INTO {h-schema}crl_entry"
            + " (crl_uuid, serial_number, revocation_date, revocation_reason) VALUES ";
    private static final String KEEP_STORED_ENTRY = " ON CONFLICT (crl_uuid, serial_number) DO NOTHING";
    private static final String REPLACE_STORED_ENTRY = " ON CONFLICT (crl_uuid, serial_number) DO UPDATE"
            + " SET revocation_date = EXCLUDED.revocation_date, revocation_reason = EXCLUDED.revocation_reason";
    private static final String DELETE_ENTRIES = "DELETE FROM {h-schema}crl_entry"
            + " WHERE crl_uuid = ?1 AND serial_number IN (";
    private static final String CRL_NUMBERS = "SELECT uuid, crl_number, crl_number_delta FROM {h-schema}crl";

    private final CrlRepository crlRepository;
    private final CrlEntryRepository crlEntryRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    public CrlWriter(CrlRepository crlRepository, CrlEntryRepository crlEntryRepository) {
        this.crlRepository = crlRepository;
        this.crlEntryRepository = crlEntryRepository;
    }

    /**
     * Persists a base CRL plus all of its entries in a single transaction.
     *
     * <p>
     * For a new CRL: inserts the CRL row (ON CONFLICT DO NOTHING) and inserts the entries into it. For an updated CRL:
     * deletes the old entries of the existing row and inserts the new ones. Either way it then writes the base-metadata
     * columns, which clears the delta-metadata columns, since the entries of a delta CRL applied to the old base CRL
     * are gone with it.
     *
     * <p>
     * Nothing is written when the row already holds this CRL or a newer one, which a concurrent writer stored first:
     * one with the same number, a higher one, or a delta CRL numbered above it. A complete CRL numbered like the stored
     * delta CRL is written, since a CRL issuer gives a complete CRL and a delta CRL issued together the same number.
     * The returned UUID is the row's, which for a new CRL differs from {@code crl.getUuid()} when a concurrent writer
     * inserted the row. Callers that need a fresh entity must refetch from the repository.
     */
    @Transactional
    public CrlWrite persistCrlAndEntries(Crl crl, boolean isNewCrl, Iterable<CrlEntryData> entries,
            Date lastRevocationDate) {
        StoredCrlNumbers stored;
        if (isNewCrl) {
            crlRepository.insertWithIssuerConflictResolve(crl);
            stored = lockCrlOfIssuer(crl.getIssuerDn(), crl.getSerialNumber());
        } else {
            stored = lockCrl(crl.getUuid());
        }
        boolean insertedNow = isNewCrl && stored.uuid().equals(crl.getUuid());
        if (!insertedNow) {
            if (!stored.isOlderThanBaseCrl(new BigInteger(crl.getCrlNumber()))) {
                return new CrlWrite(stored.uuid(), false);
            }
            crlEntryRepository.deleteEntriesOfCrl(stored.uuid());
        }
        forEachChunk(entries, chunk -> insertEntries(stored.uuid(), chunk, KEEP_STORED_ENTRY));
        crlRepository.updateBaseMetadata(stored.uuid(), crl.getCrlNumber(), crl.getNextUpdate(), lastRevocationDate);
        return new CrlWrite(stored.uuid(), true);
    }

    /**
     * Applies a delta CRL's changes to an existing base CRL in a single transaction: removes entries listed in
     * {@code removeSerials}, upserts entries listed in {@code upserts}, and writes the delta-metadata columns. A serial
     * number listed twice keeps its last listing.
     *
     * <p>
     * Nothing is written when the row no longer holds the base CRL {@code baseCrlNumber} or already holds this delta
     * CRL or a newer one, which a concurrent writer stored first.
     *
     * @return whether the changes were applied
     */
    @Transactional
    public boolean applyDeltaCrl(UUID crlUuid, String baseCrlNumber, Iterable<String> removeSerials,
            Iterable<CrlEntryData> upserts, String crlNumberDelta, Date nextUpdateDelta, Date lastRevocationDate) {
        StoredCrlNumbers stored = lockCrl(crlUuid);
        if (!stored.acceptsDeltaCrl(new BigInteger(baseCrlNumber), new BigInteger(crlNumberDelta))) {
            return false;
        }
        forEachChunk(removeSerials, chunk -> deleteEntries(crlUuid, chunk));
        forEachChunk(upserts, chunk -> insertEntries(crlUuid, lastListingOfEachSerial(chunk), REPLACE_STORED_ENTRY));
        crlRepository.updateDeltaMetadata(crlUuid, crlNumberDelta, nextUpdateDelta, lastRevocationDate);
        return true;
    }

    private StoredCrlNumbers lockCrl(UUID crlUuid) {
        Object[] row = (Object[]) crlRowQuery(CRL_NUMBERS + " WHERE uuid = :uuid FOR UPDATE")
                .setParameter("uuid", crlUuid)
                .uniqueResult();
        if (row == null) {
            throw new IllegalStateException("CRL row " + crlUuid + " not found");
        }
        return StoredCrlNumbers.of(row);
    }

    private StoredCrlNumbers lockCrlOfIssuer(String issuerDn, String serialNumber) {
        Object[] row = (Object[]) crlRowQuery(
                CRL_NUMBERS + " WHERE issuer_dn = :issuerDn AND serial_number = :serialNumber FOR UPDATE")
                .setParameter("issuerDn", issuerDn)
                .setParameter("serialNumber", serialNumber)
                .uniqueResult();
        if (row == null) {
            throw new IllegalStateException("CRL row not found after insert for issuer " + issuerDn);
        }
        return StoredCrlNumbers.of(row);
    }

    private NativeQuery<?> crlRowQuery(String sql) {
        return entityManager.createNativeQuery(sql).unwrap(NativeQuery.class).addSynchronizedEntityClass(Crl.class);
    }

    private void insertEntries(UUID crlUuid, Collection<CrlEntryData> entries, String onConflict) {
        StringBuilder sql = new StringBuilder(ENTRY_COLUMNS);
        List<Object> parameters = new ArrayList<>(entries.size() * 4);
        for (CrlEntryData entry : entries) {
            if (!parameters.isEmpty()) {
                sql.append(", ");
            }
            int first = parameters.size() + 1;
            sql.append("(?%d, ?%d, ?%d, ?%d)".formatted(first, first + 1, first + 2, first + 3));
            parameters.add(crlUuid);
            parameters.add(entry.serialNumber());
            parameters.add(entry.revocationDate());
            parameters.add(entry.revocationReason());
        }
        executeEntryStatement(sql.append(onConflict).toString(), parameters);
    }

    private void deleteEntries(UUID crlUuid, Collection<String> serialNumbers) {
        StringBuilder sql = new StringBuilder(DELETE_ENTRIES);
        List<Object> parameters = new ArrayList<>(serialNumbers.size() + 1);
        parameters.add(crlUuid);
        for (String serialNumber : serialNumbers) {
            if (parameters.size() > 1) {
                sql.append(", ");
            }
            parameters.add(serialNumber);
            sql.append('?').append(parameters.size());
        }
        executeEntryStatement(sql.append(')').toString(), parameters);
    }

    private void executeEntryStatement(String sql, List<Object> parameters) {
        NativeQuery<?> statement = entityManager
                .createNativeQuery(sql)
                .unwrap(NativeQuery.class)
                .addSynchronizedEntityClass(CrlEntry.class);
        for (int i = 0; i < parameters.size(); i++) {
            statement.setParameter(i + 1, parameters.get(i));
        }
        statement.executeUpdate();
    }

    /** One statement cannot change a row twice, so a serial number listed twice in a chunk keeps its last listing. */
    private static Collection<CrlEntryData> lastListingOfEachSerial(List<CrlEntryData> chunk) {
        Map<String, CrlEntryData> lastListings = new LinkedHashMap<>();
        for (CrlEntryData entry : chunk) {
            lastListings.put(entry.serialNumber(), entry);
        }
        return lastListings.values();
    }

    private static <T> void forEachChunk(Iterable<T> items, Consumer<List<T>> writeChunk) {
        List<T> chunk = new ArrayList<>(ENTRIES_PER_STATEMENT);
        for (T item : items) {
            chunk.add(item);
            if (chunk.size() == ENTRIES_PER_STATEMENT) {
                writeChunk.accept(chunk);
                chunk = new ArrayList<>(ENTRIES_PER_STATEMENT);
            }
        }
        if (!chunk.isEmpty()) {
            writeChunk.accept(chunk);
        }
    }

    /**
     * The row a base CRL was written to, and whether its entries were written: they are not when the row already holds
     * this CRL or a newer one, which a writer for another validation stored first.
     */
    public record CrlWrite(UUID crlUuid, boolean written) {
    }

    private record StoredCrlNumbers(UUID uuid, BigInteger crlNumber, BigInteger crlNumberDelta) {

        static StoredCrlNumbers of(Object[] row) {
            BigInteger crlNumberDelta = row[2] == null ? null : new BigInteger((String) row[2]);
            return new StoredCrlNumbers((UUID) row[0], new BigInteger((String) row[1]), crlNumberDelta);
        }

        boolean isOlderThanBaseCrl(BigInteger baseCrlNumber) {
            return baseCrlNumber.compareTo(crlNumber) > 0
                    && (crlNumberDelta == null || baseCrlNumber.compareTo(crlNumberDelta) >= 0);
        }

        boolean acceptsDeltaCrl(BigInteger baseCrlNumber, BigInteger deltaCrlNumber) {
            return baseCrlNumber.equals(crlNumber)
                    && (crlNumberDelta == null || deltaCrlNumber.compareTo(crlNumberDelta) > 0);
        }
    }
}

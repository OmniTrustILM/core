package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.Crl;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CrlRepository extends SecurityFilterRepository<Crl, Long> {

    /**
     * Until when a stored CRL, and the delta CRL last applied to it, are current, and whether it lists a serial number.
     * A projection, so its values are those of the row even when the persistence context of the request still holds the
     * CRL as it was read before an update.
     */
    interface CrlStateView {
        Date getNextUpdate();

        Date getNextUpdateDelta();

        long getListedEntries();

        default boolean lists() {
            return getListedEntries() > 0;
        }
    }

    Optional<Crl> findByIssuerDnAndSerialNumber(String issuerDn, String serialNumber);

    /**
     * Reads the validity of a CRL and whether it lists the serial number, in one statement: the entries and the dates
     * come from one snapshot, which two statements do not give while another request refreshes the CRL between them.
     *
     * @param serialNumber the serial number as {@code CrlEntry} stores it: lower-case hexadecimal
     */
    @Query("""
            SELECT c.nextUpdate AS nextUpdate, c.nextUpdateDelta AS nextUpdateDelta,
                   (SELECT COUNT(e) FROM CrlEntry e
                     WHERE e.id.crlUuid = c.uuid AND e.id.serialNumber = :serialNumber) AS listedEntries
              FROM Crl c
             WHERE c.uuid = :uuid
            """)
    Optional<CrlStateView> findStateByUuidAndSerialNumber(@Param("uuid") UUID uuid,
            @Param("serialNumber") String serialNumber);

    List<Crl> findByCaCertificateUuid(UUID caCertificateUuid);

    List<Crl> findByCaCertificateUuidIn(List<UUID> caCertificateUuids);

    @Modifying
    @Query("UPDATE Crl c SET c.caCertificateUuid = NULL WHERE c.caCertificateUuid IN ?1")
    void clearCaCertificateReferenceIn(List<UUID> caCertificateUuids);

    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}crl (
            uuid, ca_certificate_uuid, issuer_dn, serial_number,
            crl_issuer_dn, crl_number, next_update, crl_number_delta, next_update_delta, last_revocation_date)
            VALUES (
            :#{#crl.uuid}, :#{#crl.caCertificateUuid}, :#{#crl.issuerDn}, :#{#crl.serialNumber},
            :#{#crl.crlIssuerDn}, :#{#crl.crlNumber}, :#{#crl.nextUpdate}, :#{#crl.crlNumberDelta}, :#{#crl.nextUpdateDelta}, :#{#crl.lastRevocationDate})
            ON CONFLICT (issuer_dn, serial_number)
            DO NOTHING
            """,
            nativeQuery = true)
    void insertWithIssuerConflictResolve(@Param("crl") Crl crl);

    @Modifying
    @Query("""
            UPDATE Crl c
               SET c.crlNumber = :crlNumber,
                   c.nextUpdate = :nextUpdate,
                   c.lastRevocationDate = :lastRevocationDate,
                   c.crlNumberDelta = NULL,
                   c.nextUpdateDelta = NULL
             WHERE c.uuid = :uuid
            """)
    void updateBaseMetadata(@Param("uuid") UUID uuid, @Param("crlNumber") String crlNumber,
            @Param("nextUpdate") Date nextUpdate, @Param("lastRevocationDate") Date lastRevocationDate);

    @Modifying
    @Query("""
            UPDATE Crl c
               SET c.crlNumberDelta = :crlNumberDelta,
                   c.nextUpdateDelta = :nextUpdateDelta,
                   c.lastRevocationDate = :lastRevocationDate
             WHERE c.uuid = :uuid
            """)
    void updateDeltaMetadata(@Param("uuid") UUID uuid, @Param("crlNumberDelta") String crlNumberDelta,
            @Param("nextUpdateDelta") Date nextUpdateDelta, @Param("lastRevocationDate") Date lastRevocationDate);
}

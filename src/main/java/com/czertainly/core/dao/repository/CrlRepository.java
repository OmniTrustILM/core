package com.czertainly.core.dao.repository;

import com.czertainly.core.dao.entity.Crl;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CrlRepository extends SecurityFilterRepository<Crl, Long>
{
    Optional<Crl> findByIssuerDnAndSerialNumber(String issuerDn, String serialNumber);

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
            """, nativeQuery = true)
    void insertWithIssuerConflictResolve(@Param("crl") Crl crl);

    @Modifying
    @Query("""
            UPDATE Crl c
               SET c.crlNumber = :crlNumber,
                   c.nextUpdate = :nextUpdate,
                   c.lastRevocationDate = :lastRevocationDate
             WHERE c.uuid = :uuid
            """)
    void updateBaseMetadata(@Param("uuid") UUID uuid,
                            @Param("crlNumber") String crlNumber,
                            @Param("nextUpdate") Date nextUpdate,
                            @Param("lastRevocationDate") Date lastRevocationDate);

    @Modifying
    @Query("""
            UPDATE Crl c
               SET c.crlNumberDelta = :crlNumberDelta,
                   c.nextUpdateDelta = :nextUpdateDelta,
                   c.lastRevocationDate = :lastRevocationDate
             WHERE c.uuid = :uuid
            """)
    void updateDeltaMetadata(@Param("uuid") UUID uuid,
                             @Param("crlNumberDelta") String crlNumberDelta,
                             @Param("nextUpdateDelta") Date nextUpdateDelta,
                             @Param("lastRevocationDate") Date lastRevocationDate);
}

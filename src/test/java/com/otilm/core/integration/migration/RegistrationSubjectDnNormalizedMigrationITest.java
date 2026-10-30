package com.otilm.core.integration.migration;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CustomOidEntryRepository;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.util.CertificateUtil;
import db.migration.V202608071000__RegistrationSubjectDnNormalizedMigration;
import java.sql.Connection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegistrationSubjectDnNormalizedMigrationITest extends BaseMigrationTest {

    @Autowired
    DataSource dataSource;
    @Autowired
    CertificateRepository certificateRepository;
    @Autowired
    CustomOidEntryRepository customOidEntryRepository;

    // OidHandler is process-wide static state; seedRdnOidRegistry writes into it, so each test
    // snapshots the RDN category and restores it afterward rather than leaking a custom code into
    // unrelated tests sharing the same surefire JVM.
    private Map<String, OidRecord> rdnRegistrySnapshot;

    @BeforeEach
    void snapshotRdnRegistry() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        rdnRegistrySnapshot = existing == null ? null : new HashMap<>(existing);
    }

    @AfterEach
    void restoreRdnRegistry() {
        customOidEntryRepository.deleteAll();
        if (rdnRegistrySnapshot == null) {
            OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        } else {
            OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdnRegistrySnapshot);
        }
    }

    @Test
    void migrate_backfillsRegistrationRowsAndLeavesOutOfScopeRowsAlone() throws Exception {
        Certificate registeredWithDn = persist(CertificateState.REGISTERED, "CN=device-1", null);
        Certificate pendingWithDn = persist(CertificateState.PENDING_REGISTRATION, "CN=device-2", null);
        Certificate pendingApprovalWithDn = persist(CertificateState.PENDING_APPROVAL, "CN=device-approval", null);
        Certificate registeredNullDn = persist(CertificateState.REGISTERED, null, null);
        Certificate registeredBlankDn = persist(CertificateState.REGISTERED, "   ", null);
        Certificate registeredUnparseable = persist(CertificateState.REGISTERED, "not-a-dn", null);
        Certificate issuedUntouched = persist(CertificateState.ISSUED, "CN=device-3", null);
        String existingNormalized = CertificateUtil.normalizeStoredSubjectDn("CN=already-normalized");
        Certificate registeredAlreadyNormalized = persist(CertificateState.REGISTERED, "CN=already-normalized",
                existingNormalized);

        runMigration();

        assertThat(reload(registeredWithDn).getSubjectDnNormalized())
                .as("a REGISTERED row with a parseable DN is backfilled exactly as the identity match normalizes it")
                .isEqualTo(CertificateUtil.normalizeStoredSubjectDn("CN=device-1"));
        assertThat(reload(pendingWithDn).getSubjectDnNormalized())
                .as("PENDING_REGISTRATION rows are in scope because they transition to REGISTERED unchanged")
                .isEqualTo(CertificateUtil.normalizeStoredSubjectDn("CN=device-2"));
        assertThat(reload(pendingApprovalWithDn).getSubjectDnNormalized())
                .as("PENDING_APPROVAL rows are in scope because a rejected approval restores them to REGISTERED")
                .isEqualTo(CertificateUtil.normalizeStoredSubjectDn("CN=device-approval"));
        assertThat(reload(registeredNullDn).getSubjectDnNormalized())
                .as("a null subject DN normalizes to the empty name")
                .isEmpty();
        assertThat(reload(registeredBlankDn).getSubjectDnNormalized())
                .as("a blank subject DN normalizes to the empty name")
                .isEmpty();
        assertThat(reload(registeredUnparseable).getSubjectDnNormalized())
                .as("an unparseable stored DN stays NULL, matching the identity match's own skip")
                .isNull();
        assertThat(reload(issuedUntouched).getSubjectDnNormalized())
                .as("a certificate outside the backfilled registration states is out of scope")
                .isNull();
        assertThat(reload(registeredAlreadyNormalized).getSubjectDnNormalized())
                .as("an already-populated normalized subject is never overwritten")
                .isEqualTo(existingNormalized);
    }

    @Test
    void migrate_seedsCustomRdnCodesFromTheDatabaseBeforeBackfilling() throws Exception {
        String customOid = "1.2.3.4.5.9101";
        String customCode = "WIDGETID";
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        assertThat(OidHandler.getOidForRdnCode(customCode))
                .as("the custom code must be unresolvable before the migration seeds it from custom_oid_entry")
                .isNull();

        RdnAttributeTypeCustomOidEntry entry = new RdnAttributeTypeCustomOidEntry();
        entry.setOid(customOid);
        entry.setDisplayName("Widget Id");
        entry.setCode(customCode);
        entry.setAltCodes(List.of());
        customOidEntryRepository.save(entry);

        Certificate withCustomRdn = persist(CertificateState.REGISTERED, customCode + "=widget-42, CN=device-9", null);

        runMigration();

        assertThat(reload(withCustomRdn).getSubjectDnNormalized())
                .as("the custom RDN code resolves to its registered OID once the migration seeds it from the database")
                .contains(customOid + "=widget-42");
    }

    @Test
    void migrate_seedsSystemRdnCodesWithoutAnyCustomEntries() throws Exception {
        // A deployment with no custom RDN OIDs: the seed must still publish the SystemOid built-ins,
        // because codes such as EMAIL are absent from BouncyCastle's keyword table and stored DNs
        // rendered with them would otherwise be skipped as unparseable.
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        assertThat(OidHandler.getOidForRdnCode("EMAIL"))
                .as("the system code must be unresolvable before the migration seeds the built-ins")
                .isNull();

        Certificate withSystemRdn = persist(CertificateState.REGISTERED, "EMAIL=user@example.com, CN=device-10", null);

        runMigration();

        assertThat(reload(withSystemRdn).getSubjectDnNormalized())
                .as("a system RDN code unknown to BouncyCastle resolves through the seeded built-ins")
                .contains("1.2.840.113549.1.9.1=user@example.com");
    }

    @Test
    void migrate_customEntryOnSystemOidWinsOverTheBuiltIn() throws Exception {
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());

        RdnAttributeTypeCustomOidEntry entry = new RdnAttributeTypeCustomOidEntry();
        entry.setOid("1.2.840.113549.1.9.1");
        entry.setDisplayName("Contact Mail");
        entry.setCode("CONTACTMAIL");
        entry.setAltCodes(List.of());
        customOidEntryRepository.save(entry);

        Certificate withShadowingCode = persist(CertificateState.REGISTERED, "CONTACTMAIL=user@example.com", null);

        runMigration();

        assertThat(reload(withShadowingCode).getSubjectDnNormalized())
                .as("a custom row occupying a system OID keeps its own code, mirroring the runtime registry merge")
                .contains("1.2.840.113549.1.9.1=user@example.com");
    }

    // --- helpers ---

    private void runMigration() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            Context context = mock(Context.class);
            when(context.getConnection()).thenReturn(conn);
            new V202608071000__RegistrationSubjectDnNormalizedMigration().migrate(context);
        }
    }

    private Certificate persist(CertificateState state, String subjectDn, String subjectDnNormalized) {
        Certificate certificate = new Certificate();
        certificate.setState(state);
        certificate.setSubjectDn(subjectDn);
        certificate.setSubjectDnNormalized(subjectDnNormalized);
        return certificateRepository.save(certificate);
    }

    private Certificate reload(Certificate certificate) {
        return certificateRepository.findByUuid(certificate.getUuid()).orElseThrow();
    }
}

package com.otilm.core.integration.migration;

import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.core.dao.repository.CertificateRepository;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs the trusted certificate migration over certificates stored before it: every certificate trusted as a CA becomes
 * a trust row with the validation purpose, and nothing else changes.
 */
class TrustedCertificateMigrationITest extends BaseMigrationTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611240015__trusted_certificate.sql";

    @Autowired
    private DataSource dataSource;
    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void createsOneValidationTrustRowPerTrustedCa_whenMigrating() throws Exception {
        // given
        UUID trustedRootUuid = certificateRepository
                .save(aCertificate().withSubjectType(CertificateSubjectType.ROOT_CA).withTrustedCa(true).build())
                .getUuid();
        certificateRepository
                .save(aCertificate()
                        .withSubjectType(CertificateSubjectType.INTERMEDIATE_CA)
                        .withTrustedCa(false)
                        .build());
        certificateRepository.save(aCertificate().withSubjectType(CertificateSubjectType.END_ENTITY).build());
        var jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("DROP TABLE IF EXISTS trusted_certificate_sync");
        jdbc.execute("DROP TABLE IF EXISTS trusted_certificate");

        // when
        runMigration();

        // then
        assertThat(jdbc.queryForObject("SELECT count(*) FROM trusted_certificate", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT certificate_uuid FROM trusted_certificate", UUID.class))
                .isEqualTo(trustedRootUuid);
        assertThat(jdbc
                .queryForObject("SELECT validation AND NOT platform AND NOT platform_removal_pending "
                        + "FROM trusted_certificate", Boolean.class))
                .isTrue();
        assertThat(jdbc
                .queryForObject("SELECT trusted_ca FROM certificate WHERE uuid = ?", Boolean.class, trustedRootUuid))
                .isTrue();
        assertThat(jdbc.queryForObject("SELECT initial_import_done FROM trusted_certificate_sync", Boolean.class))
                .isFalse();
    }

    private void runMigration() throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }
}

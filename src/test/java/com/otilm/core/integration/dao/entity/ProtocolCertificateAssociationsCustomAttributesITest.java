package com.otilm.core.integration.dao.entity;

import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import com.otilm.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SqlCapture;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static org.assertj.core.api.Assertions.assertThat;

class ProtocolCertificateAssociationsCustomAttributesITest extends BaseSpringBootTest {

    private static final UUID DOMAIN_ATTRIBUTE_UUID = UUID.fromString("6b0f0c8e-5f4e-4c7a-9d2b-1a3e5c7f9b21");

    @Autowired
    private ProtocolCertificateAssociationsRepository associationsRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void storesTheNewCustomAttributes_whenALoadedAssociationIsGivenAsManyAsBefore() {
        // given
        UUID associationsUuid = persistAssociationsWithDomain("old.example");
        var changedDomain = "changed.example";

        // when
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(status -> entityManager
                        .find(ProtocolCertificateAssociations.class, associationsUuid)
                        .setCustomAttributes(List.of(buildDomainAttribute(changedDomain))));

        // then
        assertThat(readStoredDomain(associationsUuid)).isEqualTo(changedDomain);
    }

    @Test
    void sendsNoUpdate_whenAnAssociationWithCustomAttributesIsLoaded() throws Exception {
        // given
        UUID associationsUuid = persistAssociationsWithDomain("old.example");

        // when
        List<String> statements = SqlCapture
                .during(() -> new TransactionTemplate(transactionManager)
                        .execute(status -> entityManager.find(ProtocolCertificateAssociations.class, associationsUuid)))
                .statements();

        // then
        assertThat(statements).noneMatch(sql -> sql.startsWith("update core.protocol_certificate_associations"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UUID persistAssociationsWithDomain(String domain) {
        ProtocolCertificateAssociations associations = new ProtocolCertificateAssociations();
        associations.setCustomAttributes(List.of(buildDomainAttribute(domain)));
        return associationsRepository.save(associations).getUuid();
    }

    private static RequestAttributeV3 buildDomainAttribute(String domain) {
        return aCustomAttribute().withUuid(DOMAIN_ATTRIBUTE_UUID).withName("domain").withStringContent(domain).build();
    }

    private String readStoredDomain(UUID associationsUuid) {
        return jdbcTemplate
                .queryForObject("SELECT custom_attributes->0->'content'->0->>'data' FROM " + dbSchema
                        + ".protocol_certificate_associations WHERE uuid = ?", String.class, associationsUuid);
    }
}

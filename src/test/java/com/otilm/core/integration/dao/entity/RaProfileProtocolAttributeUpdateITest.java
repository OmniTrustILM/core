package com.otilm.core.integration.dao.entity;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileProtocolAttribute;
import com.otilm.core.dao.repository.RaProfileProtocolAttributeRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.EstRouteSeeder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class RaProfileProtocolAttributeUpdateITest extends BaseSpringBootTest {

    private static final String EST_ATTRIBUTES = "[{\"name\":\"est\"}]";
    private static final String ACME_ATTRIBUTES = "[{\"name\":\"acme\"}]";

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private RaProfileProtocolAttributeRepository protocolAttributes;

    @Test
    void keepsTheEstAttributes_whenAnotherProtocolWritesTheRowFromAStaleCopy() {
        // given
        RaProfile raProfile = routes.seedRaProfile("devices-ra");
        RaProfileProtocolAttribute seeded = new RaProfileProtocolAttribute();
        seeded.setRaProfile(raProfile);
        UUID rowUuid = protocolAttributes.save(seeded).getUuid();
        EntityManager staleReader = entityManagerFactory.createEntityManager();
        EntityManager estWriter = entityManagerFactory.createEntityManager();
        try {
            staleReader.getTransaction().begin();
            RaProfileProtocolAttribute staleCopy = staleReader.find(RaProfileProtocolAttribute.class, rowUuid);
            estWriter.getTransaction().begin();
            estWriter.find(RaProfileProtocolAttribute.class, rowUuid).setEstIssueCertificateAttributes(EST_ATTRIBUTES);
            estWriter.getTransaction().commit();

            // when
            staleCopy.setAcmeIssueCertificateAttributes(ACME_ATTRIBUTES);
            staleReader.getTransaction().commit();

            // then
            RaProfileProtocolAttribute stored = protocolAttributes.findAll().getFirst();
            assertThat(stored.getAcmeIssueCertificateAttributes()).isEqualTo(ACME_ATTRIBUTES);
            assertThat(stored.getEstIssueCertificateAttributes()).isEqualTo(EST_ATTRIBUTES);
        } finally {
            staleReader.close();
            estWriter.close();
        }
    }
}

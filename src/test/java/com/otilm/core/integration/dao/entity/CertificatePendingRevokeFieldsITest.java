package com.otilm.core.integration.dao.entity;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.CertificatePendingRevokeWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * JPA round-trip coverage for the two new nullable columns added to {@code certificate}:
 * {@code pending_revoke_destroy_key} (BOOLEAN) and {@code pending_revoke_attributes} (JSONB carrying a list of
 * {@link RequestAttribute}).
 *
 * <p>
 * Both columns are populated only when a revocation request whose connector responded asynchronously moves the
 * certificate to {@code PENDING_REVOKE}; outside that state they are always {@code null}.
 * </p>
 */
class CertificatePendingRevokeFieldsITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificatePendingRevokeWriter pendingRevokeWriter;

    @Test
    void newCertificate_hasNullPendingRevokeFields_byDefault() {
        X509CertificateEntity cert = new X509CertificateEntity();
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertNull(fetched.getPendingRevokeDestroyKey(), "pendingRevokeDestroyKey should default to null");
        assertNull(fetched.getPendingRevokeAttributes(), "pendingRevokeAttributes should default to null");
    }

    @Test
    void destroyKeyFlag_roundTrips() {
        X509CertificateEntity cert = new X509CertificateEntity();
        cert.setPendingRevokeDestroyKey(Boolean.TRUE);
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(Boolean.TRUE, fetched.getPendingRevokeDestroyKey());
    }

    @Test
    void destroyKeyFlag_canBeFalse() {
        X509CertificateEntity cert = new X509CertificateEntity();
        cert.setPendingRevokeDestroyKey(Boolean.FALSE);
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(Boolean.FALSE, fetched.getPendingRevokeDestroyKey());
    }

    @Test
    void revokeAttributes_v2_roundTrip_preservesConcreteSubtype() {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(UUID.randomUUID());
        attr.setName("revokeReason");
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV2("Compromised")));

        X509CertificateEntity cert = new X509CertificateEntity();
        cert.setPendingRevokeAttributes(List.of(attr));
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        List<RequestAttribute> stored = fetched.getPendingRevokeAttributes();
        assertNotNull(stored);
        assertEquals(1, stored.size());
        // RequestAttribute's @JsonTypeInfo discriminates by `version`; V2 must come back as V2.
        RequestAttribute firstStored = stored.getFirst();
        assertInstanceOf(RequestAttributeV2.class, firstStored, "v2 input must round-trip as RequestAttributeV2");
        RequestAttributeV2 v2 = (RequestAttributeV2) firstStored;
        assertEquals("revokeReason", v2.getName());
        assertEquals(attr.getUuid(), v2.getUuid());
    }

    @Test
    void revokeAttributes_v3_roundTrip_preservesConcreteSubtype() {
        // The platform supports both v2 and v3 attributes; storage must be version-agnostic.
        RequestAttributeV3 attr = new RequestAttributeV3();
        attr.setUuid(UUID.randomUUID());
        attr.setName("revokeReason");
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV3("KeyCompromise")));

        X509CertificateEntity cert = new X509CertificateEntity();
        cert.setPendingRevokeAttributes(List.of(attr));
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        List<RequestAttribute> stored = fetched.getPendingRevokeAttributes();
        assertNotNull(stored);
        assertEquals(1, stored.size());
        RequestAttribute firstStored = stored.getFirst();
        assertInstanceOf(RequestAttributeV3.class, firstStored,
                "v3 input must round-trip as RequestAttributeV3 — discriminated by JSON `version` field");
        RequestAttributeV3 v3 = (RequestAttributeV3) firstStored;
        assertEquals("revokeReason", v3.getName());
        assertEquals(attr.getUuid(), v3.getUuid());
    }

    @Test
    void revokeAttributes_mixedV2AndV3_roundTrip() {
        // A list mixing both versions must preserve each entry's concrete subtype.
        RequestAttributeV2 v2 = new RequestAttributeV2();
        v2.setUuid(UUID.randomUUID());
        v2.setName("v2-attr");
        v2.setContentType(AttributeContentType.STRING);
        v2.setContent(List.of(new StringAttributeContentV2("old")));

        RequestAttributeV3 v3 = new RequestAttributeV3();
        v3.setUuid(UUID.randomUUID());
        v3.setName("v3-attr");
        v3.setContentType(AttributeContentType.STRING);
        v3.setContent(List.of(new StringAttributeContentV3("new")));

        X509CertificateEntity cert = new X509CertificateEntity();
        cert.setPendingRevokeAttributes(List.of(v2, v3));
        certificateRepository.save(cert);

        List<RequestAttribute> stored = certificateRepository
                .findByUuid(cert.getUuid())
                .orElseThrow()
                .getPendingRevokeAttributes();
        assertNotNull(stored);
        assertEquals(2, stored.size());
        assertInstanceOf(RequestAttributeV2.class, stored.get(0));
        assertInstanceOf(RequestAttributeV3.class, stored.get(1));
    }

    @Test
    void persistsAttributes_whenWriterSavesThem() {
        // given
        X509CertificateEntity cert = certificateRepository.save(new X509CertificateEntity());
        RequestAttributeV2 attribute = aStringAttribute("dummy");

        // when
        pendingRevokeWriter.save(cert.getUuid(), List.of(attribute));

        // then
        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(fetched.getPendingRevokeAttributes()).hasSize(1);
        assertThat(fetched.getPendingRevokeAttributes().getFirst().getName()).isEqualTo("dummy");
    }

    @Test
    void persistsNullAttributes_whenWriterClearsThem() {
        // given
        X509CertificateEntity cert = new X509CertificateEntity();
        cert.setPendingRevokeAttributes(List.of(aStringAttribute("dummy")));
        certificateRepository.save(cert);

        // when
        pendingRevokeWriter.clear(cert.getUuid());

        // then
        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(fetched.getPendingRevokeAttributes()).isNull();
    }

    @Test
    void persistsNullDestroyKey_whenEntityClearsIt() {
        // given
        X509CertificateEntity cert = new X509CertificateEntity();
        cert.setPendingRevokeDestroyKey(Boolean.TRUE);
        certificateRepository.save(cert);

        // when
        cert.setPendingRevokeDestroyKey(null);
        certificateRepository.save(cert);

        // then
        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertThat(fetched.getPendingRevokeDestroyKey()).isNull();
    }

    @Test
    void newCertificate_archivedFlagUnaffected() {
        // Sanity: ensure adding the new columns hasn't broken the existing archived default.
        X509CertificateEntity cert = new X509CertificateEntity();
        certificateRepository.save(cert);
        assertFalse(certificateRepository.findByUuid(cert.getUuid()).orElseThrow().isArchived());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static RequestAttributeV2 aStringAttribute(String name) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2("x")));
        return attribute;
    }
}

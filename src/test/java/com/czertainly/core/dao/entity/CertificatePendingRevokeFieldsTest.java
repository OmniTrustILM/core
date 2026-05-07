package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * JPA round-trip coverage for the two new nullable columns added to {@code certificate}:
 * {@code pending_revoke_destroy_key} (BOOLEAN) and {@code pending_revoke_attributes} (JSONB
 * carrying a list of {@link RequestAttribute}).
 *
 * <p>Both columns are populated only when a revocation request whose connector responded
 * asynchronously moves the certificate to {@code PENDING_REVOKE}; outside that state they
 * are always {@code null}.</p>
 */
class CertificatePendingRevokeFieldsTest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void newCertificate_hasNullPendingRevokeFields_byDefault() {
        Certificate cert = new Certificate();
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertNull(fetched.getPendingRevokeDestroyKey(),
                "pendingRevokeDestroyKey should default to null");
        assertNull(fetched.getPendingRevokeAttributes(),
                "pendingRevokeAttributes should default to null");
    }

    @Test
    void destroyKeyFlag_roundTrips() {
        Certificate cert = new Certificate();
        cert.setPendingRevokeDestroyKey(Boolean.TRUE);
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(Boolean.TRUE, fetched.getPendingRevokeDestroyKey());
    }

    @Test
    void destroyKeyFlag_canBeFalse() {
        Certificate cert = new Certificate();
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

        Certificate cert = new Certificate();
        cert.setPendingRevokeAttributes(List.of(attr));
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        List<RequestAttribute> stored = fetched.getPendingRevokeAttributes();
        assertNotNull(stored);
        assertEquals(1, stored.size());
        // RequestAttribute's @JsonTypeInfo discriminates by `version`; V2 must come back as V2.
        RequestAttribute firstStored = stored.getFirst();
        assertInstanceOf(RequestAttributeV2.class, firstStored,
                "v2 input must round-trip as RequestAttributeV2");
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

        Certificate cert = new Certificate();
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

        Certificate cert = new Certificate();
        cert.setPendingRevokeAttributes(List.of(v2, v3));
        certificateRepository.save(cert);

        List<RequestAttribute> stored = certificateRepository.findByUuid(cert.getUuid())
                .orElseThrow().getPendingRevokeAttributes();
        assertNotNull(stored);
        assertEquals(2, stored.size());
        assertInstanceOf(RequestAttributeV2.class, stored.get(0));
        assertInstanceOf(RequestAttributeV3.class, stored.get(1));
    }

    @Test
    void clearingPendingRevokeFields_persistsAsNull() {
        // Set values, save, then clear, save, fetch — fields should be null again.
        Certificate cert = new Certificate();
        cert.setPendingRevokeDestroyKey(Boolean.TRUE);
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setName("dummy");
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV2("x")));
        cert.setPendingRevokeAttributes(List.of(attr));
        certificateRepository.save(cert);

        cert.setPendingRevokeDestroyKey(null);
        cert.setPendingRevokeAttributes(null);
        certificateRepository.save(cert);

        Certificate fetched = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertNull(fetched.getPendingRevokeDestroyKey());
        assertNull(fetched.getPendingRevokeAttributes());
    }

    @Test
    void newCertificate_archivedFlagUnaffected() {
        // Sanity: ensure adding the new columns hasn't broken the existing archived default.
        Certificate cert = new Certificate();
        certificateRepository.save(cert);
        assertFalse(certificateRepository.findByUuid(cert.getUuid()).orElseThrow().isArchived());
    }
}

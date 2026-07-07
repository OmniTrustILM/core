package com.otilm.core.integration.service.writer.registration;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistration;
import com.otilm.core.dao.repository.CertificateRegistrationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.writer.registration.CertificateRegistrationWriter;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Integration coverage for the register->issue binding persistence against a real PostgreSQL.
 */
class CertificateRegistrationWriterITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRegistrationWriter writer;
    @Autowired
    private CertificateRegistrationRepository registrationRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;

    private UUID certificateUuid;

    @BeforeEach
    void createCertificate() {
        Certificate certificate = new Certificate();
        certificate.setState(CertificateState.REGISTERED);
        certificateUuid = certificateRepository.save(certificate).getUuid();
    }

    private static MetadataAttribute handle(String name, String value) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(value)));
        return attribute;
    }

    @Test
    void upsertCreatesBindingWithSerializedMeta() {
        // when
        writer.upsert(certificateUuid, List.of(handle("endEntityName", "device-7")));

        // then
        CertificateRegistration binding = registrationRepository.findByCertificateUuid(certificateUuid).orElseThrow();
        List<MetadataAttribute> roundTripped = AttributeDefinitionUtils.deserialize(binding.getMeta(), MetadataAttribute.class);
        assertThat(roundTripped).hasSize(1);
        assertThat(roundTripped.get(0).getName()).isEqualTo("endEntityName");
    }

    @Test
    void upsertWithEmptyMetaCreatesBindingWithoutMeta() {
        // when — the binding row itself marks the certificate register-bound even without a CA handle
        writer.upsert(certificateUuid, List.of());

        // then
        CertificateRegistration binding = registrationRepository.findByCertificateUuid(certificateUuid).orElseThrow();
        assertThat(binding.getMeta()).isNull();
    }

    @Test
    void upsertWithNullMetaCreatesBindingWithoutMeta() {
        // when
        writer.upsert(certificateUuid, null);

        // then
        assertThat(registrationRepository.findByCertificateUuid(certificateUuid)).isPresent();
    }

    @Test
    void secondUpsertReplacesMetaWithoutDuplicatingTheRow() {
        // given
        writer.upsert(certificateUuid, List.of(handle("trackingId", "t-1")));

        // when — async completion replaces the tracking handle with the final CA handle
        writer.upsert(certificateUuid, List.of(handle("endEntityName", "device-7")));

        // then
        assertThat(registrationRepository.count()).isEqualTo(1);
        CertificateRegistration binding = registrationRepository.findByCertificateUuid(certificateUuid).orElseThrow();
        assertThat(binding.getMeta()).contains("endEntityName").doesNotContain("trackingId");
    }

    @Test
    void clearRemovesBinding() {
        // given
        writer.upsert(certificateUuid, List.of(handle("endEntityName", "device-7")));

        // when
        writer.clear(certificateUuid);

        // then
        assertThat(registrationRepository.findByCertificateUuid(certificateUuid)).isEmpty();
    }

    @Test
    void clearIsIdempotentWhenNoBindingExists() {
        assertThatCode(() -> writer.clear(certificateUuid)).doesNotThrowAnyException();
    }

    @Test
    void lockedFinderReturnsBindingInsideTransaction() {
        // given
        writer.upsert(certificateUuid, List.of(handle("endEntityName", "device-7")));

        // when — SELECT ... FOR UPDATE requires an active transaction
        CertificateRegistration locked = new TransactionTemplate(transactionManager).execute(
                status -> registrationRepository.findAndLockByCertificateUuid(certificateUuid).orElseThrow());

        // then
        assertThat(locked).isNotNull();
        assertThat(locked.getCertificateUuid()).isEqualTo(certificateUuid);
    }

}

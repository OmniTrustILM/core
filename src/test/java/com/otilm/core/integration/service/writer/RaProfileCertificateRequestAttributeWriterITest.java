package com.otilm.core.integration.service.writer;

import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileCertificateRequestAttribute;
import com.otilm.core.dao.entity.RaProfileValueSourceBinding;
import com.otilm.core.dao.repository.RaProfileCertificateRequestAttributeRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.RaProfileValueSourceBindingRepository;
import com.otilm.core.service.writer.RaProfileCertificateRequestAttributeWriter;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RaProfileCertificateRequestAttributeWriterITest extends BaseSpringBootTest {

    @Autowired
    private RaProfileCertificateRequestAttributeWriter writer;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private RaProfileCertificateRequestAttributeRepository requestAttributeRepository;
    @Autowired
    private RaProfileValueSourceBindingRepository valueSourceBindingRepository;

    private RaProfile newRaProfile() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("rp-" + UUID.randomUUID());
        return raProfileRepository.save(raProfile);
    }

    @Test
    void saveStaticSetUpsertsSingleRow() {
        // given
        RaProfile raProfile = newRaProfile();

        // when: a second save updates the same row rather than inserting a duplicate
        writer.saveStaticSet(raProfile, "[1]", AttributeSetMergeMode.MERGE, null);
        writer.saveStaticSet(raProfile, "[2]", AttributeSetMergeMode.STATIC_ONLY, Boolean.TRUE);

        // then
        RaProfileCertificateRequestAttribute stored = requestAttributeRepository.findByRaProfileUuid(raProfile.getUuid()).orElseThrow();
        assertThat(stored.getRequestAttributes()).isEqualTo("[2]");
        assertThat(stored.getMergeMode()).isEqualTo(AttributeSetMergeMode.STATIC_ONLY);
        assertThat(stored.getExternalCsrValidationStrict()).isTrue();
    }

    @Test
    void clearStaticSetNullsThePayloadButKeepsTheRow() {
        // given
        RaProfile raProfile = newRaProfile();
        writer.saveStaticSet(raProfile, "[1]", AttributeSetMergeMode.MERGE, null);

        // when
        writer.clearStaticSet(raProfile.getUuid());

        // then
        RaProfileCertificateRequestAttribute stored = requestAttributeRepository.findByRaProfileUuid(raProfile.getUuid()).orElseThrow();
        assertThat(stored.getRequestAttributes()).isNull();
    }

    @Test
    void replaceValueSourceBindingsClearsThenInserts() {
        // given: one binding stored
        RaProfile raProfile = newRaProfile();
        writer.replaceValueSourceBindings(raProfile.getUuid(), List.of(binding(raProfile.getUuid(), "a", "STATIC_LIST")));
        assertThat(valueSourceBindingRepository.findByRaProfileUuid(raProfile.getUuid())).hasSize(1);

        // when: replaced with a different single binding
        writer.replaceValueSourceBindings(raProfile.getUuid(), List.of(binding(raProfile.getUuid(), "b", "CONNECTOR_CALLBACK")));

        // then: the old binding is gone, only the new one remains
        List<RaProfileValueSourceBinding> after = valueSourceBindingRepository.findByRaProfileUuid(raProfile.getUuid());
        assertThat(after).hasSize(1);
        assertThat(after.get(0).getAttributeName()).isEqualTo("b");
    }

    @Test
    void replaceValueSourceBindingsWithEmptyListClearsAll() {
        // given
        RaProfile raProfile = newRaProfile();
        writer.replaceValueSourceBindings(raProfile.getUuid(), List.of(binding(raProfile.getUuid(), "a", "STATIC_LIST")));

        // when
        writer.replaceValueSourceBindings(raProfile.getUuid(), List.of());

        // then
        assertThat(valueSourceBindingRepository.findByRaProfileUuid(raProfile.getUuid())).isEmpty();
    }

    private RaProfileValueSourceBinding binding(UUID raProfileUuid, String name, String type) {
        RaProfileValueSourceBinding binding = new RaProfileValueSourceBinding();
        binding.setRaProfileUuid(raProfileUuid);
        binding.setAttributeName(name);
        binding.setValueSourceType(type);
        return binding;
    }
}

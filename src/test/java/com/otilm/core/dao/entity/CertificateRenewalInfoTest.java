package com.otilm.core.dao.entity;

import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateRenewalInfoTest {

    @Test
    void equalsItself_whenComparedToTheSameInstance() {
        // given
        CertificateRenewalInfo info = anInfoWithUuid(UUID.randomUUID());

        // then
        assertThat(info.equals(info)).isTrue();
    }

    @Test
    void isNotEqualToNull() {
        // given
        CertificateRenewalInfo info = anInfoWithUuid(UUID.randomUUID());

        // then
        assertThat(info.equals(null)).isFalse();
    }

    @Test
    void isNotEqualToAnObjectOfAnotherClass() {
        // given
        CertificateRenewalInfo info = anInfoWithUuid(UUID.randomUUID());

        // then
        assertThat(info.equals("not a renewal info")).isFalse();
    }

    @Test
    void equalsWithEqualHashCode_whenInstancesShareTheSameUuid() {
        // given
        UUID uuid = UUID.randomUUID();
        CertificateRenewalInfo first = anInfoWithUuid(uuid);
        CertificateRenewalInfo second = anInfoWithUuid(uuid);

        // then
        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    void isNotEqualToAnotherInstance_whenUuidIsNull() {
        // given
        CertificateRenewalInfo first = new CertificateRenewalInfo();
        CertificateRenewalInfo second = new CertificateRenewalInfo();

        // then
        assertThat(first.equals(second)).isFalse();
    }

    @Test
    void isNotEqual_whenUuidsDiffer() {
        // given
        CertificateRenewalInfo first = anInfoWithUuid(UUID.randomUUID());
        CertificateRenewalInfo second = anInfoWithUuid(UUID.randomUUID());

        // then
        assertThat(first.equals(second)).isFalse();
    }

    private static CertificateRenewalInfo anInfoWithUuid(UUID uuid) {
        CertificateRenewalInfo info = new CertificateRenewalInfo();
        info.setUuid(uuid);
        return info;
    }
}

package com.otilm.core.dao.entity;

import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateRenewalInfoTest {

    @Test
    void equalsItself_whenComparedToTheSameInstance() {
        // given
        CertificateRenewalInfo info = anInfoWithUuid(UUID.randomUUID());

        // when
        boolean equal = info.equals(info);

        // then
        assertThat(equal).isTrue();
    }

    @Test
    void isNotEqual_whenComparedToNull() {
        // given
        CertificateRenewalInfo info = anInfoWithUuid(UUID.randomUUID());

        // when
        boolean equal = info.equals(null);

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void isNotEqual_whenComparedToAnObjectOfAnotherClass() {
        // given
        CertificateRenewalInfo info = anInfoWithUuid(UUID.randomUUID());
        Object anotherClass = "not a renewal info";

        // when
        boolean equal = info.equals(anotherClass);

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void equalsWithEqualHashCode_whenInstancesShareTheSameUuid() {
        // given
        UUID uuid = UUID.randomUUID();
        CertificateRenewalInfo first = anInfoWithUuid(uuid);
        CertificateRenewalInfo second = anInfoWithUuid(uuid);

        // when
        boolean equal = first.equals(second);
        int firstHash = first.hashCode();
        int secondHash = second.hashCode();

        // then
        assertThat(equal).isTrue();
        assertThat(firstHash).isEqualTo(secondHash);
    }

    @Test
    void isNotEqual_whenBothUuidsAreNull() {
        // given
        CertificateRenewalInfo first = new CertificateRenewalInfo();
        CertificateRenewalInfo second = new CertificateRenewalInfo();

        // when
        boolean equal = first.equals(second);

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void isNotEqual_whenUuidsDiffer() {
        // given
        CertificateRenewalInfo first = anInfoWithUuid(UUID.randomUUID());
        CertificateRenewalInfo second = anInfoWithUuid(UUID.randomUUID());

        // when
        boolean equal = first.equals(second);

        // then
        assertThat(equal).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static CertificateRenewalInfo anInfoWithUuid(UUID uuid) {
        CertificateRenewalInfo info = new CertificateRenewalInfo();
        info.setUuid(uuid);
        return info;
    }
}

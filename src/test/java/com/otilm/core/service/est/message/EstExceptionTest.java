package com.otilm.core.service.est.message;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EstExceptionTest {

    @Test
    void usesTheErrorTextAsMessage_whenConstructedWithAnError() {
        // given
        EstError error = EstError.SERVICE_UNAVAILABLE;

        // when
        EstException exception = new EstException(error);

        // then
        assertThat(exception.error()).isEqualTo(error);
        assertThat(exception).hasMessage(error.text());
    }

    @Test
    void hasNoRealm_whenConstructedWithoutOne() {
        // given
        EstError error = EstError.UNAUTHORIZED;

        // when
        EstException exception = new EstException(error);

        // then
        assertThat(exception.realm()).isEmpty();
    }

    @Test
    void exposesRealm_whenConstructedWithOne() {
        // given
        EstError error = EstError.UNAUTHORIZED;
        String realm = "devices";

        // when
        EstException exception = new EstException(error, realm);

        // then
        assertThat(exception.error()).isEqualTo(error);
        assertThat(exception.realm()).contains(realm);
        assertThat(exception).hasMessage(error.text());
    }

    @Test
    void hasNoDetail_whenConstructedWithoutOne() {
        // given
        EstError error = EstError.POLICY_VIOLATION;

        // when
        EstException exception = new EstException(error);

        // then
        assertThat(exception.detail()).isEmpty();
    }

    @Test
    void keepsDetail_whenRealmIsAdded() {
        // given
        EstException withDetail = new EstException(EstError.POLICY_VIOLATION).withDetail("a policy text");

        // when
        EstException withRealm = withDetail.withRealm("devices");

        // then
        assertThat(withRealm).isNotSameAs(withDetail);
        assertThat(withRealm.error()).isEqualTo(EstError.POLICY_VIOLATION);
        assertThat(withRealm.realm()).contains("devices");
        assertThat(withRealm.detail()).contains("a policy text");
        assertThat(withRealm).hasMessage(EstError.POLICY_VIOLATION.text());
        assertThat(withDetail.realm()).isEmpty();
    }

    @Test
    void keepsRealm_whenDetailIsAdded() {
        // given
        EstException withRealm = new EstException(EstError.POLICY_VIOLATION, "devices");

        // when
        EstException withDetail = withRealm.withDetail("a policy text");

        // then
        assertThat(withDetail).isNotSameAs(withRealm);
        assertThat(withDetail.realm()).contains("devices");
        assertThat(withDetail.detail()).contains("a policy text");
        assertThat(withDetail).hasMessage(EstError.POLICY_VIOLATION.text());
        assertThat(withRealm.detail()).isEmpty();
    }
}

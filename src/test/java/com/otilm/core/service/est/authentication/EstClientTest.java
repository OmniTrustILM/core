package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class EstClientTest {

    @ParameterizedTest
    @EnumSource(value = EstAuthenticationPolicy.class, names = {"VENDOR_MTLS", "RA_MTLS"})
    void identifiesTheClientByItsThumbprint_whenBuiltOfACertificate(EstAuthenticationPolicy policy) {
        // given
        var thumbprint = "0a1b2c3d";

        // when
        EstClient client = EstClient.ofCertificate(policy, thumbprint);

        // then
        assertThat(client).isEqualTo(new EstClient(policy, "certificate:0a1b2c3d", null));
    }
}

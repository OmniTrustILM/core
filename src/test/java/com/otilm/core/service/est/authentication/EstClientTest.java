package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.Test;
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

    @Test
    void derivesTheSameCorrelationUuid_whenTheIdentityIsTheSame() {
        // given
        var identity = "secret:" + UUID.randomUUID();
        var client = new EstClient(EstAuthenticationPolicy.RA_BASIC, identity, null);
        var sameClientAgain = new EstClient(EstAuthenticationPolicy.RA_BASIC, identity, null);

        // when
        UUID correlationUuid = client.correlationUuid();

        // then
        assertThat(correlationUuid).isEqualTo(sameClientAgain.correlationUuid());
    }

    @Test
    void derivesAnotherCorrelationUuid_whenTheIdentityDiffers() {
        // given
        var client = new EstClient(EstAuthenticationPolicy.RA_BASIC, "secret:" + UUID.randomUUID(), null);
        var anotherClient = new EstClient(EstAuthenticationPolicy.RA_BASIC, "secret:" + UUID.randomUUID(), null);

        // when
        UUID correlationUuid = client.correlationUuid();

        // then
        assertThat(correlationUuid).isNotEqualTo(anotherClient.correlationUuid());
    }

    @Test
    void derivesAVersion8UuidThatIsNotTheMd5NameUuid_whenDerivingTheCorrelationUuid() {
        // given
        var identity = "certificate:0a1b2c3d";
        var client = EstClient.ofCertificate(EstAuthenticationPolicy.VENDOR_MTLS, "0a1b2c3d");
        var md5NameUuid = UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8));

        // when
        UUID correlationUuid = client.correlationUuid();

        // then
        assertThat(correlationUuid.version()).isEqualTo(8);
        assertThat(correlationUuid.variant()).isEqualTo(2);
        assertThat(correlationUuid).isNotEqualTo(md5NameUuid);
    }
}

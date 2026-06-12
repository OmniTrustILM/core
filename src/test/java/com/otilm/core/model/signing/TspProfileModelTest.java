package com.otilm.core.model.signing;

import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TspProfileModelTest {

    @Test
    void carriesMethodsAndCredentialRefs() {
        // given
        var cred = new TspProfileModel.BasicCredentialRef("svc", UUID.randomUUID(), UUID.randomUUID(), "fp");

        // when
        TspProfileModel model = new TspProfileModel(
                UUID.randomUUID(), "p", null, true, null, null, List.of(),
                List.of(TspAuthenticationMethod.BASIC_PASSWORD), List.of(cred), UUID.randomUUID());

        // then
        assertThat(model.allowedAuthenticationMethods()).contains(TspAuthenticationMethod.BASIC_PASSWORD);
        assertThat(model.basicCredentials().get(0).username()).isEqualTo("svc");
    }
}
